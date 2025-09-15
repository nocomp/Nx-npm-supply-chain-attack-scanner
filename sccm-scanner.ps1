<# here you go, sccm + reports adapted to servers
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, Position=0)]
  [ValidateSet('web','local')]
  [string]$Mode,

  # --- Web options (unchanged, kept for completeness) ---
  [string]$Url,
  [string]$File,
  [string]$Domain,
  [string]$Ns,
  [string]$DnsWordlist,
  [int]$DnsLimit,
  [string]$Scheme = 'https',
  [int]$Limit,
  [int]$Workers = 6,

  # --- Local options (SCCM-focused) ---
  [string[]]$Roots,           # e.g. 'C:\','D:\' ; if empty -> auto-detect fixed drives
  [switch]$IncludeAllPackageJson,  # scan all package.json (not only node_modules)
  [string]$OutDir,            # default: .\scanner_output
  [string]$ReportPrefix,      # default: auto hostname-based
  [string]$LogPath,           # optional log file (adds rolling append)
  [switch]$NoHtml,            # if set, skip HTML (keep JSON/CSV)

  # --- Behavior ---
  [switch]$Quiet,             # minimal console output
  [int]$MaxDepth = 0          # 0 = unlimited (use carefully on roots), else limit depth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --------------------------
# Logging helpers
# --------------------------
function Log([string]$msg,[string]$level='INFO'){
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[{0}] {1} {2}" -f $ts,$level,$msg
  if(-not $Quiet){ Write-Host $line }
  if($LogPath){
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch {}
  }
}
function Warn($m){ Log $m 'WARN' }
function Err($m){ Log $m 'ERROR' }

# --------------------------
# IO roots
# --------------------------
$ScriptRoot  = if($PSScriptRoot){ $PSScriptRoot } else { (Get-Location).Path }
$OutputRoot  = if($OutDir){ $OutDir } else { Join-Path $ScriptRoot "scanner_output" }
$DumpRoot    = Join-Path $OutputRoot   "web_dumps"
$ReportsRoot = Join-Path $OutputRoot   "reports"
New-Item -ItemType Directory -Path $DumpRoot,$ReportsRoot -ErrorAction SilentlyContinue | Out-Null

function NowTag    { (Get-Date).ToString('yyyyMMdd_HHmmss') }
function NowPretty { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
function Sanitize-Label([string]$s,[int]$maxlen=40){
  if([string]::IsNullOrWhiteSpace($s)){ return "root" }
  $x = $s -replace '[^A-Za-z0-9\-]+','-' -replace '-{2,}','-'
  if($x.Length -gt $maxlen){ $x = $x.Substring(0,$maxlen).TrimEnd('-') }
  if([string]::IsNullOrWhiteSpace($x)){ return "root" }
  return $x.Trim('-')
}

# --------------------------
# Indicators (packages/versions & strings)
# --------------------------
$BadPackages = [ordered]@{
  "debug"               = "4.4.2"
  "chalk"               = "5.6.1"
  "ansi-styles"         = "6.2.2"
  "strip-ansi"          = "7.1.1"
  "color-convert"       = "3.1.1"
  "ansi-regex"          = "6.2.1"
  "supports-color"      = "10.2.1"
  "wrap-ansi"           = "9.0.1"
  "slice-ansi"          = "7.1.1"
  "color-name"          = "2.0.1"
  "color-string"        = "2.1.1"
  "has-ansi"            = "6.0.1"
  "supports-hyperlinks" = "4.1.1"
  "chalk-template"      = "1.1.1"
  "backslash"           = "0.2.1"
  "is-arrayish"         = "0.3.3"
  "error-ex"            = "1.3.3"
  "simple-swizzle"      = "0.2.3"
}

$PackageKeywords = @(
  $BadPackages.Keys
  "ansi-colors","kleur","kleur/colors","log-symbols","supports-hyperlinks"
) | Select-Object -Unique

# Suspicious patterns (JS)
$re_env_window = @'typeof\s+window\s*!==\s*["']undefined["']'@
$re_env_eth    = @'typeof\s+window\.ethereum\s*!==\s*["']undefined["']'@
$re_eth_req    = @'window\.ethereum\.request\(\{\s*["']method["']\s*:\s*["']eth_accounts["']\s*\}\)'@
$re_eth_call   = @'ethereum\.request\('@
$re_wallets    = @'walletconnect|metamask|phantom\.|solana\.|keplr\.'@
$re_newfunc    = @'new\s+Function\('@
$re_atob       = @'atob\('@
$re_fromch     = @'fromCharCode\([^)]{0,80}\)'@
$re_hex_iife   = @'const\s+0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+;\s*\(function\(\s*_0x[0-9a-fA-F]+,\s*_0x[0-9a-fA-F]+\)\{'@
$re_hex_call   = @'_0x[0-9a-fA-F]{4,}\('@
$SuspiciousRegex = @($re_env_window,$re_env_eth,$re_eth_req,$re_eth_call,$re_wallets,
  $re_newfunc,$re_atob,$re_fromch,$re_hex_iife,$re_hex_call)

# Specific obfuscation snippet
$ObfExact = 'const _0x112fa8=_0x180f;(function(_0x13c8b9,_0_35f660){const _0x15b386=_0x180f,'
$ObfRelax = @'const\s+_0x112fa8\s*=\s*_0x180f;\s*\(function\(\s*_0x13c8b9\s*,\s*_0_35f660\s*\)\s*\{\s*const\s+_0x15b386\s*=\s*_0x180f\s*,'@

$IocInfo = @{
  compromise_window_utc = "2025-09-08 ~13:00-17:00 UTC"
  phishing_domain       = "npmjs.help"
}

# --------------------------
# HTTP helpers (web mode kept intact)
# --------------------------
$Global:_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36'
function Normalize-Url([string]$u,[string]$DefaultScheme='https'){
  if([string]::IsNullOrWhiteSpace($u)){ return $null }
  if($u -notmatch '^https?://'){ $u = ("{0}://{1}" -f $DefaultScheme,$u) }
  return $u
}
function Http-GetText([string]$url){
  $hdr = @{ 'User-Agent'=$Global:_UA }
  (Invoke-WebRequest -Uri $url -Headers $hdr -UseBasicParsing -TimeoutSec 25).Content
}
function Http-GetBytes([string]$url){
  $hdr = @{ 'User-Agent'=$Global:_UA }
  (Invoke-WebRequest -Uri $url -Headers $hdr -UseBasicParsing -TimeoutSec 30).Content
}
function Get-Sha256([byte[]]$bytes){
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { -join ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) } finally { $sha256.Dispose() }
}

# --------------------------
# Local scan (SCCM hardened)
# --------------------------
# System dirs to skip when scanning root drives
$SkipDirNames = @(
  '$Recycle.Bin','System Volume Information','Windows','WinSxS','$WINDOWS.~BT','$WinREAgent',
  'Recovery','Config.Msi','DumpStack.log.tmp','hiberfil.sys','pagefile.sys','swapfile.sys'
)
$IgnoreRegex = @(".git",".svn",".hg","node_modules\.cache",".next",".nuxt",".svelte-kit")  # still skip noisy dirs

function Should-SkipDir([string]$full){
  foreach($n in $SkipDirNames){
    if($full -match "\\$([regex]::Escape($n))$"){ return $true }
    if($full -match "\\$([regex]::Escape($n))\\"){ return $true }
  }
  foreach($r in $IgnoreRegex){
    if($full -match $r){ return $true }
  }
  return $false
}

function Safe-EnumerateFiles([string]$root,[int]$depth){
  # Enumerate candidate files with robust error handling and optional depth limit.
  $targets = @('package-lock.json','yarn.lock','pnpm-lock.yaml','package.json')
  $q = New-Object System.Collections.Queue
  $q.Enqueue(@($root,0))
  $files = @()

  while($q.Count -gt 0){
    $entry = $q.Dequeue()
    $dir   = $entry[0]
    $lvl   = [int]$entry[1]

    try {
      # List files in this directory
      foreach($f in (Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue)){
        if($targets -contains $f.Name){ $files += $f.FullName }
      }
      # Descend?
      if($depth -eq 0 -or $lvl -lt $depth){
        foreach($d in (Get-ChildItem -LiteralPath $dir -Force -Directory -ErrorAction SilentlyContinue)){
          $path = $d.FullName
          if(Should-SkipDir $path){ continue }
          $q.Enqueue(@($path, $lvl+1))
        }
      }
    } catch {
      # access denied or reparse points etc → ignore
      continue
    }
  }
  return $files
}

function Scan-Local([string[]]$roots){
  $resolved = @()
  if(-not $roots -or $roots.Count -eq 0){
    # Auto-detect fixed drives (C:, D:, E:…)
    $fixed = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -eq $null -and $_.Free -ne $null } | ForEach-Object { $_.Root }
    $resolved = $fixed
  } else {
    foreach($r in $roots){
      try{
        if($r -match '^[A-Za-z]:\\?$'){ $resolved += ($r.TrimEnd('\') + '\') }
        elseif(Test-Path $r){ $resolved += (Resolve-Path $r).Path }
      } catch { Warn "Invalid root: $r" }
    }
  }
  if(-not $resolved){ throw "No valid roots to scan." }

  $host = [System.Net.Dns]::GetHostName()
  $res = @{
    host           = $host
    roots          = $resolved
    packages_hits  = @()
    errors         = @()
  }

  function Check-Pkg([string]$name,[string]$ver,[string]$where,[string]$typ){
    if($BadPackages.ContainsKey($name) -and $BadPackages[$name] -eq $ver){
      $res.packages_hits += @{ host=$host; name=$name; version=$ver; where=$where; type=$typ }
    }
  }

  foreach($root in $resolved){
    Log ("Enumerating under {0} (MaxDepth={1})" -f $root, ($MaxDepth)) 'INFO'
    $files = Safe-EnumerateFiles -root $root -depth $MaxDepth

    foreach($p in $files){
      $name = Split-Path -Leaf $p
      try{
        if($name -eq 'package-lock.json'){
          $pl = (Get-Content -Raw -Path $p -ErrorAction Stop | ConvertFrom-Json)
          function Walk($obj){
            if($null -eq $obj){ return }
            if($obj -is [pscustomobject] -or $obj -is [hashtable]){
              $nm = $obj.name; $vr = $obj.version
              if($nm -and $vr){ Check-Pkg $nm $vr $p "package-lock.json" }
              foreach($v in $obj.psobject.Properties.Value){ Walk $v }
            } elseif($obj -is [System.Collections.IEnumerable]){
              foreach($v in $obj){ Walk $v }
            }
          }
          Walk $pl

        } elseif($name -eq 'yarn.lock'){
          $data = Get-Content -Raw -Path $p -ErrorAction Stop
          foreach($m in [regex]::Matches($data,'(^|\n{2})(?<key>[^:\n]+):\n +version "(?<ver>[^"]+)"')){
            $key = $m.Groups['key'].Value; $ver = $m.Groups['ver'].Value
            $pkgName = if($key.StartsWith('@')){ $parts = $key.Split('@'); "@$($parts[1])" } else { $key.Split('@')[0] }
            if($pkgName -and $ver){ Check-Pkg $pkgName $ver $p "yarn.lock" }
          }

        } elseif($name -eq 'pnpm-lock.yaml'){
          $data = Get-Content -Raw -Path $p -ErrorAction Stop
          foreach($m in [regex]::Matches($data,'(?m)^\s*/([^/\s]+)/(\d+\.\d+\.\d+)')){
            $nm = $m.Groups[1].Value; $vr = $m.Groups[2].Value
            if($nm -and $vr){ Check-Pkg $nm $vr $p "pnpm-lock.yaml" }
          }

        } elseif($name -eq 'package.json'){
          # Only treat node_modules/package.json as "installed" unless flag is set
          if($IncludeAllPackageJson -or ($p -match '\\node_modules\\')){
            $txt = Get-Content -Raw -Path $p -ErrorAction Stop
            try{
              $pkg = $txt | ConvertFrom-Json
              if($pkg.name -and $pkg.version){ Check-Pkg $pkg.name $pkg.version $p "package.json" }
            } catch { }
          }
        }
      } catch {
        $res.errors += ("{0}: {1}" -f $p, $_.Exception.Message)
      }
    }
  }
  return $res
}

# --------------------------
# Web scan (kept for parity)
# --------------------------
$re_script_src = @'<script[^>]+src=["']([^"']+)["']'@
$re_link_pre   = @'<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["']'@
$re_href       = @'href=["']([^"']+)["']'@
$JsExts        = @('.js','.mjs','.map')
$MaxPages      = 20
$MaxJsPerSite  = 200

function Url-Join([string]$base,[string]$link){ try { ([System.Uri]::new([System.Uri]$base, $link)).AbsoluteUri } catch { $null } }
function Same-Origin([string]$a,[string]$b){ try { $ua=[System.Uri]$a;$ub=[System.Uri]$b; ($ua.Scheme -eq $ub.Scheme -and $ua.Host -eq $ub.Host -and $ua.Port -eq $ub.Port) } catch { $false } }
function Get-ScriptsFromHtml([string]$html){
  if([string]::IsNullOrEmpty($html)){ return @() }
  $out=@()
  try{
    foreach($m in [regex]::Matches($html,$re_script_src,'IgnoreCase')){ $v=$m.Groups[1].Value; if($v){ $out+= $v } }
    foreach($m in [regex]::Matches($html,$re_link_pre,'IgnoreCase'))  { $v=$m.Groups[1].Value; if($v){ $out+= $v } }
  } catch {}
  $out | Where-Object { $_ } | Select-Object -Unique
}

function Summarize-WebScan($scan){
  $bundles=$susp=$comp=$obx=$obr=0
  foreach($j in $scan.js_files){
    if($j.size){ $bundles++ }
    if($j.patterns -and $j.patterns.Count -gt 0){ $susp++ }
    if($j.bad_version_match -and $j.bad_version_match.Count -gt 0){ $comp++ }
    if($j.obfuscation_exact){ $obx++ }
    if($j.obfuscation_relaxed){ $obr++ }
  }
  @{ bundles=$bundles; suspicious=$susp; compromised=$comp; obfus_exact=$obx; obfus_relax=$obr }
}
function Print-Triage($url,$k){
  $line = ("* {0} -- bundles:{1} suspicious:{2} compromised:{3} obfus(exact/relax):{4}/{5}" -f $url,$k.bundles,$k.suspicious,$k.compromised,$k.obfus_exact,$k.obfus_relax)
  if(-not $Quiet){
    if($k.compromised -gt 0){ Write-Host $line -ForegroundColor Red }
    elseif($k.suspicious -gt 0 -or $k.obfus_exact -gt 0 -or $k.obfus_relax -gt 0){ Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line -ForegroundColor Green }
  } else {
    Log $line 'INFO'
  }
}

function Crawl-And-Collect([string]$BaseUrl){
  $res = @{ base_url=$BaseUrl; pages_crawled=@(); js_files=@() }
  try {
    $html = Http-GetText $BaseUrl
    $res.pages_crawled += @{ url=$BaseUrl; status=200; size=($html.Length) }
  } catch {
    $res.pages_crawled += @{ url=$BaseUrl; error=("$_") }
    return $res
  }

  $toVisit = New-Object System.Collections.Queue
  $seenPages = New-Object System.Collections.Generic.HashSet[string]
  $seenJs    = New-Object System.Collections.Generic.HashSet[string]
  $toVisit.Enqueue($BaseUrl); [void]$seenPages.Add($BaseUrl)

  try{ foreach($s in (Get-ScriptsFromHtml $html)){ $full=Url-Join $BaseUrl $s; if($full -and ($JsExts | Where-Object { $full.EndsWith($_) })){ [void]$seenJs.Add($full) } } } catch {}

  while($toVisit.Count -gt 0 -and $res.pages_crawled.Count -lt $MaxPages){
    $url = $toVisit.Dequeue()
    if($url -ne $BaseUrl){
      try{
        $html2 = Http-GetText $url
        $res.pages_crawled += @{ url=$url; status=200; size=($html2.Length) }
        try{ foreach($s in (Get-ScriptsFromHtml $html2)){ $full=Url-Join $url $s; if($full -and ($JsExts | Where-Object { $full.EndsWith($_) }) -and $seenJs.Count -lt $MaxJsPerSite){ [void]$seenJs.Add($full) } } } catch {}
        foreach($m in [regex]::Matches($html2,$re_href,'IgnoreCase')){
          $lnk = $m.Groups[1].Value; $full = Url-Join $url $lnk
          if($full -and (Same-Origin $BaseUrl $full)){
            if(($JsExts | Where-Object { $full.EndsWith($_) })){ if($seenJs.Count -lt $MaxJsPerSite){ [void]$seenJs.Add($full) } }
            else { if(-not $seenPages.Contains($full) -and $seenPages.Count -lt $MaxPages){ [void]$seenPages.Add($full); $toVisit.Enqueue($full) } }
          }
        }
      } catch { $res.pages_crawled += @{ url=$url; error=("$_") } }
    }
  }

  # Iterate JS safely without .ToArray()
  $jsList=@(); foreach($j in $seenJs){ $jsList+= $j }
  foreach($js in ($jsList | Sort-Object)){
    try{
      $bytes = Http-GetBytes $js
      $text  = [Text.Encoding]::UTF8.GetString($bytes)
      $hash  = Get-Sha256 $bytes
      $hash12= $hash.Substring(0,12)
      $u     = [Uri]$js
      $hostDir = Join-Path $DumpRoot ($u.Host.Replace(':','_'))
      New-Item -ItemType Directory -Path $hostDir -ErrorAction SilentlyContinue | Out-Null
      $name = [IO.Path]::GetFileName($u.AbsolutePath); if([string]::IsNullOrWhiteSpace($name)){ $name = "bundle.js" }
      $outPath = Join-Path $hostDir ("{0}__{1}" -f $hash12,$name)
      [IO.File]::WriteAllBytes($outPath, $bytes)

      $keywords=@(); foreach($k in $PackageKeywords){ if([regex]::IsMatch($text,[regex]::Escape($k))){ $keywords += $k } }
      $patterns=@(); foreach($rx in $SuspiciousRegex){ if([regex]::IsMatch($text,$rx,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)){ $patterns += $rx } }
      $obfExact = $text.Contains($ObfExact)
      $obfRelax = [regex]::IsMatch($text,$ObfRelax)

      $versionHints=@()
      foreach($namePkg in $BadPackages.Keys){
        $p1 = ("{0}[@:]?\s*[`"']?(\d+\.\d+\.\d+)[`"']?" -f [regex]::Escape($namePkg))
        foreach($m in [regex]::Matches($text,$p1)){ $versionHints += @{ name=$namePkg; version=$m.Groups[1].Value } }
        $p2 = ('"name"\s*:\s*"{0}"\s*,\s*"version"\s*:\s*"(\d+\.\d+\.\d+)"' -f [regex]::Escape($namePkg))
        foreach($m in [regex]::Matches($text,$p2)){ $versionHints += @{ name=$namePkg; version=$m.Groups[1].Value } }
      }
      if($versionHints){ $versionHints = $versionHints | Sort-Object -Property name,version -Unique }

      $bad=@()
      foreach($vh in $versionHints){ if($BadPackages.ContainsKey($vh.name) -and $BadPackages[$vh.name] -eq $vh.version){ $bad += ("{0}@{1}" -f $vh.name,$vh.version) } }

      $res.js_files += @{
        url=$js; path=$outPath; size=$bytes.Length; sha256=$hash;
        keywords=$keywords; patterns=$patterns; version_hints=$versionHints;
        bad_version_match=$bad; obfuscation_exact=$obfExact; obfuscation_relaxed=$obfRelax
      }
    } catch { $res.js_files += @{ url=$js; error=("$_") } }
  }
  return $res
}

# --------------------------
# Reporting (HTML + JSON + CSV)
# --------------------------
function Write-Json([string]$path,$obj){
  $json = $obj | ConvertTo-Json -Depth 8
  Set-Content -Path $path -Value $json -Encoding UTF8
}
function Write-CsvSummary([string]$csvPath,$packages_hits){
  $rows = @()
  foreach($h in $packages_hits){
    $rows += [pscustomobject]@{
      host    = $h.host
      name    = $h.name
      version = $h.version
      where   = $h.where
      type    = $h.type
    }
  }
  $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
}

$css = @"
:root{--bg:#0b1016;--fg:#e9edf4;--muted:#9aa3b2;--card:#121826;--line:#1b2a44;--accent:#7aa2ff;--warn:#fbbf24;--danger:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:Segoe UI,Roboto,Arial,sans-serif}
header{padding:18px 20px;border-bottom:1px solid var(--line)}
h1{font-size:22px;margin:0 0 6px}.sub{color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(6,minmax(140px,1fr));gap:12px;padding:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
.kpi .n{font-size:28px;font-weight:700}.kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
section{padding:10px 16px 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-top:12px}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:8px 6px;font-size:13px}
th{color:var(--muted);text-align:left}
code{background:#0f1725;border:1px solid #1e2a44;border-radius:6px;padding:0 4px}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--line);background:#0f1725;color:var(--muted);font-size:12px}
.danger{color:var(--danger)}.warn{color:var(--warn)}.ok{color:#36d399}
footer{color:var(--muted);font-size:12px;padding:16px;border-top:1px solid var(--line)}
"@

function Build-Report($webScans,$localScan,[string]$htmlPath,[string]$jsonPath,[string]$csvPath){
  $ts = NowPretty
  $summary = @{
    generated_at = $ts
    ioc_info     = $IocInfo
    bad_packages = $BadPackages
    web_scans    = $webScans
    local_scan   = $localScan
  }
  Write-Json $jsonPath $summary

  # CSV (only local hits)
  if($localScan -and $localScan.packages_hits){ Write-CsvSummary -csvPath $csvPath -packages_hits $localScan.packages_hits }

  if($NoHtml){ return } # skip HTML when requested

  # KPIs
  $totWeb = ($webScans | Measure-Object).Count
  $bundles=$susp=$comp=$obx=$obr=0
  foreach($w in ($webScans | Where-Object { $_ })){
    $k = Summarize-WebScan $w
    $bundles += $k.bundles; $susp += $k.suspicious; $comp += $k.compromised; $obx += $k.obfus_exact; $obr += $k.obfus_relax
  }
  $totLocal = if($localScan){ ($localScan.packages_hits | Measure-Object).Count } else { 0 }

  # Impact section (top): servers impacted + paths
  $impactHtml = ""
  if($localScan -and $localScan.packages_hits){
    $byHost = $localScan.packages_hits | Group-Object host
    foreach($grp in $byHost){
      $paths = ($grp.Group | Select-Object -ExpandProperty where | Sort-Object -Unique)
      $pkgList = ($grp.Group | ForEach-Object { "{0}@{1}" -f $_.name,$_.version } | Sort-Object -Unique) -join ', '
      $impactHtml += "<div class='card'><h3>Impacted host: <code>$($grp.Name)</code></h3>"
      $impactHtml += "<div><b>Packages:</b> <code>$pkgList</code></div>"
      $impactHtml += "<div style='margin-top:6px'><b>Paths:</b><ul>"
      foreach($p in $paths){ $impactHtml += "<li><code>$([System.Web.HttpUtility]::HtmlEncode($p))</code></li>" }
      $impactHtml += "</ul></div></div>"
    }
  } else {
    $impactHtml = "<div class='card ok'>No local compromised packages detected.</div>"
  }

  $html = New-Object System.Text.StringBuilder
  [void]$html.Append("<!doctype html><html><head><meta charset='utf-8'><title>Supply-chain NPM Scanner Report</title><style>$css</style></head><body>")
  [void]$html.Append("<header><h1>Supply-chain NPM Scanner - Report</h1><div class='sub'>Generated at $ts</div></header>")

  # Impact section first
  [void]$html.Append("<section><h2>Impact Summary (Hosts & Paths)</h2>$impactHtml</section>")

  # KPIs
  [void]$html.Append("<div class='kpis'>")
  [void]$html.Append("<div class='kpi'><div class='n'>${totWeb}</div><div class='l'>Web targets</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n'>${bundles}</div><div class='l'>Bundles analyzed</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n warn'>${susp}</div><div class='l'>Suspicious patterns</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n danger'>${comp}</div><div class='l'>Compromised (web)</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n'>${obx}/${obr}</div><div class='l'>Obfuscation (exact/relax)</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n danger'>${totLocal}</div><div class='l'>Compromised (local)</div></div>")
  [void]$html.Append("</div>")

  # IOC / Known versions
  [void]$html.Append("<section><div class='card'><h3>Incident IOCs / Reference</h3><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>")
  foreach($k in $IocInfo.Keys){ $v=[System.Web.HttpUtility]::HtmlEncode($IocInfo[$k]); [void]$html.Append("<tr><td>$k</td><td><code>$v</code></td></tr>") }
  [void]$html.Append("</tbody></table></div></section>")

  [void]$html.Append("<section><div class='card'><h3>Known Compromised Versions</h3><table><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>")
  foreach($k in ($BadPackages.Keys | Sort-Object)){ $v=$BadPackages[$k]; [void]$html.Append("<tr><td><code>$k</code></td><td class='danger'><code>$v</code></td></tr>") }
  [void]$html.Append("</tbody></table></div></section>")

  # Web details (if used)
  if($webScans -and $webScans.Count -gt 0){
    [void]$html.Append("<section><h2>Web Scans</h2>")
    foreach($w in $webScans){
      $k = Summarize-WebScan $w
      $badge = "bundles:$($k.bundles) - suspicious:$($k.suspicious) - compromised:$($k.compromised) - obfus:$($k.obfus_exact)/$($k.obfus_relax)"
      $t = [System.Web.HttpUtility]::HtmlEncode($w.base_url)
      [void]$html.Append("<div class='card'><h3>Target: <code>$t</code> <span class='pill'>$badge</span></h3>")
      [void]$html.Append("<details><summary class='pill'>Crawled pages</summary><table><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Error</th></tr></thead><tbody>")
      foreach($p in $w.pages_crawled){
        $u  = [System.Web.HttpUtility]::HtmlEncode($p.url)
        $st = if($p.PSObject.Properties.Name -contains 'status'){ [System.Web.HttpUtility]::HtmlEncode("$($p.status)") } else { "-" }
        $sz = if($p.PSObject.Properties.Name -contains 'size')  { [System.Web.HttpUtility]::HtmlEncode("$($p.size)")  } else { "-" }
        $er = if($p.PSObject.Properties.Name -contains 'error') { [System.Web.HttpUtility]::HtmlEncode("$($p.error)") } else { "-" }
        [void]$html.Append("<tr><td>$u</td><td>$st</td><td>$sz</td><td class='danger'>$er</td></tr>")
      }
      [void]$html.Append("</tbody></table></details>")
      [void]$html.Append("</div>")
    }
    [void]$html.Append("</section>")
  }

  [void]$html.Append("<footer>Rebuild artifacts after remediation (pin/override versions), invalidate CDN if needed. - Supply-chain NPM Scanner</footer></body></html>")
  Set-Content -Path $htmlPath -Value $html.ToString() -Encoding UTF8
}

# --------------------------
# Orchestration
# --------------------------
$ts = NowTag

try{
  if($Mode -eq 'web'){
    # unchanged behavior for web path (kept for parity with previous versions)
    $targets = @()
    if($Url){
      $targets = @( Normalize-Url $Url $Scheme )
      $prefix  = if($ReportPrefix){ $ReportPrefix } else { "report_{0}__web" -f (Sanitize-Label ([Uri]$targets[0]).Host) }
    } elseif($File){
      $lines = Get-Content -Path $File | Where-Object { $_.Trim() }
      $targets = $lines | ForEach-Object { Normalize-Url $_ $Scheme } | Where-Object { $_ }
      if(-not $targets){ throw "No web targets in file." }
      $first = ([Uri]$targets[0]).Host; $rest = [Math]::Max(0, $targets.Count-1)
      $prefix = if($ReportPrefix){ $ReportPrefix } else { "report_{0}+{1}__webbatch" -f (Sanitize-Label $first),$rest }
    } elseif($Domain){
      $hosts = New-Object System.Collections.Generic.HashSet[string]
      foreach($h in (Get-SubdomainsFromCRT -domain $Domain -Limit $Limit) + $Domain){ [void]$hosts.Add($h) }
      if($Ns){
        Log ("DNS brute-force via $Ns on $Domain") 'INFO'
        $dnsHits = BruteForce-Subdomains -domain $Domain -server $Ns -Wordlist $DnsWordlist -Limit $DnsLimit
        foreach($h in $dnsHits){ [void]$hosts.Add($h) }
      }
      $arrHosts=@(); foreach($h in $hosts){ $arrHosts+= $h }
      $targets = ($arrHosts | Sort-Object | ForEach-Object { Normalize-Url $_ $Scheme }) | Where-Object { $_ }
      if(-not $targets){ throw "No web targets discovered for domain." }
      $first = ([Uri]$targets[0]).Host; $rest = [Math]::Max(0, $targets.Count-1)
      $prefix = if($ReportPrefix){ $ReportPrefix } else { "report_{0}+{1}__webbatch" -f (Sanitize-Label $first),$rest }
    } else { throw "For 'web' mode, specify -Url or -File or -Domain" }

    if(-not $Quiet){ Write-Host ("[*] Web targets: {0}" -f $targets.Count) -ForegroundColor Cyan } else { Log ("Web targets: {0}" -f $targets.Count) }

    $webScans = @()
    foreach($u in $targets){
      try{
        $scan = Crawl-And-Collect $u
        $webScans += $scan
        Print-Triage $u (Summarize-WebScan $scan)
      } catch {
        $webScans += @{ base_url=$u; pages_crawled=@(@{url=$u; error=("$_")}); js_files=@() }
        Warn ("{0} -- error during scan" -f $u)
      }
    }

    $htmlOut = Join-Path $ReportsRoot ("{0}_{1}.html" -f $prefix,$ts)
    $jsonOut = Join-Path $ReportsRoot ("{0}_{1}.json" -f $prefix,$ts)
    $csvOut  = Join-Path $ReportsRoot ("{0}_{1}.csv"  -f $prefix,$ts)
    Build-Report $webScans $null $htmlOut $jsonOut $csvOut
    if(-not $NoHtml){ Log "[OK] HTML report: $htmlOut" }
    Log "[OK] JSON report: $jsonOut"
    Log "[OK] CSV summary: $csvOut"
    exit 0
  }

  if($Mode -eq 'local'){
    $host = Sanitize-Label ([System.Net.Dns]::GetHostName())
    $prefix = if($ReportPrefix){ $ReportPrefix } else { "report_{0}__local" -f $host }

    $localScan = Scan-Local $Roots
    $htmlOut = Join-Path $ReportsRoot ("{0}_{1}.html" -f $prefix,$ts)
    $jsonOut = Join-Path $ReportsRoot ("{0}_{1}.json" -f $prefix,$ts)
    $csvOut  = Join-Path $ReportsRoot ("{0}_{1}.csv"  -f $prefix,$ts)
    Build-Report @() $localScan $htmlOut $jsonOut $csvOut

    if(-not $NoHtml){ Log "[OK] HTML report: $htmlOut" }
    Log "[OK] JSON report: $jsonOut"
    Log "[OK] CSV summary: $csvOut"

    # Exit codes for SCCM:
    # 0 = success; 1 = success with findings; 2 = error
    $findings = ($localScan.packages_hits | Measure-Object).Count
    if($findings -gt 0){ exit 1 } else { exit 0 }
  }

  throw "Unknown mode."
}
catch {
  Err $_.Exception.Message
  exit 2
}
