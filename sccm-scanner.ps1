<# Supply-chain NPM Scanner (PowerShell) - SCCM-ready
 - Scan roots like C:\ D:\ E:\ robustly
 - HTML/JSON + CSV, top-of-report "Impacted hosts & paths"
 - Silent-friendly, exit codes: 0 OK no findings / 1 OK with findings / 2 error
 - -Help/-h/-? prints usage
#>

[CmdletBinding()]
param(
  [ValidateSet('web','local')]
  [string]$Mode = 'local',

  # Web (optional)
  [string]$Url,
  [string]$File,
  [string]$Domain,
  [string]$Ns,
  [string]$DnsWordlist,
  [int]$DnsLimit = 0,
  [string]$Scheme = 'https',
  [int]$Limit = 0,

  # Local (SCCM focus)
  [string[]]$Roots,
  [switch]$IncludeAllPackageJson,
  [string]$OutDir,
  [string]$ReportPrefix,
  [string]$LogPath,
  [switch]$NoHtml,
  [switch]$Quiet,
  [int]$MaxDepth = 0,

  # Help
  [Alias('h','?')][switch]$Help
)

if($Help){
  @"
Usage:
  Local (auto-detect fixed drives C:\ D:\ ...):
    powershell -ExecutionPolicy Bypass -File .\sccm-scanner.ps1 -Mode local

  Local (specific roots, limit depth, CSV/JSON/HTML output):
    ... -Mode local -Roots 'C:\','D:\' -MaxDepth 6 -OutDir 'C:\Temp\scan' -Quiet

  Web (optional):
    ... -Mode web -Url https://example.com
    ... -Mode web -Domain corp.local -Ns 10.0.0.53

Exit codes:
  0 = success (no local findings), 1 = success (findings), 2 = error
"@ | Write-Output
  exit 0
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- logging ----------
function Log([string]$msg,[string]$lvl='INFO'){
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[{0}] {1} {2}" -f $ts,$lvl,$msg
  if(-not $Quiet){ Write-Host $line }
  if($LogPath){ try{ Add-Content -Path $LogPath -Value $line -Encoding UTF8 }catch{} }
}
function Warn($m){ Log $m 'WARN' }
function Err($m){ Log $m 'ERROR' }

# ---------- IO ----------
$ScriptRoot  = if($PSScriptRoot){ $PSScriptRoot } else { (Get-Location).Path }
$OutputRoot  = if($OutDir){ $OutDir } else { Join-Path $ScriptRoot 'scanner_output' }
$DumpRoot    = Join-Path $OutputRoot 'web_dumps'
$ReportsRoot = Join-Path $OutputRoot 'reports'
New-Item -ItemType Directory -Path $DumpRoot,$ReportsRoot -ErrorAction SilentlyContinue | Out-Null

function NowTag    { (Get-Date).ToString('yyyyMMdd_HHmmss') }
function NowPretty { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
function Sanitize-Label([string]$s,[int]$maxlen=40){
  if([string]::IsNullOrWhiteSpace($s)){ return 'root' }
  $x = $s -replace '[^A-Za-z0-9\-]+','-' -replace '-{2,}','-'
  if($x.Length -gt $maxlen){ $x = $x.Substring(0,$maxlen).TrimEnd('-') }
  if([string]::IsNullOrWhiteSpace($x)){ return 'root' }
  $x.Trim('-')
}

# ---------- Indicators ----------
$BadPackages = [ordered]@{
  'debug'='4.4.2'; 'chalk'='5.6.1'; 'ansi-styles'='6.2.2'; 'strip-ansi'='7.1.1';
  'color-convert'='3.1.1'; 'ansi-regex'='6.2.1'; 'supports-color'='10.2.1';
  'wrap-ansi'='9.0.1'; 'slice-ansi'='7.1.1'; 'color-name'='2.0.1'; 'color-string'='2.1.1';
  'has-ansi'='6.0.1'; 'supports-hyperlinks'='4.1.1'; 'chalk-template'='1.1.1';
  'backslash'='0.2.1'; 'is-arrayish'='0.3.3'; 'error-ex'='1.3.3'; 'simple-swizzle'='0.2.3'
}
$PackageKeywords = @(
  $BadPackages.Keys
  'ansi-colors','kleur','kleur/colors','log-symbols','supports-hyperlinks'
) | Select-Object -Unique

# ---------- Suspicious regex ----------
$re_env_window = @'
typeof\s+window\s*!==\s*["']undefined["']
'@

$re_env_eth = @'
typeof\s+window\.ethereum\s*!==\s*["']undefined["']
'@

$re_eth_req = @'
window\.ethereum\.request\(\{\s*["']method["']\s*:\s*["']eth_accounts["']\s*\}\)
'@

$re_eth_call = @'
ethereum\.request\(
'@

$re_wallets = @'
walletconnect|metamask|phantom\.|solana\.|keplr\.
'@

$re_newfunc = @'
new\s+Function\(
'@

$re_atob = @'
atob\(
'@

$re_fromch = @'
fromCharCode\([^)]{0,80}\)
'@

$re_hex_iife = @'
const\s+0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+;\s*\(function\(\s*_0x[0-9a-fA-F]+,\s*_0x[0-9a-fA-F]+\)\{
'@

$re_hex_call = @'
_0x[0-9a-fA-F]{4,}\(
'@

$SuspiciousRegex = @(
  $re_env_window,$re_env_eth,$re_eth_req,$re_eth_call,$re_wallets,
  $re_newfunc,$re_atob,$re_fromch,$re_hex_iife,$re_hex_call
)

# Obfuscation snippet
$ObfExact = 'const _0x112fa8=_0x180f;(function(_0x13c8b9,_0_35f660){const _0x15b386=_0x180f,'
$ObfRelax = @'
const\s+_0x112fa8\s*=\s*_0x180f;\s*\(function\(\s*_0x13c8b9\s*,\s*_0_35f660\s*\)\s*\{\s*const\s+_0x15b386\s*=\s*_0x180f\s*,
'@

$IocInfo = @{
  compromise_window_utc = '2025-09-08 ~13:00-17:00 UTC'
  phishing_domain       = 'npmjs.help'
}

# ---------- HTTP (web mode) ----------
$Global:_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36'
function Normalize-Url([string]$u,[string]$DefaultScheme='https'){
  if([string]::IsNullOrWhiteSpace($u)){ return $null }
  if($u -notmatch '^https?://'){ $u = ('{0}://{1}' -f $DefaultScheme,$u) }
  $u
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
  try { -join ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha256.Dispose() }
}

# ---------- Local scan (roots-ready) ----------
$SkipDirNames = @(
  '$Recycle.Bin','System Volume Information','Windows','WinSxS','$WINDOWS.~BT','$WinREAgent',
  'Recovery','Config.Msi','DumpStack.log.tmp','hiberfil.sys','pagefile.sys','swapfile.sys'
)
$IgnoreRegex = @('.git','.svn','.hg','node_modules\.cache','.next','.nuxt','.svelte-kit')

function Should-SkipDir([string]$full){
  foreach($n in $SkipDirNames){
    if($full -match "\\$([regex]::Escape($n))$"){ return $true }
    if($full -match "\\$([regex]::Escape($n))\\"){ return $true }
  }
  foreach($r in $IgnoreRegex){ if($full -match $r){ return $true } }
  $false
}

function Safe-EnumerateFiles([string]$root,[int]$depth){
  $targets = @('package-lock.json','yarn.lock','pnpm-lock.yaml','package.json')
  $q = New-Object System.Collections.Queue
  $q.Enqueue(@($root,0))
  $files = @()
  while($q.Count -gt 0){
    $entry = $q.Dequeue(); $dir=$entry[0]; $lvl=[int]$entry[1]
    try{
      foreach($f in (Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue)){
        if($targets -contains $f.Name){ $files += $f.FullName }
      }
      if($depth -eq 0 -or $lvl -lt $depth){
        foreach($d in (Get-ChildItem -LiteralPath $dir -Force -Directory -ErrorAction SilentlyContinue)){
          $path=$d.FullName; if(Should-SkipDir $path){ continue }
          $q.Enqueue(@($path,$lvl+1))
        }
      }
    } catch { continue }
  }
  $files
}

function Scan-Local([string[]]$roots){
  $resolved = @()
  if(-not $roots -or $roots.Count -eq 0){
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
  if(-not $resolved){ throw 'No valid roots to scan.' }

  $MachineName = [System.Net.Dns]::GetHostName()
  $res = @{ host=$MachineName; roots=$resolved; packages_hits=@(); errors=@() }

  function Check-Pkg([string]$name,[string]$ver,[string]$where,[string]$typ){
    if($BadPackages.ContainsKey($name) -and $BadPackages[$name] -eq $ver){
      $res.packages_hits += @{ host=$MachineName; name=$name; version=$ver; where=$where; type=$typ }
    }
  }

  foreach($root in $resolved){
    Log ("Enumerating under {0} (MaxDepth={1})" -f $root,$MaxDepth)
    $files = Safe-EnumerateFiles -root $root -depth $MaxDepth
    foreach($p in $files){
      $name = Split-Path -Leaf $p
      try{
        if($name -eq 'package-lock.json'){
          $pl = (Get-Content -Raw -Path $p -ErrorAction Stop | ConvertFrom-Json)
          function Walk($obj){
            if($null -eq $obj){ return }
            if($obj -is [pscustomobject] -or $obj -is [hashtable]){
              $nm=$obj.name; $vr=$obj.version
              if($nm -and $vr){ Check-Pkg $nm $vr $p 'package-lock.json' }
              foreach($v in $obj.psobject.Properties.Value){ Walk $v }
            } elseif($obj -is [System.Collections.IEnumerable]){
              foreach($v in $obj){ Walk $v }
            }
          }
          Walk $pl
        } elseif($name -eq 'yarn.lock'){
          $data = Get-Content -Raw -Path $p -ErrorAction Stop
          foreach($m in [regex]::Matches($data,'(^|\n{2})(?<key>[^:\n]+):\n +version "(?<ver>[^"]+)"')){
            $key=$m.Groups['key'].Value; $ver=$m.Groups['ver'].Value
            $pkgName = if($key.StartsWith('@')){ $parts=$key.Split('@'); "@$($parts[1])" } else { $key.Split('@')[0] }
            if($pkgName -and $ver){ Check-Pkg $pkgName $ver $p 'yarn.lock' }
          }
        } elseif($name -eq 'pnpm-lock.yaml'){
          $data = Get-Content -Raw -Path $p -ErrorAction Stop
          foreach($m in [regex]::Matches($data,'(?m)^\s*/([^/\s]+)/(\d+\.\d+\.\d+)')){
            $nm=$m.Groups[1].Value; $vr=$m.Groups[2].Value
            if($nm -and $vr){ Check-Pkg $nm $vr $p 'pnpm-lock.yaml' }
          }
        } elseif($name -eq 'package.json'){
          if($IncludeAllPackageJson -or ($p -match '\\node_modules\\')){
            $txt = Get-Content -Raw -Path $p -ErrorAction Stop
            try{
              $pkg = $txt | ConvertFrom-Json
              if($pkg.name -and $pkg.version){ Check-Pkg $pkg.name $pkg.version $p 'package.json' }
            } catch {}
          }
        }
      } catch {
        $res.errors += ("{0}: {1}" -f $p, $_.Exception.Message)
      }
    }
  }
  $res
}

# ---------- Web scan (optional, minimal) ----------
$re_script_src = @'
<script[^>]+src=["']([^"']+)["']
'@
$re_link_pre = @'
<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["']
'@
$re_href = @'
href=["']([^"']+)["']
'@
$JsExts = @('.js','.mjs','.map')
$MaxPages = 20
$MaxJsPerSite = 200

function Url-Join([string]$base,[string]$link){ try{ ([System.Uri]::new([System.Uri]$base,$link)).AbsoluteUri }catch{ $null } }
function Same-Origin([string]$a,[string]$b){ try{ $ua=[Uri]$a; $ub=[Uri]$b; ($ua.Scheme -eq $ub.Scheme -and $ua.Host -eq $ub.Host -and $ua.Port -eq $ub.Port) }catch{ $false } }
function Get-ScriptsFromHtml([string]$html){
  if([string]::IsNullOrEmpty($html)){ return @() }
  $out=@()
  try{
    foreach($m in [regex]::Matches($html,$re_script_src,'IgnoreCase')){ $v=$m.Groups[1].Value; if($v){ $out+= $v } }
    foreach($m in [regex]::Matches($html,$re_link_pre,'IgnoreCase'))  { $v=$m.Groups[1].Value; if($v){ $out+= $v } }
  }catch{}
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
function Crawl-And-Collect([string]$BaseUrl){
  $res = @{ base_url=$BaseUrl; pages_crawled=@(); js_files=@() }
  try{
    $html = Http-GetText $BaseUrl
    $res.pages_crawled += @{ url=$BaseUrl; status=200; size=($html.Length) }
  }catch{
    $res.pages_crawled += @{ url=$BaseUrl; error=("$_") }; return $res
  }
  $toVisit = New-Object System.Collections.Queue
  $seenPages = New-Object System.Collections.Generic.HashSet[string]
  $seenJs    = New-Object System.Collections.Generic.HashSet[string]
  $toVisit.Enqueue($BaseUrl); [void]$seenPages.Add($BaseUrl)

  try{ foreach($s in (Get-ScriptsFromHtml $html)){ $f=Url-Join $BaseUrl $s; if($f -and ($JsExts | Where-Object { $f.EndsWith($_) })){ [void]$seenJs.Add($f) } } }catch{}
  while($toVisit.Count -gt 0 -and $res.pages_crawled.Count -lt $MaxPages){
    $url = $toVisit.Dequeue()
    if($url -ne $BaseUrl){
      try{
        $html2 = Http-GetText $url
        $res.pages_crawled += @{ url=$url; status=200; size=($html2.Length) }
        try{ foreach($s in (Get-ScriptsFromHtml $html2)){ $f=Url-Join $url $s; if($f -and ($JsExts | Where-Object { $f.EndsWith($_) }) -and $seenJs.Count -lt $MaxJsPerSite){ [void]$seenJs.Add($f) } } }catch{}
        foreach($m in [regex]::Matches($html2,$re_href,'IgnoreCase')){
          $lnk=$m.Groups[1].Value; $f=Url-Join $url $lnk
          if($f -and (Same-Origin $BaseUrl $f)){
            if(($JsExts | Where-Object { $f.EndsWith($_) })){ if($seenJs.Count -lt $MaxJsPerSite){ [void]$seenJs.Add($f) } }
            else { if(-not $seenPages.Contains($f) -and $seenPages.Count -lt $MaxPages){ [void]$seenPages.Add($f); $toVisit.Enqueue($f) } }
          }
        }
      }catch{ $res.pages_crawled += @{ url=$url; error=("$_") } }
    }
  }
  $jsList=@(); foreach($j in $seenJs){ $jsList+= $j }
  foreach($js in ($jsList | Sort-Object)){
    try{
      $bytes = Http-GetBytes $js
      $text  = [Text.Encoding]::UTF8.GetString($bytes)
      $hash  = Get-Sha256 $bytes
      $hash12= $hash.Substring(0,12)
      $u=[Uri]$js
      $hostDir = Join-Path $DumpRoot ($u.Host.Replace(':','_'))
      New-Item -ItemType Directory -Path $hostDir -ErrorAction SilentlyContinue | Out-Null
      $name = [IO.Path]::GetFileName($u.AbsolutePath); if([string]::IsNullOrWhiteSpace($name)){ $name = 'bundle.js' }
      $outPath = Join-Path $hostDir ("{0}__{1}" -f $hash12,$name)
      [IO.File]::WriteAllBytes($outPath,$bytes)

      $keywords=@(); foreach($k in $PackageKeywords){ if([regex]::IsMatch($text,[regex]::Escape($k))){ $keywords+= $k } }
      $patterns=@(); foreach($rx in $SuspiciousRegex){ if([regex]::IsMatch($text,$rx,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)){ $patterns+= $rx } }
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

      $bad=@(); foreach($vh in $versionHints){ if($BadPackages.ContainsKey($vh.name) -and $BadPackages[$vh.name] -eq $vh.version){ $bad += ("{0}@{1}" -f $vh.name,$vh.version) } }
      $res.js_files += @{ url=$js; path=$outPath; size=$bytes.Length; sha256=$hash; keywords=$keywords; patterns=$patterns; version_hints=$versionHints; bad_version_match=$bad; obfuscation_exact=$obfExact; obfuscation_relaxed=$obfRelax }
    }catch{ $res.js_files += @{ url=$js; error=("$_") } }
  }
  $res
}

# ---------- Reporting ----------
function Write-Json([string]$path,$obj){
  Set-Content -Path $path -Value ($obj | ConvertTo-Json -Depth 8) -Encoding UTF8
}
function Write-CsvSummary([string]$csvPath,$packages_hits){
  $rows=@()
  foreach($h in $packages_hits){
    $rows += [pscustomobject]@{ host=$h.host; name=$h.name; version=$h.version; where=$h.where; type=$h.type }
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
  $summary = @{ generated_at=$ts; ioc_info=$IocInfo; bad_packages=$BadPackages; web_scans=$webScans; local_scan=$localScan }
  Write-Json $jsonPath $summary
  if($localScan -and $localScan.packages_hits){ Write-CsvSummary -csvPath $csvPath -packages_hits $localScan.packages_hits }

  if($NoHtml){ return }

  $totWeb = ($webScans | Measure-Object).Count
  $bundles=$susp=$comp=$obx=$obr=0
  foreach($w in ($webScans | Where-Object { $_ })){
    $k = @{ bundles=0;suspicious=0;compromised=0;obfus_exact=0;obfus_relax=0 }
    foreach($j in $w.js_files){
      if($j.size){ $k.bundles++ }
      if($j.patterns -and $j.patterns.Count -gt 0){ $k.suspicious++ }
      if($j.bad_version_match -and $j.bad_version_match.Count -gt 0){ $k.compromised++ }
      if($j.obfuscation_exact){ $k.obfus_exact++ }
      if($j.obfuscation_relaxed){ $k.obfus_relax++ }
    }
    $bundles += $k.bundles; $susp += $k.suspicious; $comp += $k.compromised; $obx += $k.obfus_exact; $obr += $k.obfus_relax
  }
  $totLocal = if($localScan){ ($localScan.packages_hits | Measure-Object).Count } else { 0 }

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
  [void]$html.Append("<section><h2>Impact Summary (Hosts & Paths)</h2>$impactHtml</section>")
  [void]$html.Append("<div class='kpis'>")
  [void]$html.Append("<div class='kpi'><div class='n'>${totWeb}</div><div class='l'>Web targets</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n'>${bundles}</div><div class='l'>Bundles analyzed</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n warn'>${susp}</div><div class='l'>Suspicious patterns</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n danger'>${comp}</div><div class='l'>Compromised (web)</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n'>${obx}/${obr}</div><div class='l'>Obfuscation (exact/relax)</div></div>")
  [void]$html.Append("<div class='kpi'><div class='n danger'>${totLocal}</div><div class='l'>Compromised (local)</div></div>")
  [void]$html.Append("</div>")
  [void]$html.Append("<section><div class='card'><h3>Incident IOCs / Reference</h3><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>")
  foreach($k in $IocInfo.Keys){ $v=[System.Web.HttpUtility]::HtmlEncode($IocInfo[$k]); [void]$html.Append("<tr><td>$k</td><td><code>$v</code></td></tr>") }
  [void]$html.Append("</tbody></table></div></section>")
  [void]$html.Append("<section><div class='card'><h3>Known Compromised Versions</h3><table><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>")
  foreach($k in ($BadPackages.Keys | Sort-Object)){ $v=$BadPackages[$k]; [void]$html.Append("<tr><td><code>$k</code></td><td class='danger'><code>$v</code></td></tr>") }
  [void]$html.Append("</tbody></table></div></section>")
  [void]$html.Append("<footer>Rebuild artifacts after remediation (pin/override versions), invalidate CDN if needed. - Supply-chain NPM Scanner</footer></body></html>")
  Set-Content -Path $htmlPath -Value $html.ToString() -Encoding UTF8
}

# ---------- Orchestration ----------
$ts = NowTag
try{
  if($Mode -eq 'local'){
    $MachineLabel = Sanitize-Label ([System.Net.Dns]::GetHostName())
    $prefix = if($ReportPrefix){ $ReportPrefix } else { "report_{0}__local" -f $MachineLabel }
    $localScan = Scan-Local $Roots
    $htmlOut = Join-Path $ReportsRoot ("{0}_{1}.html" -f $prefix,$ts)
    $jsonOut = Join-Path $ReportsRoot ("{0}_{1}.json" -f $prefix,$ts)
    $csvOut  = Join-Path $ReportsRoot ("{0}_{1}.csv"  -f $prefix,$ts)
    Build-Report @() $localScan $htmlOut $jsonOut $csvOut
    if(-not $NoHtml){ Log "[OK] HTML report: $htmlOut" }
    Log "[OK] JSON report: $jsonOut"
    Log "[OK] CSV summary: $csvOut"
    $findings = ($localScan.packages_hits | Measure-Object).Count
    if($findings -gt 0){ exit 1 } else { exit 0 }
  }

  if($Mode -eq 'web'){
    $targets=@()
    if($Url){ $targets=@( Normalize-Url $Url $Scheme ) }
    elseif($File){
      $lines = Get-Content -Path $File | Where-Object { $_.Trim() }
      $targets = $lines | ForEach-Object { Normalize-Url $_ $Scheme } | Where-Object { $_ }
    }
    elseif($Domain){
      $hosts = New-Object System.Collections.Generic.HashSet[string]
      # crt.sh only (minimal)
      $url = "https://crt.sh/?q=%25.$Domain&output=json"
      try{ $data = Invoke-RestMethod -Uri $url -TimeoutSec 20 }catch{ $data = @() }
      foreach($e in $data){
        $names = ($e.name_value -split "`n") | ForEach-Object { $_.Trim().ToLower().Trim('.') }
        foreach($n in $names){ if($n -like "*.$Domain" -or $n -eq $Domain){ [void]$hosts.Add($n) } }
      }
      $arr=@(); foreach($h in $hosts){ $arr+=$h }
      $targets = $arr | Sort-Object | ForEach-Object { Normalize-Url $_ $Scheme }
    } else { throw "For 'web' mode, specify -Url or -File or -Domain" }

    if(-not $targets){ throw 'No web targets.' }
    if(-not $Quiet){ Write-Host ("[*] Web targets: {0}" -f $targets.Count) -ForegroundColor Cyan }

    $webScans=@()
    foreach($u in $targets){
      try{ $webScans += (Crawl-And-Collect $u) }catch{ $webScans += @{ base_url=$u; pages_crawled=@(@{url=$u; error=("$_")}); js_files=@() } }
    }

    $first = ([Uri]$targets[0]).Host; $rest = [Math]::Max(0,$targets.Count-1)
    $prefix = if($ReportPrefix){ $ReportPrefix } else { "report_{0}+{1}__webbatch" -f (Sanitize-Label $first),$rest }
    $htmlOut = Join-Path $ReportsRoot ("{0}_{1}.html" -f $prefix,$ts)
    $jsonOut = Join-Path $ReportsRoot ("{0}_{1}.json" -f $prefix,$ts)
    $csvOut  = Join-Path $ReportsRoot ("{0}_{1}.csv"  -f $prefix,$ts)
    Build-Report $webScans $null $htmlOut $jsonOut $csvOut
    if(-not $NoHtml){ Log "[OK] HTML report: $htmlOut" }
    Log "[OK] JSON report: $jsonOut"
    Log "[OK] CSV summary: $csvOut"
    exit 0
  }

  throw 'Unknown mode.'
}
catch{
  Err $_.Exception.Message
  exit 2
}
