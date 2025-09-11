param([string[]]$Path, [switch]$HtmlReport)

$BadPackages = @{
    "debug" = "4.4.2"; "chalk" = "5.6.1"; "ansi-styles" = "6.2.2"
    "strip-ansi" = "7.1.1"; "color-convert" = "3.1.1"; "ansi-regex" = "6.2.1"
    "supports-color" = "10.2.1"; "wrap-ansi" = "9.0.1"; "slice-ansi" = "7.1.1"
    "color-name" = "2.0.1"; "color-string" = "2.1.1"; "has-ansi" = "6.0.1"
    "supports-hyperlinks" = "4.1.1"; "chalk-template" = "1.1.1"
    "backslash" = "0.2.1"; "is-arrayish" = "0.3.3"; "error-ex" = "1.3.3"
    "simple-swizzle" = "0.2.3"
}

$compromisedCount = 0
$scannedFiles = 0
$detections = @()

Write-Host "[*] NPM Supply Chain Scanner - Demarrage..." -ForegroundColor Cyan
Write-Host "[*] Recherche des packages compromis (hack du 8 septembre 2024)" -ForegroundColor Cyan

foreach ($scanPath in $Path) {
    if (-not (Test-Path $scanPath)) {
        Write-Host "[!] Chemin non trouve: $scanPath" -ForegroundColor Red
        continue
    }
    
    Write-Host "[*] Scan de: $scanPath" -ForegroundColor White
    
    $packageFiles = Get-ChildItem -Path $scanPath -Name "package.json" -Recurse -ErrorAction SilentlyContinue
    $lockFiles = Get-ChildItem -Path $scanPath -Name "package-lock.json" -Recurse -ErrorAction SilentlyContinue
    
    Write-Host "    Trouve $($packageFiles.Count) fichiers package.json" -ForegroundColor Gray
    Write-Host "    Trouve $($lockFiles.Count) fichiers package-lock.json" -ForegroundColor Gray
    
    # Scan package.json
    foreach ($file in $packageFiles) {
        try {
            $fullPath = Join-Path $scanPath $file
            $content = Get-Content $fullPath -Raw -ErrorAction Stop
            $package = $content | ConvertFrom-Json -ErrorAction Stop
            $scannedFiles++
            
            if ($package.name -and $package.version) {
                if ($BadPackages.ContainsKey($package.name) -and $BadPackages[$package.name] -eq $package.version) {
                    $compromisedCount++
                    $detections += "[COMPROMIS] $($package.name)@$($package.version) dans $fullPath"
                    Write-Host "    [!] COMPROMIS: $($package.name)@$($package.version)" -ForegroundColor Red
                }
            }
            
            # Dependencies
            @("dependencies", "devDependencies") | ForEach-Object {
                if ($package.$_) {
                    $package.$_.PSObject.Properties | ForEach-Object {
                        $depVersion = $_.Value -replace '[^0-9.].*', ''
                        if ($depVersion -match '^\d+\.\d+\.\d+$') {
                            if ($BadPackages.ContainsKey($_.Name) -and $BadPackages[$_.Name] -eq $depVersion) {
                                $compromisedCount++
                                $detections += "[COMPROMIS] $($_.Name)@$depVersion dans $fullPath (dependencies)"
                                Write-Host "    [!] COMPROMIS DEP: $($_.Name)@$depVersion" -ForegroundColor Red
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Host "    [!] Erreur lecture: $file" -ForegroundColor Yellow
        }
    }
    
    # Scan package-lock.json
    foreach ($file in $lockFiles) {
        try {
            $fullPath = Join-Path $scanPath $file
            $content = Get-Content $fullPath -Raw -ErrorAction Stop
            $lock = $content | ConvertFrom-Json -ErrorAction Stop
            $scannedFiles++
            
            if ($lock.packages) {
                $lock.packages.PSObject.Properties | ForEach-Object {
                    if ($_.Value.name -and $_.Value.version) {
                        if ($BadPackages.ContainsKey($_.Value.name) -and $BadPackages[$_.Value.name] -eq $_.Value.version) {
                            $compromisedCount++
                            $detections += "[COMPROMIS] $($_.Value.name)@$($_.Value.version) dans $fullPath (lock)"
                            Write-Host "    [!] COMPROMIS LOCK: $($_.Value.name)@$($_.Value.version)" -ForegroundColor Red
                        }
                    }
                }
            }
        } catch {
            Write-Host "    [!] Erreur lecture lock: $file" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "[*] RESUME:" -ForegroundColor Cyan
Write-Host "    Fichiers scannees: $scannedFiles" -ForegroundColor White
Write-Host "    Packages compromis detectes: $compromisedCount" -ForegroundColor $(if($compromisedCount -gt 0){"Red"}else{"Green"})

if ($compromisedCount -gt 0) {
    Write-Host ""
    Write-Host "[!] ALERTE: Des packages compromis ont ete detectes!" -ForegroundColor Red
    Write-Host "    Actions recommandees:" -ForegroundColor Yellow
    Write-Host "    1. Supprimez node_modules/" -ForegroundColor Yellow
    Write-Host "    2. Mettez a jour les packages" -ForegroundColor Yellow
    Write-Host "    3. Reinstallez (npm install)" -ForegroundColor Yellow
    Write-Host "    4. Verifiez vos wallets crypto" -ForegroundColor Yellow
} else {
    Write-Host "    [OK] Aucun package compromis detecte!" -ForegroundColor Green
}

# Generation du rapport HTML (toujours si demande)
if ($HtmlReport) {
    $reportPath = "npm_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NPM Scanner Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
.container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; }
.clean { color: #28a745; font-weight: bold; }
.compromised { color: #dc3545; font-weight: bold; }
.info { color: #666; }
</style>
</head>
<body>
<div class="container">
<h1>NPM Supply Chain Scanner - Rapport</h1>
<p><strong>Date du scan:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p><strong>Chemin scanne:</strong> $($Path -join ', ')</p>

<div class="summary">
<h3>Resumé du scan</h3>
<p><strong>Fichiers analyses:</strong> $scannedFiles</p>
<p><strong>Packages compromis detectes:</strong> <span class="$(if($compromisedCount -gt 0){'compromised'}else{'clean'})">$compromisedCount</span></p>
</div>

<h3>Etat du systeme</h3>
"@
    
    if ($compromisedCount -gt 0) {
        $html += "<p class='compromised'>ALERTE: Des packages compromis ont ete detectes!</p>"
        $html += "<h3>Packages compromis detectes:</h3><ul>"
        foreach ($detection in $detections) {
            $html += "<li class='compromised'>$($detection -replace '<', '&lt;' -replace '>', '&gt;')</li>"
        }
        $html += "</ul>"
        $html += "<h3>Actions recommandees:</h3><ol>"
        $html += "<li>Supprimez tous les dossiers node_modules/</li>"
        $html += "<li>Mettez a jour les packages vers des versions sures</li>"
        $html += "<li>Relancez npm install ou yarn install</li>"
        $html += "<li>Verifiez vos portefeuilles crypto et cles privees</li>"
        $html += "</ol>"
    } else {
        $html += "<p class='clean'>SYSTEME SAIN: Aucun package compromis detecte!</p>"
        $html += "<p class='info'>Votre systeme ne semble pas affecte par l'incident de supply chain du 8 septembre 2024.</p>"
    }
    
    $html += @"
<h3>Packages compromis connus (IOCs)</h3>
<table border='1' style='border-collapse: collapse; width: 100%;'>
<tr><th style='padding: 8px; background: #f8f9fa;'>Package</th><th style='padding: 8px; background: #f8f9fa;'>Version Compromise</th></tr>
"@
    
    foreach ($pkg in $BadPackages.GetEnumerator() | Sort-Object Name) {
        $html += "<tr><td style='padding: 8px;'>$($pkg.Key)</td><td style='padding: 8px; color: #dc3545; font-weight: bold;'>$($pkg.Value)</td></tr>"
    }
    
    $html += @"
</table>

<hr style='margin-top: 40px;'>
<p class='info'><small>NPM Supply Chain Scanner - Detection de l'incident du 8 septembre 2024</small></p>
</div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "[*] Rapport HTML genere: $reportPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[*] Scan termine!" -ForegroundColor Green
    