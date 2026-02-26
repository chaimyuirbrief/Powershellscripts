# COMBINED: Find orphaned MSI/MSP in C:\Windows\Installer + export CSV + MOVE to backup folder
# Run in elevated PowerShell (Admin)

$installerDir = Join-Path $env:WINDIR "Installer"
$csvOut       = Join-Path $env:USERPROFILE "Desktop\OrphanedInstallerFiles.csv"
$backupDir    = "C:\Installer_Orphans_Backup"

if (-not (Test-Path $installerDir)) {
    Write-Host "Installer folder not found: $installerDir" -ForegroundColor Red
    exit 1
}

Write-Host "Building list of MSI/MSP packages Windows Installer says are IN USE..." -ForegroundColor Cyan

# Case-insensitive "in use" set
$usedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::InvariantCultureIgnoreCase)

# Windows Installer COM object
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
} catch {
    Write-Host "Failed to create WindowsInstaller.Installer COM object. Run as Admin." -ForegroundColor Red
    exit 1
}

# Products -> LocalPackage (MSI)
foreach ($productCode in $installer.Products()) {
    try {
        $lp = $installer.ProductInfo($productCode, "LocalPackage")
        if ($lp -and (Test-Path $lp)) { [void]$usedFiles.Add((Get-Item $lp).FullName) }
    } catch {}
}

# Patches -> LocalPackage (MSP)
foreach ($patchCode in $installer.Patches()) {
    try {
        $lp = $installer.PatchInfo($patchCode, "LocalPackage")
        if ($lp -and (Test-Path $lp)) { [void]$usedFiles.Add((Get-Item $lp).FullName) }
    } catch {}
}

Write-Host "Known IN-USE installer packages: $($usedFiles.Count)" -ForegroundColor Green
Write-Host "Scanning $installerDir for *.msi / *.msp ..." -ForegroundColor Cyan

$allInstallerFiles = Get-ChildItem $installerDir -File -Recurse -Include *.msi, *.msp -ErrorAction SilentlyContinue
Write-Host "Total MSI/MSP in cache: $($allInstallerFiles.Count)" -ForegroundColor Yellow

# Orphans = in folder but NOT referenced as LocalPackage
$orphans = $allInstallerFiles | Where-Object { -not $usedFiles.Contains($_.FullName) }

Write-Host "Potential orphaned files found: $($orphans.Count)" -ForegroundColor Magenta

# Build report
$report = $orphans | Select-Object `
    FullName,
    Extension,
    @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}}

# Export CSV
$report | Sort-Object SizeMB -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvOut
Write-Host "CSV written to: $csvOut" -ForegroundColor Green

# Nothing to move? Stop here.
if (-not $orphans -or $orphans.Count -eq 0) {
    Write-Host "No orphaned files detected. Nothing to move." -ForegroundColor Green
    exit 0
}

# Create backup folder
if (-not (Test-Path $backupDir)) {
    New-Item -Path $backupDir -ItemType Directory | Out-Null
}

# Move files (safe)
Write-Host "Moving orphaned files to: $backupDir" -ForegroundColor Cyan

$moved = 0
$failed = 0

foreach ($f in $orphans) {
    $src = $f.FullName
    if (Test-Path $src) {
        try {
            Move-Item -Path $src -Destination $backupDir -Force -ErrorAction Stop
            $moved++
        } catch {
            $failed++
            Write-Host "FAILED: $src" -ForegroundColor Red
        }
    }
}

# Summary
$freedBytes = ($orphans | Where-Object { $_ -and $_.Length } | Measure-Object -Property Length -Sum).Sum
$freedGB = if ($freedBytes) { [math]::Round($freedBytes / 1GB, 2) } else { 0 }

Write-Host ""
Write-Host "DONE." -ForegroundColor Green
Write-Host "Moved:  $moved file(s)"
Write-Host "Failed: $failed file(s)" -ForegroundColor Yellow
Write-Host "Approx space moved: $freedGB GB"
Write-Host "Backup location: $backupDir"
Write-Host ""
Write-Host "If everything works fine for a few days, you can delete $backupDir to reclaim space." -ForegroundColor Yellow
Write-Host "If anything breaks, you can move the files back to $installerDir (restore script available if you want)." -ForegroundColor Yellow
