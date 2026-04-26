# tapid install script — Windows PowerShell
#
# Usage:
#   iwr https://raw.githubusercontent.com/EyeRunnMan/tapid/main/install.ps1 | iex
#
# Optional env vars:
#   $env:TAPID_VERSION  pin to a specific tag (default: latest release)
#   $env:TAPID_DIR      install dir (default: $env:LOCALAPPDATA\tapid\bin)

$ErrorActionPreference = "Stop"

$Repo = "EyeRunnMan/tapid"
$InstallDir = if ($env:TAPID_DIR) { $env:TAPID_DIR } else { "$env:LOCALAPPDATA\tapid\bin" }

# Detect arch
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "tapid-install: unsupported arch $($env:PROCESSOR_ARCHITECTURE)" }
}

# Resolve version
$ver = $env:TAPID_VERSION
if (-not $ver) {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $ver = $latest.tag_name
}
if (-not $ver.StartsWith("v")) { $ver = "v$ver" }

$asset = "tapid_${ver}_windows_${arch}.zip"
$url = "https://github.com/$Repo/releases/download/$ver/$asset"
$shaUrl = "$url.sha256"

Write-Host "-> tapid install: $ver windows/$arch"
Write-Host "-> download: $url"

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "tapid-install-$(Get-Random)")
try {
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    # Checksum
    try {
        $expectedLine = (Invoke-WebRequest -Uri $shaUrl -UseBasicParsing).Content
        $expected = ($expectedLine -split '\s+')[0]
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        if ($expected.ToLower() -ne $actual) {
            throw "sha256 mismatch (expected $expected, got $actual)"
        }
        Write-Host "✓ sha256 verified"
    } catch {
        Write-Warning "could not verify checksum: $_"
    }

    # Extract
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $tmp "tapid.exe") -Destination (Join-Path $InstallDir "tapid.exe") -Force

    Write-Host ""
    Write-Host "✓ installed: $InstallDir\tapid.exe"

    # PATH update (user-level)
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -split ';' -notcontains $InstallDir) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host ""
        Write-Host "✓ added $InstallDir to user PATH"
        Write-Host "  Open a new terminal, then run: tapid help"
    } else {
        Write-Host "✓ $InstallDir already on user PATH"
        Write-Host "  Reopen your terminal, then run: tapid help"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
