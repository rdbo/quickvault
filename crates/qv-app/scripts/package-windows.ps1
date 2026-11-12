# SPDX-License-Identifier: AGPL-3.0-or-later
# Builds the Windows release zip (plan 0052): quickvault.exe, qv.exe, the
# licence, a short README and SHA256SUMS, then the zip and its checksum.
# Run from any directory on Windows (MSVC toolchain). Artifacts are
# unsigned: Authenticode signing needs the owner's certificate and is a
# release step, not part of this script.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Push-Location $root
try {
    cargo build --release --locked -p qv-cli --bin qv
    if ($LASTEXITCODE -ne 0) { throw 'building qv failed' }
    cargo build --release --locked -p qv-app --features desktop --bin quickvault
    if ($LASTEXITCODE -ne 0) { throw 'building quickvault failed' }

    $meta = cargo metadata --no-deps --format-version 1 --locked | ConvertFrom-Json
    $version = ($meta.packages | Where-Object { $_.name -eq 'qv-app' }).version
    $name = "quickvault-$version-windows-x86_64"
    $dist = Join-Path $root 'target\dist'
    $dir = Join-Path $dist $name
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Path $dir | Out-Null

    Copy-Item (Join-Path $root 'target\release\quickvault.exe') $dir
    Copy-Item (Join-Path $root 'target\release\qv.exe') $dir
    Copy-Item (Join-Path $root 'LICENSE') (Join-Path $dir 'LICENSE.txt')
    @(
        "QuickVault $version for Windows (x86_64)"
        ''
        'quickvault.exe  the desktop app (needs the Microsoft Edge WebView2 runtime,'
        '                part of Windows 11 and delivered to Windows 10 by Windows Update)'
        'qv.exe          the command-line client'
        ''
        'Vaults, anchors and snapshots live in %LOCALAPPDATA%\QuickVault.'
        'These files are not code-signed. Check them against SHA256SUMS.'
        'Licence: AGPL-3.0-or-later (LICENSE.txt).'
    ) | Set-Content -Encoding utf8 (Join-Path $dir 'README.txt')

    $sums = Get-ChildItem -File $dir | Sort-Object Name | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
    $sums | Set-Content -Encoding ascii (Join-Path $dir 'SHA256SUMS')

    $zip = Join-Path $dist "$name.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip
    $zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    "$zipHash  $name.zip" | Set-Content -Encoding ascii "$zip.sha256"
    Write-Output "Built $zip"
    Write-Output "SHA-256 $zipHash"
}
finally {
    Pop-Location
}
