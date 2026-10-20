param([switch]$BundleTshark)

$ErrorActionPreference = 'Stop'
$version = '1.0.8'

$packagingRoot = $PSScriptRoot
$projectRoot = Split-Path -Parent $packagingRoot
$buildPython = Join-Path $projectRoot 'backend\.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $buildPython)) {
    throw "Build Python not found: $buildPython"
}

$buildRoot = Join-Path $packagingRoot 'build'
$guiDist = Join-Path $buildRoot 'dist-gui'
$backendDist = Join-Path $buildRoot 'dist-backend'

& $buildPython -m PyInstaller --noconfirm --clean --onedir --windowed --name PcapCheck `
    --distpath $guiDist --workpath (Join-Path $buildRoot 'work-gui') `
    --specpath (Join-Path $buildRoot 'spec-gui') `
    --icon (Join-Path $packagingRoot 'pcapcheck.ico') `
    (Join-Path $projectRoot 'desktop_gui\main.py')
if ($LASTEXITCODE -ne 0) { throw 'GUI PyInstaller build failed' }

& $buildPython -m PyInstaller --noconfirm --clean --onedir --console --name PcapCheckBackend `
    --distpath $backendDist --workpath (Join-Path $buildRoot 'work-backend') `
    --specpath (Join-Path $buildRoot 'spec-backend') --paths (Join-Path $projectRoot 'backend') `
    (Join-Path $packagingRoot 'backend_service.py')
if ($LASTEXITCODE -ne 0) { throw 'Backend PyInstaller build failed' }

$outputRoot = Join-Path $packagingRoot 'output'
$portable = Join-Path $outputRoot "PcapCheck_Portable_$version"
$portableZip = Join-Path $outputRoot "PcapCheck_Portable_$version.zip"
if (Test-Path -LiteralPath $portable) {
    throw "Output already exists; preserve it before building: $portable"
}
if (Test-Path -LiteralPath $portableZip) {
    throw "Output already exists; preserve it before building: $portableZip"
}
New-Item -ItemType Directory -Force -Path $portable | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $portable 'backend') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $portable 'data') | Out-Null

Copy-Item (Join-Path $guiDist 'PcapCheck\*') $portable -Recurse -Force
Copy-Item (Join-Path $backendDist 'PcapCheckBackend\*') (Join-Path $portable 'backend') -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $portable 'docs') | Out-Null
Copy-Item (Join-Path $projectRoot 'docs\kb') (Join-Path $portable 'docs\kb') -Recurse -Force
foreach ($doc in @('GETTING_STARTED.md', 'TESTING.md', 'RELEASING.md', 'GITHUB_PUBLISH.md')) {
    Copy-Item (Join-Path $projectRoot "docs\$doc") (Join-Path $portable "docs\$doc") -Force
}
Copy-Item (Join-Path $projectRoot 'README.md') (Join-Path $portable 'README.md') -Force
Copy-Item (Join-Path $projectRoot 'LICENSE') (Join-Path $portable 'LICENSE') -Force
Copy-Item (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md') (Join-Path $portable 'THIRD_PARTY_NOTICES.md') -Force
New-Item -ItemType Directory -Force -Path (Join-Path $portable 'licenses\inno-chinese') | Out-Null
Copy-Item (Join-Path $packagingRoot 'languages\LICENSE.txt') (Join-Path $portable 'licenses\inno-chinese\LICENSE.txt') -Force
Copy-Item (Join-Path $packagingRoot 'portable-data\settings.json') (Join-Path $portable 'data\settings.json') -Force
Copy-Item (Join-Path $packagingRoot 'portable-data\README.txt') (Join-Path $portable 'README.txt') -Force
& $buildPython (Join-Path $packagingRoot 'collect_licenses.py') --output (Join-Path $portable 'licenses')
if ($LASTEXITCODE -ne 0) { throw 'Third-party license collection failed' }

if ($BundleTshark) {
    Write-Warning 'Bundled TShark distribution requires corresponding-source and third-party license review. See docs/RELEASING.md.'
    $wiresharkSource = 'C:\Program Files\Wireshark'
    $wiresharkTarget = Join-Path $portable 'tools\tshark'
    if (!(Test-Path -LiteralPath (Join-Path $wiresharkSource 'tshark.exe'))) {
        throw "Wireshark TShark runtime not found: $wiresharkSource"
    }
    New-Item -ItemType Directory -Force -Path $wiresharkTarget | Out-Null
    Copy-Item (Join-Path $wiresharkSource '*') $wiresharkTarget -Recurse -Force
}

$iscc = @(
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (!$iscc) { throw 'Inno Setup ISCC.exe not found' }
& $iscc (Join-Path $packagingRoot 'PcapCheck.iss')
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed' }

$portableSize = [math]::Round(((Get-ChildItem -LiteralPath $portable -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
$installer = Join-Path $outputRoot "PcapCheck_Setup_$version.exe"
Compress-Archive -Path $portable -DestinationPath $portableZip -CompressionLevel Optimal
Write-Output "Portable package: $portable"
Write-Output "Portable archive: $portableZip"
Write-Output "Portable size: $portableSize MB"
Write-Output "Installer: $installer"
