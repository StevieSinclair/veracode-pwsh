$ErrorActionPreference = 'Stop'

# Module-level state
$script:VcCurrentProfile = 'default'

# Load order matters: Core first, then domain modules, then Dashboard last
$script:CoreFiles = @(
    'Core/Config.ps1'
    'Core/Auth.ps1'
    'Core/ApiClient.ps1'
)

$script:DomainDirs = @(
    'Applications'
    'Sandboxes'
    'Scans'
    'Users'
    'Teams'
    'Findings'
    'Policy'
    'Admin'
    'Analysis'
    'SCA'
    'DAST'
    'Dashboard'
)

foreach ($file in $script:CoreFiles) {
    $fullPath = Join-Path $PSScriptRoot $file
    if (Test-Path $fullPath) {
        . $fullPath
    }
}

foreach ($dir in $script:DomainDirs) {
    $dirPath = Join-Path $PSScriptRoot $dir
    if (Test-Path $dirPath) {
        Get-ChildItem -Path $dirPath -Filter '*.ps1' -ErrorAction SilentlyContinue |
            Sort-Object Name |
            ForEach-Object { . $_.FullName }
    }
}
