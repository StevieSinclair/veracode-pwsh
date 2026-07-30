# Reads and writes .veracode\credentials relative to the module root.
# Environment variables VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET override the file.

# $PSScriptRoot here is the Core\ directory; go up one level to reach the module root.
$script:ModuleRoot      = Split-Path $PSScriptRoot -Parent
$script:CredentialsPath = Join-Path $script:ModuleRoot '.veracode' 'credentials'

function Get-VcCredential {
    <#
    .SYNOPSIS
        Returns the API ID and secret for the given profile.
    .EXAMPLE
        $cred = Get-VcCredential
        $cred = Get-VcCredential -Profile staging
    #>
    [CmdletBinding()]
    param(
        [string]$Profile = $script:VcCurrentProfile
    )

    # Environment variables take precedence (useful for CI)
    $envId     = $env:VERACODE_API_KEY_ID
    $envSecret = $env:VERACODE_API_KEY_SECRET
    if ($envId -and $envSecret) {
        return [pscustomobject]@{ Id = $envId; Secret = $envSecret; Source = 'environment' }
    }

    if (-not (Test-Path $script:CredentialsPath)) {
        throw "Credentials file not found at '$($script:CredentialsPath)'. Run Initialize-VcCredentials to create it, or set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET environment variables."
    }

    $parsed = ConvertFrom-VcIni -Path $script:CredentialsPath
    if (-not $parsed.ContainsKey($Profile)) {
        $available = $parsed.Keys -join ', '
        throw "Profile '$Profile' not found in credentials file. Available profiles: $available"
    }

    $section = $parsed[$Profile]
    $id      = $section['veracode_api_key_id']
    $secret  = $section['veracode_api_key_secret']

    if (-not $id -or -not $secret) {
        throw "Profile '$Profile' is missing veracode_api_key_id or veracode_api_key_secret."
    }

    return [pscustomobject]@{ Id = $id.Trim(); Secret = $secret.Trim(); Source = "file:$Profile" }
}

function Set-VcCredential {
    <#
    .SYNOPSIS
        Writes or updates an API ID and secret in the credentials file.
    .EXAMPLE
        Set-VcCredential -Id 'abc123' -Secret 'def456'
        Set-VcCredential -Id 'abc123' -Secret 'def456' -Profile staging
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$Secret,

        [string]$Profile = $script:VcCurrentProfile
    )

    $dir = Split-Path $script:CredentialsPath
    if (-not (Test-Path $dir)) {
        if ($PSCmdlet.ShouldProcess($dir, 'Create directory')) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Read existing file or start fresh
    $parsed = @{}
    if (Test-Path $script:CredentialsPath) {
        $parsed = ConvertFrom-VcIni -Path $script:CredentialsPath
    }

    $parsed[$Profile] = @{
        veracode_api_key_id     = $Id
        veracode_api_key_secret = $Secret
    }

    $lines = foreach ($sectionName in $parsed.Keys) {
        "[$sectionName]"
        foreach ($key in $parsed[$sectionName].Keys) {
            "$key = $($parsed[$sectionName][$key])"
        }
        ''
    }

    if ($PSCmdlet.ShouldProcess($script:CredentialsPath, 'Write credentials')) {
        $lines | Set-Content -Path $script:CredentialsPath
        # Restrict file permissions on Unix; Windows relies on NTFS ACLs.
        if ($IsLinux -or $IsMacOS) {
            & chmod 600 $script:CredentialsPath 2>$null
        }
        Write-Host "Credentials saved to '$($script:CredentialsPath)' under profile '$Profile'."
    }
}

function Set-VcProfile {
    <#
    .SYNOPSIS
        Switches the active credentials profile for this session.
    .EXAMPLE
        Set-VcProfile -Profile staging
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Profile
    )
    $script:VcCurrentProfile = $Profile
    Write-Host "Active profile set to '$Profile'."
}

function Get-VcProfile {
    return $script:VcCurrentProfile
}

# Internal: minimal INI parser. Returns hashtable of section => hashtable of key/value.
function ConvertFrom-VcIni {
    param([string]$Path)

    $result  = @{}
    $section = $null

    foreach ($line in Get-Content -Path $Path) {
        $line = $line.Trim()
        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1].Trim()
            if (-not $result.ContainsKey($section)) {
                $result[$section] = @{}
            }
        }
        elseif ($line -match '^([^#;=]+)=(.*)$' -and $section) {
            $k = $Matches[1].Trim()
            $v = $Matches[2].Trim()
            $result[$section][$k] = $v
        }
    }

    return $result
}
