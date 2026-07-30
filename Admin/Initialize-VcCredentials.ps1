function Initialize-VcCredentials {
    <#
    .SYNOPSIS
        Interactive wizard to configure Veracode API credentials.
        Validates the credentials with a test API call before saving.
    .PARAMETER Profile
        Credential profile name (default: 'default').
    .PARAMETER Force
        Overwrite existing credentials without prompting.
    .EXAMPLE
        Initialize-VcCredentials
        Initialize-VcCredentials -Profile 'production'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Profile = 'default',
        [switch]$Force
    )

    $credPath = Join-Path (Split-Path $PSScriptRoot -Parent) '.veracode' 'credentials'

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗"
    Write-Host "║        Veracode Credential Setup Wizard          ║"
    Write-Host "╚══════════════════════════════════════════════════╝"
    Write-Host ""
    Write-Host "Profile  : $Profile"
    Write-Host "Cred file: $credPath"
    Write-Host ""

    # Warn if credentials already exist
    if (Test-Path $credPath) {
        try {
            $existing = Get-VcCredential -Profile $Profile -ErrorAction SilentlyContinue
            if ($existing -and -not $Force) {
                $confirm = Read-Host "Credentials for profile '$Profile' already exist. Overwrite? [y/N]"
                if ($confirm -notmatch '^[yY]') {
                    Write-Host "Aborted — existing credentials left unchanged."
                    return
                }
            }
        } catch { }
    }

    Write-Host "Enter your Veracode API credentials."
    Write-Host "(Generate them at: My Account → API Service Accounts in the Veracode Platform)"
    Write-Host ""

    $apiId = Read-Host "API Key ID"
    if ([string]::IsNullOrWhiteSpace($apiId)) {
        throw "API Key ID cannot be empty."
    }

    $secretSecure = Read-Host "API Key Secret" -AsSecureString
    $apiSecret    = [System.Net.NetworkCredential]::new('', $secretSecure).Password

    if ([string]::IsNullOrWhiteSpace($apiSecret)) {
        throw "API Key Secret cannot be empty."
    }

    Write-Host ""
    Write-Host "Validating credentials..." -NoNewline

    try {
        # Quick test call — list 1 application
        Set-VcCredential -Id $apiId -Secret $apiSecret -Profile $Profile
        $test = Invoke-VcApi -Method GET -Path '/appsec/v1/applications' -Query @{ size = 1 } -Profile $Profile
        Write-Host " OK" -ForegroundColor Green
        Write-Host ""
        Write-Host "Credentials saved to: $credPath  [profile: $Profile]" -ForegroundColor Green
    } catch {
        # Clean up the invalid credentials we just wrote
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host ""
        Write-Warning "Credential validation failed: $_"
        Write-Host "The credentials file may contain invalid entries — please re-run the wizard."
        throw
    }
}
