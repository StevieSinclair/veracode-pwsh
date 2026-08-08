function Remove-VcApplication {
    <#
    .SYNOPSIS
        Deletes an application from Veracode. This is permanent and removes all scan history.
    .PARAMETER Guid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Force
        Skips the confirmation prompt. Use with caution.
    .EXAMPLE
        Remove-VcApplication -Guid 'abc-def'
        Get-VcApplications -Name 'test-*' | Remove-VcApplication -WhatIf
        Get-VcApplications -Name 'test-*' | Remove-VcApplication -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Guid,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $label = if ($Name) { "'$Name' ($Guid)" } else { $Guid }

        if ($Force) {
            $ConfirmPreference = 'None'
        }

        if (-not $PSCmdlet.ShouldProcess($label, 'Permanently delete Veracode application')) { return }

        Write-Verbose "Deleting application $label..."
        Invoke-VcApi -Method DELETE -Path "/appsec/v1/applications/$Guid" -Profile $Profile | Out-Null
        Write-Verbose "Deleted application $label."
    }
}
