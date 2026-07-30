function Remove-VcUser {
    <#
    .SYNOPSIS
        Deletes or deactivates a Veracode user.
    .DESCRIPTION
        Without -Deactivate, the user record is permanently deleted.
        With -Deactivate, the account is preserved but login_enabled is set to false —
        safer for audit trail and re-activation scenarios.
    .PARAMETER UserId
        User ID. Accepts pipeline input from Get-VcUsers.
    .PARAMETER Deactivate
        Disable the account instead of deleting it.
    .PARAMETER Force
        Bypasses confirmation.
    .EXAMPLE
        Remove-VcUser -UserId 'abc' -Deactivate
        Get-VcUsers -Inactive | Remove-VcUser -Force
        Get-VcUsers -Role 'Reviewer' -Email '*@contractor.com' | Remove-VcUser -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$UserId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Email,

        [switch]$Deactivate,
        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if ($Force) { $ConfirmPreference = 'None' }

        $label  = if ($Email) { "$Email ($UserId)" } else { $UserId }
        $action = if ($Deactivate) { 'Deactivate user' } else { 'Permanently delete user' }

        if (-not $PSCmdlet.ShouldProcess($label, $action)) { return }

        if ($Deactivate) {
            Write-Verbose "Deactivating user $label (setting login_enabled = false)..."
            Set-VcUser -UserId $UserId -Email $Email -LoginEnabled $false -Profile $Profile -Confirm:$false | Out-Null
            Write-Verbose "User $label deactivated."
        } else {
            Write-Verbose "Deleting user $label..."
            Invoke-VcApi -Method DELETE -Path "/api/authn/v2/users/$UserId" -Profile $Profile | Out-Null
            Write-Verbose "User $label deleted."
        }
    }
}
