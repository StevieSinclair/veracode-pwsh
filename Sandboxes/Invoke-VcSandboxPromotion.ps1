function Invoke-VcSandboxPromotion {
    <#
    .SYNOPSIS
        Promotes the latest completed sandbox scan to a policy scan.
    .DESCRIPTION
        The sandbox must have a scan in RESULTS_READY state. The promoted scan replaces the
        application's current policy scan and triggers a compliance re-evaluation.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER SandboxGuid
        Sandbox GUID. Accepts pipeline input from Get-VcSandboxes.
    .PARAMETER DeleteOnPromotion
        When specified, the sandbox is deleted after a successful promotion.
    .EXAMPLE
        Invoke-VcSandboxPromotion -AppGuid 'app-guid' -SandboxGuid 'sb-guid'
        Get-VcSandboxes -AppGuid 'abc' | Where-Object Name -eq 'release' | Invoke-VcSandboxPromotion
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SandboxGuid,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [switch]$DeleteOnPromotion,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $label = if ($Name) { "'$Name' ($SandboxGuid)" } else { $SandboxGuid }

        if (-not $PSCmdlet.ShouldProcess($label, 'Promote sandbox scan to policy scan')) { return }

        Write-Verbose "Promoting sandbox $label to policy scan..."

        $body = @{}
        if ($DeleteOnPromotion) { $body['delete_on_promotion'] = $true }

        Invoke-VcApi -Method POST `
                     -Path "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid/promote" `
                     -Body $body -Profile $Profile | Out-Null

        Write-Host "Sandbox $label promoted to policy scan successfully."

        if ($DeleteOnPromotion) {
            Write-Verbose "Sandbox $label deleted after promotion (delete_on_promotion=true)."
        }
    }
}
