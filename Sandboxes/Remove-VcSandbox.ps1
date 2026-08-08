function Remove-VcSandbox {
    <#
    .SYNOPSIS
        Deletes a sandbox and all its scan history from an application.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER SandboxGuid
        Sandbox GUID. Accepts pipeline input from Get-VcSandboxes.
    .PARAMETER Force
        Bypasses the confirmation prompt.
    .EXAMPLE
        Remove-VcSandbox -AppGuid 'app-guid' -SandboxGuid 'sb-guid'
        Get-VcSandboxes -AppGuid 'abc' | Where-Object { $_.LastModifiedDate -lt (Get-Date).AddDays(-90) } | Remove-VcSandbox -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SandboxGuid,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $label = if ($Name) { "'$Name' ($SandboxGuid)" } else { $SandboxGuid }

        if ($Force) { $ConfirmPreference = 'None' }

        if (-not $PSCmdlet.ShouldProcess($label, 'Permanently delete sandbox')) { return }

        Write-Verbose "Deleting sandbox $label from application $AppGuid..."
        Invoke-VcApi -Method DELETE -Path "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid" `
                     -Profile $Profile | Out-Null
        Write-Verbose "Deleted sandbox $label."
    }
}
