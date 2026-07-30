function Set-VcSandbox {
    <#
    .SYNOPSIS
        Updates a sandbox name or auto-recreate setting.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER SandboxGuid
        Sandbox GUID. Accepts pipeline input from Get-VcSandboxes.
    .EXAMPLE
        Set-VcSandbox -AppGuid 'app-guid' -SandboxGuid 'sb-guid' -Name 'new-name'
        Get-VcSandboxes -AppGuid 'app-guid' | Where-Object Name -eq 'old' | Set-VcSandbox -Name 'new'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SandboxGuid,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Nullable[bool]]$AutoRecreate,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # Fetch current state to fill in unchanged fields for the PUT body.
        Write-Verbose "Fetching current sandbox state $SandboxGuid..."
        $current = Invoke-VcApi -Path "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid" -Profile $Profile

        $body = @{
            name          = $(if ($PSBoundParameters.ContainsKey('Name'))        { $Name }        else { $current.name })
            auto_recreate = $(if ($PSBoundParameters.ContainsKey('AutoRecreate')){ $AutoRecreate } else { $current.auto_recreate })
        }

        if (-not $PSCmdlet.ShouldProcess($SandboxGuid, 'Update sandbox')) { return }

        Write-Verbose "Updating sandbox $SandboxGuid..."
        $raw = Invoke-VcApi -Method PUT -Path "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid" `
                            -Body $body -Profile $Profile
        return ConvertTo-VcSandbox $raw $AppGuid
    }
}
