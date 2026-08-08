function New-VcSandbox {
    <#
    .SYNOPSIS
        Creates a new development sandbox within an application.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Name
        Sandbox display name.
    .PARAMETER AutoRecreate
        When true, Veracode automatically recreates the sandbox after promotion.
    .EXAMPLE
        New-VcSandbox -AppGuid 'abc' -Name 'feature/login-rework'
        Get-VcApplication -Guid 'abc' | New-VcSandbox -Name 'sprint-42' -AutoRecreate
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$AutoRecreate,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $body = @{
            name          = $Name
            auto_recreate = $AutoRecreate.IsPresent
        }

        if (-not $PSCmdlet.ShouldProcess("$Name (app: $AppGuid)", 'Create sandbox')) { return }

        Write-Verbose "Creating sandbox '$Name' in application $AppGuid..."
        $raw = Invoke-VcApi -Method POST -Path "/appsec/v1/applications/$AppGuid/sandboxes" `
                            -Body $body -Profile $Profile
        return ConvertTo-VcSandbox $raw $AppGuid
    }
}
