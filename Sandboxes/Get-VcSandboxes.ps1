function Get-VcSandboxes {
    <#
    .SYNOPSIS
        Lists all sandboxes for an application.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .EXAMPLE
        Get-VcSandboxes -AppGuid 'abc-def'
        Get-VcApplications -Name 'MyApp' | Get-VcSandboxes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        Write-Verbose "Fetching sandboxes for application $AppGuid..."
        $raw = Invoke-VcPagedApi -Path "/appsec/v1/applications/$AppGuid/sandboxes" `
                                 -EmbeddedKey 'sandboxes' -Profile $Profile

        $raw | ForEach-Object { ConvertTo-VcSandbox $_ $AppGuid }
    }
}

function Get-VcSandbox {
    <#
    .SYNOPSIS
        Gets a single sandbox by GUID.
    .EXAMPLE
        Get-VcSandbox -AppGuid 'app-guid' -SandboxGuid 'sb-guid'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$AppGuid,
        [Parameter(Mandatory)] [string]$SandboxGuid,
        [string]$Profile = $script:VcCurrentProfile
    )

    $raw = Invoke-VcApi -Path "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid" -Profile $Profile
    return ConvertTo-VcSandbox $raw $AppGuid
}

# Converts a raw API sandbox object to a flat PSCustomObject.
function ConvertTo-VcSandbox {
    param($Raw, [string]$AppGuid)
    [pscustomobject]@{
        SandboxGuid      = $Raw.guid
        AppGuid          = $AppGuid
        Name             = $Raw.name
        SandboxType      = $Raw.sandbox_type
        AutoRecreate     = $Raw.auto_recreate
        LastModifiedDate = $Raw.modified_date
        CustomFields     = $Raw.custom_fields
        _Raw             = $Raw
    }
}
