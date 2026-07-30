function Get-VcApplications {
    <#
    .SYNOPSIS
        Lists applications in the Veracode platform.
    .PARAMETER Name
        Wildcard filter applied client-side (e.g. 'MyApp*').
    .PARAMETER PolicyCompliance
        Filter by compliance status: PASSED, DID_NOT_PASS, NOT_ASSESSED, CALCULATING.
    .PARAMETER BusinessUnit
        Filter by business unit name (server-side filter).
    .PARAMETER ScanType
        Filter by scan type: STATIC, DYNAMIC, MANUAL.
    .PARAMETER Profile
        Credentials profile to use.
    .EXAMPLE
        Get-VcApplications
        Get-VcApplications -Name 'MyApp*' -PolicyCompliance DID_NOT_PASS
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [ValidateSet('PASSED','DID_NOT_PASS','NOT_ASSESSED','CALCULATING')]
        [string]$PolicyCompliance,
        [string]$BusinessUnit,
        [ValidateSet('STATIC','DYNAMIC','MANUAL')]
        [string]$ScanType,
        [string]$Profile = $script:VcCurrentProfile
    )

    $query = @{}
    if ($PolicyCompliance) { $query['policy_compliance_status'] = $PolicyCompliance }
    if ($BusinessUnit)     { $query['business_unit']            = $BusinessUnit }
    if ($ScanType)         { $query['scan_type']                = $ScanType }

    Write-Verbose 'Fetching all applications (paged)...'
    $raw = Invoke-VcPagedApi -Path '/appsec/v1/applications' -EmbeddedKey 'applications' `
                             -Query $query -Profile $Profile

    $apps = $raw | ForEach-Object { ConvertTo-VcApplication $_ }

    if ($Name) {
        $apps = $apps | Where-Object { $_.Name -like $Name }
    }

    return $apps
}

function Get-VcApplication {
    <#
    .SYNOPSIS
        Gets a single application by GUID or legacy numeric ID.
    .EXAMPLE
        Get-VcApplication -Guid 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
        Get-VcApplication -LegacyId 12345
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByGuid')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByGuid')]
        [string]$Guid,

        [Parameter(Mandatory, ParameterSetName = 'ByLegacyId')]
        [int]$LegacyId,

        [string]$Profile = $script:VcCurrentProfile
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByLegacyId') {
        $results = Invoke-VcApi -Path '/appsec/v1/applications' `
                                -Query @{ legacy_id = $LegacyId } -Profile $Profile
        $raw = $results._embedded.applications | Select-Object -First 1
        if (-not $raw) { throw "Application with legacy ID $LegacyId not found." }
    } else {
        $raw = Invoke-VcApi -Path "/appsec/v1/applications/$Guid" -Profile $Profile
    }

    return ConvertTo-VcApplication $raw
}

# Converts a raw API application object to a flat PSCustomObject.
function ConvertTo-VcApplication {
    param($Raw)
    [pscustomobject]@{
        Guid                = $Raw.guid
        LegacyId            = $Raw.id
        Name                = $Raw.profile.name
        Description         = $Raw.profile.description
        BusinessCriticality = $Raw.profile.business_criticality
        PolicyName          = ($Raw.profile.policies | Select-Object -First 1).name
        PolicyGuid          = ($Raw.profile.policies | Select-Object -First 1).guid
        PolicyCompliance    = $Raw.profile.policy_compliance_status
        LastScanDate        = $Raw.profile.last_completed_scan_date
        BusinessUnit        = $Raw.profile.business_unit.name
        BusinessUnitGuid    = $Raw.profile.business_unit.guid
        Teams               = ($Raw.profile.teams | ForEach-Object { $_.team_name }) -join ', '
        TeamGuids           = $Raw.profile.teams | ForEach-Object { $_.guid }
        _Raw                = $Raw
    }
}
