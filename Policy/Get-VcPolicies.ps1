function Get-VcPolicies {
    <#
    .SYNOPSIS
        Lists all security policies in the organisation.
    .PARAMETER Name
        Wildcard filter applied client-side against policy name.
    .PARAMETER Type
        Filter by policy type: CUSTOMER (org-defined) or VERACODE (built-in).
    .EXAMPLE
        Get-VcPolicies
        Get-VcPolicies -Name 'PCI*'
        Get-VcPolicies -Type CUSTOMER
    #>
    [CmdletBinding()]
    param(
        [string]$Name,

        [ValidateSet('CUSTOMER','VERACODE')]
        [string]$Type,

        [string]$Profile = $script:VcCurrentProfile
    )

    $query = @{}
    if ($Type) { $query['policy_compliance'] = $Type }

    $raw = Invoke-VcPagedApi -Path '/appsec/v1/policies' -EmbeddedKey 'policy_versions' -Query $query -Profile $Profile

    $policies = $raw | ForEach-Object { ConvertTo-VcPolicy $_ }

    if ($Name) {
        $policies = $policies | Where-Object { $_.PolicyName -like $Name }
    }

    return $policies
}

function Get-VcPolicy {
    <#
    .SYNOPSIS
        Returns a single policy by GUID.
    .PARAMETER PolicyGuid
        The policy GUID.
    .EXAMPLE
        Get-VcPolicy -PolicyGuid 'abc-123'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$PolicyGuid,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $raw = Invoke-VcApi -Method GET -Path "/appsec/v1/policies/$PolicyGuid" -Profile $Profile
        return ConvertTo-VcPolicy $raw
    }
}

function ConvertTo-VcPolicy {
    param($Raw)

    $rules = @()
    if ($Raw.finding_rules) {
        $rules = $Raw.finding_rules | ForEach-Object {
            [pscustomobject]@{
                RuleType   = $_.type
                ScanType   = $_.scan_type
                Severity   = $_.severity
                GraceJdays = $_.grace_period_days
            }
        }
    }

    [pscustomobject]@{
        PolicyGuid          = $Raw.guid
        PolicyName          = $Raw.name
        Description         = $Raw.description
        Type                = $Raw.policy_compliance_driver
        ScanFrequencyDays   = $Raw.scan_frequency_days
        GracePeriodDays     = $Raw.grace_period_days
        CustomSeverity      = $Raw.custom_severity
        FindingRules        = $rules
        FindingRuleCount    = @($rules).Count
        CreatedDate         = $Raw.created
        ModifiedDate        = $Raw.modified
        _Raw                = $Raw
    }
}
