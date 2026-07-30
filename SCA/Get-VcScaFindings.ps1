function Get-VcScaFindings {
    <#
    .SYNOPSIS
        Lists Software Composition Analysis (SCA) findings for an application,
        enriched with library, version, CVE, CVSS, license, and fix information.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER MinCvss
        Return only findings with CVSS score >= this value (e.g. 7.0 for High+).
    .PARAMETER LicenseRisk
        Filter by license risk: HIGH, MEDIUM, LOW, UNRECOGNIZED.
    .PARAMETER FlawStatus
        OPEN (default) or CLOSED.
    .EXAMPLE
        Get-VcScaFindings -AppGuid 'abc'
        Get-VcScaFindings -AppGuid 'abc' -MinCvss 7.0
        Get-VcApplications | Get-VcScaFindings -LicenseRisk HIGH
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [double]$MinCvss = 0,

        [ValidateSet('HIGH','MEDIUM','LOW','UNRECOGNIZED')]
        [string]$LicenseRisk,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus = 'OPEN',

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $query = @{ scan_type = 'SCA'; finding_status = $FlawStatus }

        $raw = Invoke-VcPagedApi -Path "/appsec/v2/applications/$AppGuid/findings" `
                                 -EmbeddedKey 'findings' -Query $query -Profile $Profile

        $findings = @($raw | ForEach-Object { ConvertTo-VcScaFinding $_ $AppGuid })

        if ($MinCvss -gt 0) {
            $findings = @($findings | Where-Object { $_.CvssScore -ge $MinCvss -or $_.Cvss3Score -ge $MinCvss })
        }
        if ($LicenseRisk) {
            $findings = @($findings | Where-Object { $_.LicenseRisk -eq $LicenseRisk })
        }

        return $findings
    }
}

function ConvertTo-VcScaFinding {
    param($Raw, [string]$AppGuid)

    $d = $Raw.finding_details
    $s = $Raw.finding_status

    # CVE IDs may be a single string or an array
    $cveIds = @()
    if ($d.cve_ids) {
        $cveIds = @($d.cve_ids)
    } elseif ($d.cve_id) {
        $cveIds = @($d.cve_id)
    }

    $cvss2 = [double]($d.cvss_score  ?? 0)
    $cvss3 = [double]($d.cvss3_score ?? 0)

    [pscustomobject]@{
        IssueId          = $Raw.issue_id
        AppGuid          = $AppGuid
        ScanType         = 'SCA'
        Severity         = $Raw.severity
        SeverityLabel    = $script:VcSeverityLabels[[int]$Raw.severity]
        CweId            = $Raw.cwe_id
        CweName          = $d.cwe?.name
        # Library info
        Library          = $d.component_filename ?? $d.file_name
        Version          = $d.component_version
        FixedInVersion   = $d.fixed_version ?? $d.fixed_in_version
        HasFix           = [bool]($d.fixed_version -or $d.fixed_in_version)
        # Vulnerability info
        CveIds           = $cveIds
        CveList          = ($cveIds -join ', ')
        CvssScore        = $cvss2
        Cvss3Score       = $cvss3
        MaxCvss          = [Math]::Max($cvss2, $cvss3)
        # License info
        LicenseName      = $d.license?.name
        LicenseRisk      = $d.license?.risk_level
        # Status
        FlawStatus       = $s?.status
        MitigationStatus = $s?.mitigation_review_status
        FirstFoundDate   = $s?.first_found_date
        LastSeenDate     = $s?.last_seen_date
        DaysOpen         = if ($s?.first_found_date) {
                               [int]([DateTimeOffset]::UtcNow -
                               [DateTimeOffset]::Parse($s.first_found_date)).TotalDays
                           } else { $null }
        _Raw             = $Raw
    }
}
