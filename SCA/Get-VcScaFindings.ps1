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

    $cvss2 = if ($null -ne $d.cvss_score)  { [double]$d.cvss_score }  else { [double]0 }
    $cvss3 = if ($null -ne $d.cvss3_score) { [double]$d.cvss3_score } else { [double]0 }
    $daysOpen = $null
    if ($null -ne $s -and $null -ne $s.first_found_date) {
        $daysOpen = [int]([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($s.first_found_date)).TotalDays
    }

    [pscustomobject]@{
        IssueId          = $Raw.issue_id
        AppGuid          = $AppGuid
        ScanType         = 'SCA'
        Severity         = $Raw.severity
        SeverityLabel    = $script:VcSeverityLabels[[int]$Raw.severity]
        CweId            = $Raw.cwe_id
        CweName          = $(if ($null -ne $d.cwe) { $d.cwe.name } else { $null })
        # Library info
        Library          = $(if ($null -ne $d.component_filename) { $d.component_filename } else { $d.file_name })
        Version          = $d.component_version
        FixedInVersion   = $(if ($null -ne $d.fixed_version) { $d.fixed_version } else { $d.fixed_in_version })
        HasFix           = [bool]($d.fixed_version -or $d.fixed_in_version)
        # Vulnerability info
        CveIds           = $cveIds
        CveList          = ($cveIds -join ', ')
        CvssScore        = $cvss2
        Cvss3Score       = $cvss3
        MaxCvss          = [Math]::Max($cvss2, $cvss3)
        # License info
        LicenseName      = $(if ($null -ne $d.license) { $d.license.name } else { $null })
        LicenseRisk      = $(if ($null -ne $d.license) { $d.license.risk_level } else { $null })
        # Status
        FlawStatus       = $(if ($null -ne $s) { $s.status } else { $null })
        MitigationStatus = $(if ($null -ne $s) { $s.mitigation_review_status } else { $null })
        FirstFoundDate   = $(if ($null -ne $s) { $s.first_found_date } else { $null })
        LastSeenDate     = $(if ($null -ne $s) { $s.last_seen_date } else { $null })
        DaysOpen         = $daysOpen
        _Raw             = $Raw
    }
}
