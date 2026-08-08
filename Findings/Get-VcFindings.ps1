# Numeric severity → human-readable label
$script:VcSeverityLabels = @{
    0 = 'Informational'
    1 = 'Very Low'
    2 = 'Low'
    3 = 'Medium'
    4 = 'High'
    5 = 'Very High'
}

function Get-VcFindings {
    <#
    .SYNOPSIS
        Lists findings (flaws) for an application or sandbox.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER SandboxGuid
        When provided, retrieves findings scoped to this sandbox via the context parameter.
    .PARAMETER ScanType
        Filter by scan type: STATIC, DYNAMIC, MANUAL, SCA.
        If omitted, all scan types are returned (note: SCA is excluded by default in the API
        unless explicitly included).
    .PARAMETER MinSeverity
        Return only findings with severity >= this value (0–5).
    .PARAMETER CweId
        Filter to a specific CWE ID.
    .PARAMETER FlawStatus
        Filter by flaw status: OPEN, CLOSED.
    .PARAMETER IncludeAnnotations
        Include mitigation annotations in the response.
    .EXAMPLE
        Get-VcFindings -AppGuid 'abc'
        Get-VcFindings -AppGuid 'abc' -MinSeverity 4 -ScanType STATIC
        Get-VcFindings -AppGuid 'abc' -SandboxGuid 'sb1' -IncludeAnnotations
        Get-VcApplications | Get-VcFindings -MinSeverity 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$SandboxGuid,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateRange(0,5)]
        [int]$MinSeverity = -1,

        [int]$CweId,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus,

        [switch]$IncludeAnnotations,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $query = @{}
        if ($ScanType)           { $query['scan_type']       = $ScanType }
        if ($MinSeverity -ge 0)  { $query['severity_gte']    = $MinSeverity }
        if ($CweId)              { $query['cwe_id']          = $CweId }
        if ($FlawStatus)         { $query['finding_status']  = $FlawStatus }
        if ($IncludeAnnotations) { $query['include_annot']   = 'TRUE' }
        if ($SandboxGuid)        { $query['context']         = $SandboxGuid }

        $path = "/appsec/v2/applications/$AppGuid/findings"
        Write-Verbose "Fetching findings from $path..."

        $raw = Invoke-VcPagedApi -Path $path -EmbeddedKey 'findings' -Query $query -Profile $Profile
        return $raw | ForEach-Object { ConvertTo-VcFinding $_ $AppGuid }
    }
}

function Get-VcFindingsSummary {
    <#
    .SYNOPSIS
        Returns a per-severity count of open findings for every application in the org.
    .PARAMETER PolicyNonCompliantOnly
        Limit to applications that are DID_NOT_PASS.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcFindingsSummary
        Get-VcFindingsSummary -PolicyNonCompliantOnly
        Get-VcFindingsSummary -Export .\findings-summary.csv
    #>
    [CmdletBinding()]
    param(
        [switch]$PolicyNonCompliantOnly,
        [string]$Export,
        [string]$Profile = $script:VcCurrentProfile
    )

    $getParams = @{ Profile = $Profile }
    if ($PolicyNonCompliantOnly) { $getParams['PolicyCompliance'] = 'DID_NOT_PASS' }

    $apps    = Get-VcApplications @getParams
    $results = [System.Collections.Generic.List[object]]::new()
    $i       = 0

    foreach ($app in $apps) {
        $i++
        Write-Progress -Activity 'Summarising findings' `
                       -Status "$($app.Name) ($i / $($apps.Count))" `
                       -PercentComplete ([int](($i / $apps.Count) * 100))
        try {
            $findings = Get-VcFindings -AppGuid $app.Guid -FlawStatus OPEN -Profile $Profile

            $bySeverity = $findings | Group-Object Severity
            $counts     = @{}
            foreach ($g in $bySeverity) { $counts[[int]$g.Name] = $g.Count }

            $results.Add([pscustomobject]@{
                AppName          = $app.Name
                AppGuid          = $app.Guid
                PolicyCompliance = $app.PolicyCompliance
                VeryHigh         = $(if ($null -ne $counts[5]) { $counts[5] } else { 0 })
                High             = $(if ($null -ne $counts[4]) { $counts[4] } else { 0 })
                Medium           = $(if ($null -ne $counts[3]) { $counts[3] } else { 0 })
                Low              = $(if ($null -ne $counts[2]) { $counts[2] } else { 0 })
                VeryLow          = $(if ($null -ne $counts[1]) { $counts[1] } else { 0 })
                Informational    = $(if ($null -ne $counts[0]) { $counts[0] } else { 0 })
                Total            = $findings.Count
            })
        } catch {
            Write-Warning "Could not fetch findings for '$($app.Name)': $_"
        }
    }

    Write-Progress -Activity 'Summarising findings' -Completed

    $output = $results.ToArray()
    if ($Export) {
        $output | Export-Csv -Path $Export -NoTypeInformation
        Write-Host "Findings summary exported to '$Export'."
    }

    return $output
}

# Converts a raw findings API object to a flat PSCustomObject.
function ConvertTo-VcFinding {
    param($Raw, [string]$AppGuid)
    [pscustomobject]@{
        IssueId            = $Raw.issue_id
        AppGuid            = $AppGuid
        ScanType           = $Raw.scan_type
        Severity           = $Raw.severity
        SeverityLabel      = $script:VcSeverityLabels[[int]$Raw.severity]
        CweId              = $Raw.cwe_id
        CweName            = $Raw.finding_details.cwe.name
        Category           = $Raw.finding_details.finding_category.name
        CategoryId         = $Raw.finding_details.finding_category.id
        FileName           = $Raw.finding_details.file_name
        LineNumber         = $Raw.finding_details.file_line_number
        AttackVector       = $Raw.finding_details.attack_vector
        FlawStatus         = $Raw.finding_status.status
        MitigationStatus   = $Raw.finding_status.mitigation_review_status
        FirstFoundDate     = $Raw.finding_status.first_found_date
        LastSeenDate       = $Raw.finding_status.last_seen_date
        DaysOpen           = $(if ($Raw.finding_status.first_found_date) {
                                 [int]([DateTimeOffset]::UtcNow -
                                 [DateTimeOffset]::Parse($Raw.finding_status.first_found_date)).TotalDays
                             } else { $null })
        Annotations        = $Raw.annotations
        _Raw               = $Raw
    }
}
