# DAST analysis states that indicate a stuck/stalled scan
$script:VcDastStuckStates = @('RUNNING','QUEUED','AGENT_SCANNING','PENDING')

function Get-VcDastScans {
    <#
    .SYNOPSIS
        Lists Dynamic Analysis (DAST) scans from the Web Application Scanning service.
    .PARAMETER Status
        Filter by scan status: RUNNING, FINISHED, FAILED, SCHEDULED, QUEUED, CANCELLED.
    .PARAMETER AppGuid
        Filter to a specific application GUID.
    .PARAMETER StuckOnly
        Return only scans in an active state older than -ThresholdHours.
    .PARAMETER ThresholdHours
        Hours beyond which an active scan is considered stuck (default 8).
    .EXAMPLE
        Get-VcDastScans
        Get-VcDastScans -Status RUNNING
        Get-VcDastScans -StuckOnly -ThresholdHours 12
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('RUNNING','FINISHED','FAILED','SCHEDULED','QUEUED','CANCELLED','AGENT_SCANNING','PENDING')]
        [string]$Status,

        [string]$AppGuid,

        [switch]$StuckOnly,

        [int]$ThresholdHours = 8,

        [string]$Profile = $script:VcCurrentProfile
    )

    $query = @{}
    if ($Status)  { $query['status']  = $Status }
    if ($AppGuid) { $query['app_id']  = $AppGuid }

    $raw   = Invoke-VcPagedApi -Path '/was/configservice/v1/analyses' -EmbeddedKey 'analyses' -Query $query -Profile $Profile
    $scans = @($raw | ForEach-Object { ConvertTo-VcDastScan $_ })

    if ($StuckOnly) {
        $scans = @($scans | Where-Object { $_.Status -in $script:VcDastStuckStates -and $_.AgeHours -gt $ThresholdHours })
    }

    return $scans
}

function Get-VcDastScan {
    <#
    .SYNOPSIS
        Returns full configuration and status for a single DAST analysis.
    .PARAMETER AnalysisId
        The DAST analysis ID (from Get-VcDastScans).
    .EXAMPLE
        Get-VcDastScan -AnalysisId 'abc-123'
        Get-VcDastScans | Select-Object -First 1 | Get-VcDastScan
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$AnalysisId,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $raw = Invoke-VcApi -Method GET -Path "/was/configservice/v1/analyses/$AnalysisId" -Profile $Profile
        return ConvertTo-VcDastScan $raw
    }
}

function ConvertTo-VcDastScan {
    param($Raw)

    $ageHours = -1
    if ($Raw.start_time) {
        try {
            $ageHours = [int]([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($Raw.start_time)).TotalHours
        } catch { }
    }

    $isStuck = $Raw.status -in $script:VcDastStuckStates -and $ageHours -gt 0

    [pscustomobject]@{
        AnalysisId    = $Raw.analysis_id
        Name          = $Raw.analysis_name
        Status        = $Raw.status
        ScanType      = $(if ($null -ne $Raw.analysis_type) { $Raw.analysis_type } else { 'DYNAMIC' })
        AppGuid       = $Raw.app_id
        ScanUrl       = $(if ($null -ne $Raw.scan_url) { $Raw.scan_url } else { $Raw.scans | Select-Object -First 1 -ExpandProperty scan_url })
        StartTime     = $Raw.start_time
        FinishTime    = $Raw.finish_time
        ScheduledTime = $(if ($null -ne $Raw.schedule) { $Raw.schedule.start_time } else { $null })
        AgeHours      = $ageHours
        IsStuck       = $isStuck
        FindingCount  = $(if ($null -ne $Raw.finding_count) { $Raw.finding_count } else { 0 })
        _Raw          = $Raw
    }
}
