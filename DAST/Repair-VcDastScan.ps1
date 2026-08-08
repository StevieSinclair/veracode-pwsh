function Repair-VcDastScan {
    <#
    .SYNOPSIS
        Detects and stops stuck DAST analyses across the org or a specific analysis.
    .DESCRIPTION
        A DAST scan is considered stuck when it has been in a non-progressing state
        (RUNNING, QUEUED, AGENT_SCANNING, PENDING) for longer than -ThresholdHours.
        Lists all matching analyses, displays them, and stops each one after confirmation.
    .PARAMETER AnalysisId
        Stop only this specific analysis ID. Mutually exclusive with -All.
    .PARAMETER All
        Check all DAST analyses org-wide.
    .PARAMETER ThresholdHours
        Minimum age in hours before an active analysis is considered stuck (default 8).
    .PARAMETER Force
        Stop without individual confirmation prompts.
    .EXAMPLE
        Repair-VcDastScan -All
        Repair-VcDastScan -All -ThresholdHours 12 -Force
        Repair-VcDastScan -AnalysisId 'abc-123' -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [string]$AnalysisId,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All,

        [int]$ThresholdHours = 8,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $scan = Get-VcDastScan -AnalysisId $AnalysisId -Profile $Profile
        $stuckScans = @($scan | Where-Object { $_.Status -in $script:VcDastStuckStates })
    } else {
        Write-Verbose 'Fetching all DAST analyses to check for stuck scans...'
        $stuckScans = @(Get-VcDastScans -StuckOnly -ThresholdHours $ThresholdHours -Profile $Profile)
    }

    if ($stuckScans.Count -eq 0) {
        Write-Host "No stuck DAST analyses found (threshold: ${ThresholdHours}h)." -ForegroundColor Green
        return
    }

    Write-Host "`nFound $($stuckScans.Count) stuck DAST analysis/analyses:`n" -ForegroundColor Yellow
    $stuckScans | Format-Table -AutoSize -Property AnalysisId, Name, Status, AgeHours, ScanUrl

    $stopped = 0
    $errored = 0

    foreach ($scan in $stuckScans) {
        $label = if ($scan.Name) { "'$($scan.Name)' ($($scan.AnalysisId))" } else { $scan.AnalysisId }
        $label += " — $($scan.Status), age $($scan.AgeHours)h"

        if (-not $PSCmdlet.ShouldProcess($label, 'Stop stuck DAST analysis')) { continue }

        try {
            Stop-VcDastScan -AnalysisId $scan.AnalysisId `
                            -Name $scan.Name `
                            -Force `
                            -Profile $Profile `
                            -Confirm:$false
            Write-Host "  [STOPPED] $label" -ForegroundColor Green
            $stopped++
        } catch {
            Write-Warning "  [FAILED]  $label : $_"
            $errored++
        }
    }

    Write-Host "`nResult: $stopped stopped, $errored failed." -ForegroundColor $(
        if ($errored -gt 0) { 'Yellow' } else { 'Green' }
    )
}
