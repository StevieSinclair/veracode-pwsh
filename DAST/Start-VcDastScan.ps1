function Start-VcDastScan {
    <#
    .SYNOPSIS
        Triggers an existing DAST analysis to run immediately by setting its start time to now.
    .PARAMETER AnalysisId
        The DAST analysis ID to start. Accepts pipeline input from Get-VcDastScans.
    .EXAMPLE
        Start-VcDastScan -AnalysisId 'abc-123'
        Get-VcDastScans -Status SCHEDULED | Start-VcDastScan -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$AnalysisId,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if (-not $PSCmdlet.ShouldProcess($AnalysisId, 'Start DAST scan')) { return }

        Write-Verbose "Fetching current analysis config for '$AnalysisId'..."
        $current = Invoke-VcApi -Method GET -Path "/was/configservice/v1/analyses/$AnalysisId" -Profile $Profile

        # Merge: set schedule start_time to now to trigger immediate run
        $nowUtc = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        if (-not $current.schedule) {
            $current | Add-Member -NotePropertyName 'schedule' -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $durVal = if ($current.schedule.PSObject.Properties['duration']) { $current.schedule.duration } else { 'P1D' }
        $current.schedule | Add-Member -NotePropertyName 'start_time' -NotePropertyValue $nowUtc  -Force
        $current.schedule | Add-Member -NotePropertyName 'duration'   -NotePropertyValue $durVal  -Force

        $result = Invoke-VcApi -Method PUT -Path "/was/configservice/v1/analyses/$AnalysisId" -Body $current -Profile $Profile
        Write-Host "DAST scan '$AnalysisId' started (scheduled: $nowUtc)."
        return ConvertTo-VcDastScan $result
    }
}
