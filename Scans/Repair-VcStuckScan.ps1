function Repair-VcStuckScan {
    <#
    .SYNOPSIS
        Detects and removes stuck scans across one application or the entire org.
    .DESCRIPTION
        A scan is considered stuck when it has been in a non-progressing state
        (INCOMPLETE, PRESCAN_SUBMITTED, SUBMITTED_TO_ENGINE, SCAN_IN_PROGRESS, SCAN_SUBMITTED)
        for longer than -ThresholdHours. The function lists all matching scans, displays them,
        and prompts for confirmation before deleting each one.
    .PARAMETER AppGuid
        Target a single application. Mutually exclusive with -All.
    .PARAMETER All
        Scan every application in the org. May take a while for large portfolios.
    .PARAMETER ThresholdHours
        Minimum age in hours before a non-progressing scan is considered stuck (default 4).
    .PARAMETER Force
        Delete without individual confirmation prompts.
    .EXAMPLE
        Repair-VcStuckScan -AppGuid 'abc' -ThresholdHours 6
        Repair-VcStuckScan -All -ThresholdHours 8 -WhatIf
        Repair-VcStuckScan -All -Force
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [string]$AppGuid,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [int]$ThresholdHours = 4,
        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    # Build the list of (appGuid, appName) pairs to inspect
    $targets = if ($All) {
        Write-Verbose 'Fetching all applications for org-wide stuck-scan check...'
        Get-VcApplications -Profile $Profile |
            Select-Object @{ N = 'AppGuid'; E = { $_.Guid } }, @{ N = 'AppName'; E = { $_.Name } }
    } else {
        @([pscustomobject]@{ AppGuid = $AppGuid; AppName = $AppGuid })
    }

    # Collect stuck scans across all targets
    $stuckScans = [System.Collections.Generic.List[object]]::new()
    $i = 0

    foreach ($target in $targets) {
        $i++
        if ($All) {
            Write-Progress -Activity 'Scanning for stuck scans' `
                           -Status "$($target.AppName) ($i / $($targets.Count))" `
                           -PercentComplete ([int](($i / $targets.Count) * 100))
        }
        try {
            Get-VcScans -AppGuid $target.AppGuid -Profile $Profile -ErrorAction Stop |
                Where-Object { $_.IsStuck -and $_.AgeHours -ge $ThresholdHours } |
                ForEach-Object {
                    $_ | Add-Member -NotePropertyName AppName -NotePropertyValue $target.AppName -Force
                    $stuckScans.Add($_)
                }
        } catch {
            Write-Warning "Could not fetch scans for '$($target.AppName)': $_"
        }
    }

    if ($All) { Write-Progress -Activity 'Scanning for stuck scans' -Completed }

    if ($stuckScans.Count -eq 0) {
        Write-Host "No stuck scans found (threshold: ${ThresholdHours}h)." -ForegroundColor Green
        return
    }

    # Display the stuck scans before acting
    Write-Host "`nFound $($stuckScans.Count) stuck scan(s):`n" -ForegroundColor Yellow
    $stuckScans | Format-Table -AutoSize -Property AppName, ScanId, Status, AgeHours, SandboxGuid

    $deleted = 0
    $errored = 0

    foreach ($scan in $stuckScans) {
        $label = "Scan $($scan.ScanId) ($($scan.AppName), $($scan.Status), age $($scan.AgeHours)h)"

        if (-not $PSCmdlet.ShouldProcess($label, 'Delete stuck scan')) { continue }

        try {
            Remove-VcScan -AppGuid $scan.AppGuid `
                          -ScanId $scan.ScanId `
                          -SandboxGuid $scan.SandboxGuid `
                          -Status $scan.Status `
                          -Force:$Force `
                          -Profile $Profile `
                          -Confirm:$false
            Write-Host "  [DELETED] $label" -ForegroundColor Green
            $deleted++
        } catch {
            Write-Warning "  [FAILED]  $label : $_"
            $errored++
        }
    }

    Write-Host "`nResult: $deleted deleted, $errored failed." -ForegroundColor $(
        if ($errored -gt 0) { 'Yellow' } else { 'Green' }
    )
}
