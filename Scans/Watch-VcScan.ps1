function Watch-VcScan {
    <#
    .SYNOPSIS
        Polls an application's current scan status and prints a live status line until
        the scan reaches a terminal state (RESULTS_READY, FAILED, INCOMPLETE).
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER SandboxGuid
        When provided, watches a sandbox scan instead of the policy scan.
    .PARAMETER IntervalSeconds
        How often to poll (default 30 seconds).
    .PARAMETER Bell
        Play a console bell when the scan completes or fails.
    .PARAMETER TimeoutMinutes
        Stop watching after this many minutes regardless of scan state (default 480 = 8 hours).
    .EXAMPLE
        Watch-VcScan -AppGuid 'abc'
        Watch-VcScan -AppGuid 'abc' -SandboxGuid 'sb1' -IntervalSeconds 60
        Get-VcApplications -Name 'MyApp' | Watch-VcScan -Bell
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$SandboxGuid,

        [int]$IntervalSeconds = 30,

        [switch]$Bell,

        [int]$TimeoutMinutes = 480,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $terminalStates = @('RESULTS_READY', 'FAILED', 'INCOMPLETE', 'NO_MODULES_DEFINED',
                            'PRESCAN_FAILED', 'CANCELLED')

        $stopAt  = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
        $started = [DateTime]::UtcNow

        Write-Host "Watching scan for app '$AppGuid'$(if ($SandboxGuid) { " (sandbox $SandboxGuid)" })..."
        Write-Host "Press Ctrl+C to stop watching.`n"

        $lastStatus = $null

        while ([DateTime]::UtcNow -lt $stopAt) {
            try {
                $scanParams = @{ AppGuid = $AppGuid; Profile = $Profile }
                if ($SandboxGuid) { $scanParams['SandboxGuid'] = $SandboxGuid }

                $scans = Get-VcScans @scanParams
                $latest = $scans | Sort-Object SubmittedDate -Descending | Select-Object -First 1

                if (-not $latest) {
                    Write-Host "  $([DateTime]::UtcNow.ToString('HH:mm:ss'))  No scans found — waiting..."
                } else {
                    $elapsed = [int]([DateTime]::UtcNow - $started).TotalMinutes
                    $line = "  $([DateTime]::UtcNow.ToString('HH:mm:ss'))  Scan $($latest.ScanId)" +
                            "  Status: $($latest.Status.PadRight(25))" +
                            "  Age: $($latest.AgeHours)h  Elapsed: ${elapsed}m"

                    if ($latest.Status -ne $lastStatus) {
                        Write-Host $line
                        $lastStatus = $latest.Status
                    } else {
                        # Overwrite the current line in place
                        Write-Host "`r$line" -NoNewline
                    }

                    if ($latest.Status -in $terminalStates) {
                        Write-Host ""
                        if ($latest.Status -eq 'RESULTS_READY') {
                            Write-Host "`nScan complete: RESULTS_READY  (total elapsed: ${elapsed}m)" -ForegroundColor Green
                        } else {
                            Write-Host "`nScan ended with status: $($latest.Status)  (total elapsed: ${elapsed}m)" -ForegroundColor Yellow
                        }
                        if ($Bell) { [Console]::Beep(800, 400) }
                        return $latest
                    }
                }
            } catch {
                Write-Warning "Poll error: $_"
            }

            Start-Sleep -Seconds $IntervalSeconds
        }

        Write-Warning "Watcher timed out after $TimeoutMinutes minutes."
    }
}
