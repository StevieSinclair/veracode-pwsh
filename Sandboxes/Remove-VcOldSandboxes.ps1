function Remove-VcOldSandboxes {
    <#
    .SYNOPSIS
        Deletes sandboxes for an application that have not been modified within a threshold.
        Sandboxes whose latest scan is RESULTS_READY are preserved by default.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER OlderThanDays
        Remove sandboxes not modified within this many days (default 90).
    .PARAMETER KeepResultsReady
        When set, skip sandboxes whose latest scan has completed results (default: true).
    .PARAMETER Force
        Skip the per-sandbox confirmation prompt.
    .EXAMPLE
        Remove-VcOldSandboxes -AppGuid 'abc' -OlderThanDays 60 -WhatIf
        Remove-VcOldSandboxes -AppGuid 'abc' -OlderThanDays 30 -Force
        Get-VcApplications | Remove-VcOldSandboxes -OlderThanDays 90 -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [int]$OlderThanDays = 90,

        [switch]$KeepResultsReady = $true,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if ($Force) { $ConfirmPreference = 'None' }

        $cutoff    = [DateTime]::UtcNow.AddDays(-$OlderThanDays)
        $sandboxes = Get-VcSandboxes -AppGuid $AppGuid -Profile $Profile

        $candidates = $sandboxes | Where-Object {
            $modDate = if ($_.LastModifiedDate) {
                try { [DateTime]::Parse($_.LastModifiedDate) } catch { [DateTime]::MaxValue }
            } else { [DateTime]::MinValue }
            $modDate -lt $cutoff
        }

        if (-not $candidates -or $candidates.Count -eq 0) {
            Write-Host "No sandboxes older than $OlderThanDays days found for app '$AppGuid'."
            return
        }

        $deleted = 0
        $skipped = 0

        foreach ($sb in $candidates) {
            if ($KeepResultsReady) {
                try {
                    $scans  = Get-VcScans -AppGuid $AppGuid -SandboxGuid $sb.SandboxGuid -Profile $Profile
                    $latest = $scans | Sort-Object SubmittedDate -Descending | Select-Object -First 1
                    if ($latest -and $latest.Status -eq 'RESULTS_READY') {
                        Write-Verbose "Skipping '$($sb.Name)' — latest scan is RESULTS_READY."
                        $skipped++
                        continue
                    }
                } catch {
                    Write-Verbose "Could not fetch scans for sandbox '$($sb.Name)': $_"
                }
            }

            $label = "'$($sb.Name)' (last modified: $($sb.LastModifiedDate))"
            if (-not $PSCmdlet.ShouldProcess($label, 'Delete sandbox')) {
                $skipped++
                continue
            }

            try {
                Remove-VcSandbox -AppGuid $AppGuid -SandboxGuid $sb.SandboxGuid -Force -Profile $Profile
                Write-Host "  [DELETED] $label"
                $deleted++
            } catch {
                Write-Warning "Failed to delete $label`: $_"
                $skipped++
            }
        }

        Write-Host "Sandbox cleanup for '$AppGuid': $deleted deleted, $skipped skipped."
    }
}
