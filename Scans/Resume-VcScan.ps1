function Resume-VcScan {
    <#
    .SYNOPSIS
        Deletes the latest (blocking) scan for an application or sandbox so a new one can be submitted.
    .DESCRIPTION
        When a CI/CD pipeline is blocked because a scan already exists, this command removes
        the latest scan after confirmation. If the scan has already completed (RESULTS_READY),
        deletion is blocked unless -Force is used — completed results should not be destroyed
        carelessly.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER SandboxGuid
        When specified, targets the latest scan in this sandbox.
    .PARAMETER Force
        Allow deletion of a scan in RESULTS_READY (completed) state.
    .EXAMPLE
        Resume-VcScan -AppGuid 'abc'
        Resume-VcScan -AppGuid 'abc' -SandboxGuid 'sb1'
        Get-VcApplications -Name 'MyApp' | Resume-VcScan -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$SandboxGuid,
        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        Write-Verbose "Fetching scans for application $AppGuid$(if ($SandboxGuid) { ", sandbox $SandboxGuid" })..."

        $scans = Get-VcScans -AppGuid $AppGuid -SandboxGuid $SandboxGuid -Profile $Profile

        if (-not $scans -or $scans.Count -eq 0) {
            Write-Host "No scans found for application $AppGuid — nothing to remove."
            return
        }

        $latest = $scans | Sort-Object SubmittedDate -Descending | Select-Object -First 1

        Write-Host "Latest scan:  ID=$($latest.ScanId)  Status=$($latest.Status)  Age=$($latest.AgeHours)h"

        if ($latest.Status -eq 'RESULTS_READY' -and -not $Force) {
            Write-Warning "Latest scan is RESULTS_READY (completed results exist). Use -Force to delete anyway."
            return
        }

        $label = "Scan $($latest.ScanId) (status: $($latest.Status))"
        if (-not $PSCmdlet.ShouldProcess($label, "Delete latest scan to unblock pipeline")) { return }

        Remove-VcScan -AppGuid $AppGuid `
                      -ScanId $latest.ScanId `
                      -SandboxGuid $SandboxGuid `
                      -Status $latest.Status `
                      -Force `
                      -Profile $Profile `
                      -Confirm:$false

        Write-Host "Pipeline unblocked — submit a new scan now." -ForegroundColor Green
    }
}
