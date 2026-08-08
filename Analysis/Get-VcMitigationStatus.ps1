function Get-VcMitigationStatus {
    <#
    .SYNOPSIS
        Breaks down findings by mitigation review status and flags long-pending proposals.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER PendingOnly
        Show only findings with PROPOSED mitigations awaiting review.
    .PARAMETER StaleDays
        Flag PROPOSED mitigations that have been pending longer than this many days (default 30).
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcMitigationStatus -AppGuid 'abc'
        Get-VcMitigationStatus -AppGuid 'abc' -PendingOnly
        Get-VcMitigationStatus -AppGuid 'abc' -StaleDays 14 -Export .\mit.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [switch]$PendingOnly,

        [int]$StaleDays = 30,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $findings = @(Get-VcFindings -AppGuid $AppGuid -IncludeAnnotations -FlawStatus OPEN -Profile $Profile)

        if ($PendingOnly) {
            $findings = @($findings | Where-Object { $_.MitigationStatus -eq 'PROPOSED' })
        }

        $rows = $findings | ForEach-Object {
            $staleFlag = $false
            if ($_.MitigationStatus -eq 'PROPOSED' -and $_.DaysOpen -ge $StaleDays) {
                $staleFlag = $true
            }
            [pscustomobject]@{
                IssueId           = $_.IssueId
                CweId             = $_.CweId
                CweName           = $_.CweName
                Severity          = $_.Severity
                SeverityLabel     = $_.SeverityLabel
                MitigationStatus  = $_.MitigationStatus
                DaysOpen          = $_.DaysOpen
                IsStaleProposal   = $staleFlag
                FileName          = $_.FileName
                LineNumber        = $_.LineNumber
            }
        }

        # Summary by status
        $summary = $rows | Group-Object MitigationStatus | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ MitigationStatus = $_.Name; Count = $_.Count }
        }

        Write-Host ""
        Write-Host "  Mitigation Status — $($findings.Count) finding(s)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 50) -ForegroundColor DarkGray

        foreach ($s in $summary) {
            $color = switch ($s.MitigationStatus) {
                'NONE'     { 'DarkGray' }
                'PROPOSED' { 'Yellow' }
                'APPROVED' { 'Green' }
                'ACCEPTED' { 'Green' }
                'REJECTED' { 'Red' }
                default    { 'White' }
            }
            Write-Host ("  {0,-15} {1,4} finding(s)" -f $s.MitigationStatus, $s.Count) -ForegroundColor $color
        }

        $stale = @($rows | Where-Object { $_.IsStaleProposal })
        if ($stale.Count -gt 0) {
            Write-Host ""
            Write-Host "  ⚠  $($stale.Count) PROPOSED mitigation(s) pending ≥ $StaleDays days (review overdue)" -ForegroundColor Red
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
