function Get-VcCweBreakdown {
    <#
    .SYNOPSIS
        Heat map of the top N CWEs by finding count for an application.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Top
        Number of CWEs to show (default 20).
    .PARAMETER ScanType
        Limit to one scan type: STATIC, DYNAMIC, MANUAL, SCA.
    .PARAMETER FlawStatus
        OPEN (default) or CLOSED.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcCweBreakdown -AppGuid 'abc'
        Get-VcCweBreakdown -AppGuid 'abc' -Top 10 -ScanType STATIC -Export .\cwes.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [int]$Top = 20,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus = 'OPEN',

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $params = @{ AppGuid = $AppGuid; FlawStatus = $FlawStatus; Profile = $Profile }
        if ($ScanType) { $params['ScanType'] = $ScanType }

        $findings = @(Get-VcFindings @params)
        $total    = $findings.Count

        $grouped = $findings | Group-Object CweId | Sort-Object Count -Descending | Select-Object -First $Top

        $rank = 0
        $rows = $grouped | ForEach-Object {
            $rank++
            $sample = $_.Group[0]
            $pct    = if ($total -gt 0) { [Math]::Round($_.Count / $total * 100, 1) } else { 0 }

            # Severity distribution inline (VH H M L VL I)
            $vhC = @($_.Group | Where-Object { $_.Severity -eq 5 }).Count
            $hC  = @($_.Group | Where-Object { $_.Severity -eq 4 }).Count
            $mC  = @($_.Group | Where-Object { $_.Severity -eq 3 }).Count
            $lC  = @($_.Group | Where-Object { $_.Severity -le 2 }).Count

            [pscustomobject]@{
                Rank         = $rank
                CweId        = $sample.CweId
                CweName      = $sample.CweName
                Count        = $_.Count
                PctTotal     = $pct
                VeryHigh     = $vhC
                High         = $hC
                Medium       = $mC
                LowAndBelow  = $lC
            }
        }

        Write-Host ""
        Write-Host "  CWE Heat Map — Top $Top of $($grouped.Count) CWEs ($total finding(s) total)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 75) -ForegroundColor DarkGray
        Write-Host ("  {0,4}  {1,6}  {2,-38}  {3,5}  {4,6}  VH H M L" -f '#','CWE','Name','Count','%') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $name = if ($r.CweName.Length -gt 37) { $r.CweName.Substring(0,34) + '...' } else { $r.CweName }
            $color = if ($r.VeryHigh -gt 0) { 'Red' } elseif ($r.High -gt 0) { 'Yellow' } else { 'White' }
            Write-Host ("  {0,4}  {1,6}  {2,-38}  {3,5}  {4,5}%  {5} {6} {7} {8}" -f `
                $r.Rank, $r.CweId, $name, $r.Count, $r.PctTotal,
                $r.VeryHigh, $r.High, $r.Medium, $r.LowAndBelow) -ForegroundColor $color
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
