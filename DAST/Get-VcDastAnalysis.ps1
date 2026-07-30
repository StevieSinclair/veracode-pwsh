function Get-VcDastAnalysis {
    <#
    .SYNOPSIS
        Comprehensive analysis of DAST findings for an application: severity breakdown,
        CWE distribution, URL/endpoint heat map, and attack vector distribution.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Top
        Number of top endpoints / CWEs / vectors to show (default 10).
    .PARAMETER Export
        Path to write the combined analysis as a CSV (endpoint heat map rows).
    .EXAMPLE
        Get-VcDastAnalysis -AppGuid 'abc'
        Get-VcDastAnalysis -AppGuid 'abc' -Top 20 -Export .\dast-analysis.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [int]$Top = 10,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $findings = @(Get-VcDastFindings -AppGuid $AppGuid -Profile $Profile)
        $total    = $findings.Count

        if ($total -eq 0) {
            Write-Host "  No DAST findings found for app '$AppGuid'."
            return
        }

        Write-Host ""
        Write-Host "  DAST Analysis — $total finding(s)" -ForegroundColor Cyan
        Write-Host ("  " + "═" * 62) -ForegroundColor DarkCyan

        # ── Severity Breakdown ────────────────────────────────────────────
        Write-Host ""
        Write-Host "  Severity Breakdown:" -ForegroundColor DarkCyan
        $sevCounts = @{0=0;1=0;2=0;3=0;4=0;5=0}
        foreach ($f in $findings) { $sevCounts[[int]$f.Severity]++ }
        $sevRows = 5..0 | ForEach-Object {
            $sev   = $_
            $count = $sevCounts[$sev]
            $pct   = [Math]::Round($count / $total * 100, 1)
            $bar   = '█' * [int]($count / $total * 30)
            $color = switch ($sev) { 5{'Red'}; 4{'Yellow'}; 3{'DarkYellow'}; 2{'Cyan'}; default{'DarkGray'} }
            Write-Host ("    {0,-12} {1,4}  {2,5}%  {3}" -f $script:VcSeverityLabels[$sev], $count, $pct, $bar) -ForegroundColor $color
            [pscustomobject]@{ Severity=$sev; Label=$script:VcSeverityLabels[$sev]; Count=$count; PctTotal=$pct }
        }

        # ── CWE Distribution ──────────────────────────────────────────────
        Write-Host ""
        Write-Host "  Top CWEs:" -ForegroundColor DarkCyan
        $cweRows = $findings | Group-Object CweId | Sort-Object Count -Descending | Select-Object -First $Top
        $rank = 0
        foreach ($g in $cweRows) {
            $rank++
            $sample = $g.Group[0]
            Write-Host ("    {0,2}. CWE-{1,-6} {2,-40} {3,4}" -f `
                $rank, $sample.CweId, $sample.CweName, $g.Count)
        }

        # ── URL / Endpoint Heat Map ────────────────────────────────────────
        Write-Host ""
        Write-Host "  Endpoint Heat Map (top $Top paths):" -ForegroundColor DarkCyan
        Write-Host ("    {0,-50}  {1,5}  {2,2}  {3,2}  {4,2}" -f 'Path','Count','VH','H','M') -ForegroundColor DarkGray

        $endpointRows = @($findings | Group-Object Path | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
            $vhC = 0; $hC = 0; $mC = 0
            foreach ($f in $_.Group) {
                if     ($f.Severity -eq 5) { $vhC++ }
                elseif ($f.Severity -eq 4) { $hC++ }
                elseif ($f.Severity -eq 3) { $mC++ }
            }
            $color = if ($vhC -gt 0) { 'Red' } elseif ($hC -gt 0) { 'Yellow' } else { 'White' }
            $path  = if ($_.Name -and $_.Name.Length -gt 49) { $_.Name.Substring(0,46) + '...' } else { $_.Name }
            Write-Host ("    {0,-50}  {1,5}  {2,2}  {3,2}  {4,2}" -f $path, $_.Count, $vhC, $hC, $mC) -ForegroundColor $color
            [pscustomobject]@{ Path=$_.Name; Count=$_.Count; VeryHigh=$vhC; High=$hC; Medium=$mC }
        })

        # ── Attack Vector Distribution ─────────────────────────────────────
        Write-Host ""
        Write-Host "  Attack Vector Distribution:" -ForegroundColor DarkCyan
        $vectorRows = $findings | Where-Object { $_.AttackVector } | Group-Object AttackVector | Sort-Object Count -Descending
        foreach ($v in $vectorRows) {
            $pct = [Math]::Round($v.Count / $total * 100, 1)
            Write-Host ("    {0,-30}  {1,4}  ({2}%)" -f $v.Name, $v.Count, $pct)
        }
        Write-Host ""

        $result = [pscustomobject]@{
            AppGuid      = $AppGuid
            TotalFindings = $total
            SeverityBreakdown = $sevRows
            EndpointHeatMap   = $endpointRows
        }

        if ($Export) {
            $endpointRows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Endpoint heat map exported to '$Export'."
        }

        return $result
    }
}
