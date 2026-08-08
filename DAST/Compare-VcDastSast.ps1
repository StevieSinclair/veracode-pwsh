function Compare-VcDastSast {
    <#
    .SYNOPSIS
        Compares SAST and DAST findings for the same application, highlighting CWE overlap.
    .DESCRIPTION
        Fetches SAST (STATIC) and DAST (DYNAMIC) findings, groups each by CWE, then
        produces an overlap table. CWEs found by both scanners are flagged as higher-priority
        remediation targets — a confirmed finding from two independent methods.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Export
        Path to write the overlap table as a CSV.
    .EXAMPLE
        Compare-VcDastSast -AppGuid 'abc-123'
        Get-VcApplications | Compare-VcDastSast -Export .\overlap.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        Write-Verbose "Fetching SAST findings for '$AppGuid'..."
        $sastFindings = @(Get-VcFindings -AppGuid $AppGuid -ScanType STATIC -Profile $Profile -ErrorAction SilentlyContinue)

        Write-Verbose "Fetching DAST findings for '$AppGuid'..."
        $dastFindings = @(Get-VcDastFindings -AppGuid $AppGuid -Profile $Profile -ErrorAction SilentlyContinue)

        if ($sastFindings.Count -eq 0 -and $dastFindings.Count -eq 0) {
            Write-Host "  No SAST or DAST findings for app '$AppGuid'." -ForegroundColor Yellow
            return
        }

        # Group by CWE
        $sastByCwe = @{}
        foreach ($f in $sastFindings) {
            $key = [string]$f.CweId
            if (-not $sastByCwe.ContainsKey($key)) { $sastByCwe[$key] = [System.Collections.Generic.List[object]]::new() }
            $sastByCwe[$key].Add($f)
        }

        $dastByCwe = @{}
        foreach ($f in $dastFindings) {
            $key = [string]$f.CweId
            if (-not $dastByCwe.ContainsKey($key)) { $dastByCwe[$key] = [System.Collections.Generic.List[object]]::new() }
            $dastByCwe[$key].Add($f)
        }

        # Union of all CWE IDs
        $allCweIds = @($sastByCwe.Keys) + @($dastByCwe.Keys) | Select-Object -Unique | Sort-Object

        $overlapCount  = 0
        $sastOnlyCount = 0
        $dastOnlyCount = 0

        $rows = foreach ($cweId in $allCweIds) {
            $sGroup = if ($sastByCwe.ContainsKey($cweId)) { $sastByCwe[$cweId] } else { @() }
            $dGroup = if ($dastByCwe.ContainsKey($cweId)) { $dastByCwe[$cweId] } else { @() }

            $sample  = if ($sGroup.Count -gt 0) { $sGroup[0] } else { $dGroup[0] }
            $overlap = $sGroup.Count -gt 0 -and $dGroup.Count -gt 0

            if ($overlap)              { $overlapCount++ }
            elseif ($sGroup.Count -gt 0) { $sastOnlyCount++ }
            else                         { $dastOnlyCount++ }

            [pscustomobject]@{
                CweId     = $cweId
                CweName   = $sample.CweName
                SastCount = $sGroup.Count
                DastCount = $dGroup.Count
                Overlap   = $overlap
            }
        }

        $rows = @($rows | Sort-Object { -[int]$_.Overlap }, { -($_.SastCount + $_.DastCount) })

        Write-Host ""
        Write-Host "  DAST / SAST CWE Comparison — App: $AppGuid" -ForegroundColor Cyan
        Write-Host ("  " + "═" * 70) -ForegroundColor DarkCyan
        Write-Host ("  {0,-8}  {1,-38}  {2,5}  {3,5}  {4}" -f `
            'CWE', 'Name', 'SAST', 'DAST', 'Overlap') -ForegroundColor DarkGray
        Write-Host ("  " + "─" * 70) -ForegroundColor DarkGray

        foreach ($row in $rows) {
            $name  = if ($row.CweName -and $row.CweName.Length -gt 37) { $row.CweName.Substring(0,34) + '...' } else { $row.CweName }
            $color = if ($row.Overlap) { 'Red' } elseif ($row.SastCount -gt 0) { 'Yellow' } else { 'Cyan' }
            $flag  = if ($row.Overlap) { '  *** CONFIRMED ***' } else { '' }
            Write-Host ("  {0,-8}  {1,-38}  {2,5}  {3,5}  {4}{5}" -f `
                "CWE-$($row.CweId)", $name, $row.SastCount, $row.DastCount, $row.Overlap, $flag) -ForegroundColor $color
        }

        Write-Host ""
        Write-Host ("  Summary: {0} SAST-only CWEs | {1} DAST-only CWEs | {2} confirmed overlap" -f `
            $sastOnlyCount, $dastOnlyCount, $overlapCount) `
            -ForegroundColor $(if ($overlapCount -gt 0) { 'Red' } else { 'Green' })
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Overlap report exported to '$Export'."
        }

        return [pscustomobject]@{
            AppGuid      = $AppGuid
            SastTotal    = $sastFindings.Count
            DastTotal    = $dastFindings.Count
            OverlapCount = $overlapCount
            Rows         = $rows
        }
    }
}
