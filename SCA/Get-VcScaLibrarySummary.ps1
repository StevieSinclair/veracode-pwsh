function Get-VcScaLibrarySummary {
    <#
    .SYNOPSIS
        Groups SCA findings by library + version, showing all CVEs, max CVSS score,
        and whether a safe upgrade version is known.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER MinCvss
        Include only libraries with at least one finding at or above this CVSS score.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcScaLibrarySummary -AppGuid 'abc'
        Get-VcScaLibrarySummary -AppGuid 'abc' -MinCvss 7.0 -Export .\libs.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [double]$MinCvss = 0,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $scaParams = @{ AppGuid = $AppGuid; Profile = $Profile }
        if ($MinCvss -gt 0) { $scaParams['MinCvss'] = $MinCvss }
        $findings = @(Get-VcScaFindings @scaParams)

        if ($findings.Count -eq 0) {
            Write-Host "  No SCA findings found for app '$AppGuid'."
            return @()
        }

        # Group by Library + Version
        $rows = $findings | Group-Object Library,Version | Sort-Object { ($_.Group | Measure-Object MaxCvss -Maximum).Maximum } -Descending | ForEach-Object {
            $g        = $_.Group
            $sample   = $g[0]
            $allCves  = @($g | ForEach-Object { $_.CveIds } | Where-Object { $_ } | Sort-Object -Unique)
            $maxCvss  = ($g | Measure-Object MaxCvss -Maximum).Maximum
            $fixVer   = @($g | Where-Object { $_.FixedInVersion } | Select-Object -ExpandProperty FixedInVersion -Unique) -join ', '

            [pscustomobject]@{
                Library         = $sample.Library
                Version         = $sample.Version
                FindingCount    = $g.Count
                CveCount        = $allCves.Count
                CveList         = ($allCves -join ', ')
                MaxCvss         = [Math]::Round([double]$maxCvss, 1)
                HighestSeverity = $script:VcSeverityLabels[($g | Measure-Object Severity -Maximum).Maximum]
                HasFix          = ($g | Where-Object { $_.HasFix }).Count -gt 0
                FixedInVersion  = $fixVer
            }
        }

        Write-Host ""
        Write-Host "  SCA Library Summary — $($rows.Count) distinct libraries ($($findings.Count) findings)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 90) -ForegroundColor DarkGray
        Write-Host ("  {0,-35}  {1,-10}  {2,5}  {3,6}  {4,6}  {5,6}  {6,8}  {7}" -f `
            'Library','Version','CVEs','MaxCVSS','Sev','Findings','HasFix','Fix Version') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $name  = if ($r.Library.Length -gt 34) { $r.Library.Substring(0,31) + '...' } else { $r.Library }
            $color = if ($r.MaxCvss -ge 9.0) { 'Red' } elseif ($r.MaxCvss -ge 7.0) { 'Yellow' } elseif ($r.MaxCvss -ge 4.0) { 'White' } else { 'DarkGray' }
            $fix   = if ($r.HasFix) { 'YES' } else { 'no' }
            $ver = if ($null -ne $r.Version) { $r.Version } else { 'unknown' }
            Write-Host ("  {0,-35}  {1,-10}  {2,5}  {3,6}  {4,6}  {5,8}  {6,6}  {7}" -f `
                $name, $ver, $r.CveCount, $r.MaxCvss, $r.HighestSeverity, $r.FindingCount, $fix, $r.FixedInVersion) -ForegroundColor $color
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
