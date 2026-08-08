function Get-VcScaUpgrades {
    <#
    .SYNOPSIS
        Generates an actionable upgrade checklist for SCA findings where a safe version
        is known. Groups by library so each library appears once with all CVEs resolved.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER MinCvss
        Only include libraries with at least one finding at or above this CVSS score.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcScaUpgrades -AppGuid 'abc'
        Get-VcScaUpgrades -AppGuid 'abc' -MinCvss 7.0 -Export .\upgrades.csv
        Get-VcApplications | Get-VcScaUpgrades | Format-Table
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

        $findings = @(Get-VcScaFindings @scaParams | Where-Object { $_.HasFix })

        if ($findings.Count -eq 0) {
            Write-Host "  No actionable upgrades found (no SCA findings with a known fix version)."
            return @()
        }

        $rows = $findings | Group-Object Library,Version | Sort-Object { ($_.Group | Measure-Object MaxCvss -Maximum).Maximum } -Descending | ForEach-Object {
            $g       = $_.Group
            $sample  = $g[0]
            $allCves = @($g | ForEach-Object { $_.CveIds } | Where-Object { $_ } | Sort-Object -Unique)
            $maxCvss = [Math]::Round(($g | Measure-Object MaxCvss -Maximum).Maximum, 1)

            # Pick the recommended (highest) fix version
            $fixVersions = @($g | Where-Object { $_.FixedInVersion } | Select-Object -ExpandProperty FixedInVersion -Unique)
            $fixVersion  = $fixVersions | Sort-Object -Descending | Select-Object -First 1

            [pscustomobject]@{
                Library        = $sample.Library
                CurrentVersion = $sample.Version
                SafeVersion    = $fixVersion
                CvesResolved   = $allCves.Count
                CveList        = ($allCves -join ', ')
                MaxCvss        = $maxCvss
                FindingsFixed  = $g.Count
                Priority       = $(if ($maxCvss -ge 9.0) { 'CRITICAL' } elseif ($maxCvss -ge 7.0) { 'HIGH' } elseif ($maxCvss -ge 4.0) { 'MEDIUM' } else { 'LOW' })
            }
        }

        Write-Host ""
        Write-Host "  SCA Upgrade Checklist — $($rows.Count) libraries with available fixes" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 90) -ForegroundColor DarkGray
        Write-Host ("  {0,-35}  {1,-12}  {2,-12}  {3,5}  {4,6}  {5,8}" -f `
            'Library','Current','Safe Version','CVEs','MaxCVSS','Priority') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $name  = if ($r.Library.Length -gt 34) { $r.Library.Substring(0,31) + '...' } else { $r.Library }
            $color = switch ($r.Priority) { 'CRITICAL'{'Red'}; 'HIGH'{'Yellow'}; 'MEDIUM'{'Cyan'}; default{'DarkGray'} }
            $curVer  = if ($null -ne $r.CurrentVersion) { $r.CurrentVersion } else { '?' }
            $safeVer = if ($null -ne $r.SafeVersion)    { $r.SafeVersion }    else { '?' }
            Write-Host ("  {0,-35}  {1,-12}  {2,-12}  {3,5}  {4,6}  {5,8}" -f `
                $name, $curVer, $safeVer, $r.CvesResolved, $r.MaxCvss, $r.Priority) -ForegroundColor $color
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
