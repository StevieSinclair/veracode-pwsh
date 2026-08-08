function Get-VcScaLicenses {
    <#
    .SYNOPSIS
        License risk report for SCA findings — groups open-source libraries by license
        risk level for legal and compliance review.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER RiskLevel
        Filter to a specific risk level: HIGH, MEDIUM, LOW, UNRECOGNIZED.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcScaLicenses -AppGuid 'abc'
        Get-VcScaLicenses -AppGuid 'abc' -RiskLevel HIGH
        Get-VcScaLicenses -AppGuid 'abc' -Export .\licenses.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [ValidateSet('HIGH','MEDIUM','LOW','UNRECOGNIZED')]
        [string]$RiskLevel,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $findings = @(Get-VcScaFindings -AppGuid $AppGuid -Profile $Profile)

        # Unique library + version + license entries
        $uniqueLibs = $findings | Group-Object Library,Version,LicenseName | ForEach-Object {
            $s = $_.Group[0]
            [pscustomobject]@{
                Library     = $s.Library
                Version     = $s.Version
                License     = $(if ($null -ne $s.LicenseName) { $s.LicenseName } else { 'Unknown' })
                RiskLevel   = $(if ($null -ne $s.LicenseRisk)  { $s.LicenseRisk }  else { 'UNRECOGNIZED' })
                FindingCount = $_.Count
                MaxCvss     = [Math]::Round(($_.Group | Measure-Object MaxCvss -Maximum).Maximum, 1)
            }
        }

        if ($RiskLevel) {
            $uniqueLibs = @($uniqueLibs | Where-Object { $_.RiskLevel -eq $RiskLevel })
        }

        $byRisk = $uniqueLibs | Group-Object RiskLevel | Sort-Object {
            switch ($_.Name) { 'HIGH'{0}; 'MEDIUM'{1}; 'LOW'{2}; default{3} }
        }

        Write-Host ""
        Write-Host "  SCA License Risk Report — $($uniqueLibs.Count) distinct library/version entries" -ForegroundColor Cyan

        foreach ($rg in $byRisk) {
            $color = switch ($rg.Name) { 'HIGH'{'Red'}; 'MEDIUM'{'Yellow'}; 'LOW'{'Green'}; default{'DarkGray'} }
            Write-Host ""
            Write-Host ("  ── $($rg.Name) RISK ($($rg.Count)) ─────────────────────────────────") -ForegroundColor $color
            foreach ($r in ($rg.Group | Sort-Object Library)) {
                $name = if ($r.Library.Length -gt 35) { $r.Library.Substring(0,32) + '...' } else { $r.Library }
                $ver = if ($null -ne $r.Version) { $r.Version } else { '?' }
                Write-Host ("    {0,-35}  {1,-10}  {2,-30}  CVSS:{3}" -f $name, $ver, $r.License, $r.MaxCvss) -ForegroundColor $color
            }
        }
        Write-Host ""

        if ($Export) {
            $uniqueLibs | Sort-Object RiskLevel,Library | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $uniqueLibs | Sort-Object RiskLevel,Library
    }
}
