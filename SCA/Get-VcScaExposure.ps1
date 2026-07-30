function Get-VcScaExposure {
    <#
    .SYNOPSIS
        Identifies vulnerable open-source libraries present across multiple applications
        (blast-radius analysis). Libraries with high CVSS scores appearing in many apps
        represent the highest organisational risk.
    .PARAMETER AppGuids
        Specific app GUIDs to scan. If omitted, all applications are scanned.
    .PARAMETER MinAppCount
        Only return libraries found in at least this many apps (default 2).
    .PARAMETER MinCvss
        Only include libraries with at least one finding at or above this CVSS score.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcScaExposure
        Get-VcScaExposure -MinCvss 7.0 -MinAppCount 3 -Export .\exposure.csv
    #>
    [CmdletBinding()]
    param(
        [string[]]$AppGuids,

        [int]$MinAppCount = 2,

        [double]$MinCvss = 0,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    if (-not $AppGuids) {
        Write-Host "  Fetching application list..." -NoNewline
        $apps    = Get-VcApplications -Profile $Profile
        $AppGuids = @($apps | Select-Object -ExpandProperty Guid)
        Write-Host " $($AppGuids.Count) apps."
    } else {
        $apps = $AppGuids | ForEach-Object { [pscustomobject]@{ Guid = $_; Name = $_ } }
    }

    $appNameMap = @{}
    foreach ($a in $apps) { $appNameMap[$a.Guid] = $a.Name }

    # Library → @{ appGuids=[]; findings=[] }
    $libraryMap = @{}

    $i = 0
    foreach ($guid in $AppGuids) {
        $i++
        Write-Progress -Activity 'Scanning for SCA exposure' `
                       -Status "$(if ($null -ne $appNameMap[$guid]) { $appNameMap[$guid] } else { $guid }) ($i / $($AppGuids.Count))" `
                       -PercentComplete ([int](($i / $AppGuids.Count) * 100))
        try {
            $scaParams = @{ AppGuid = $guid; Profile = $Profile }
            if ($MinCvss -gt 0) { $scaParams['MinCvss'] = $MinCvss }
            $findings  = @(Get-VcScaFindings @scaParams)

            foreach ($f in $findings) {
                $key = "$($f.Library)|$($f.Version)"
                if (-not $libraryMap.ContainsKey($key)) {
                    $libraryMap[$key] = @{
                        Library  = $f.Library
                        Version  = $f.Version
                        AppGuids = [System.Collections.Generic.HashSet[string]]::new()
                        Findings = [System.Collections.Generic.List[object]]::new()
                    }
                }
                $libraryMap[$key]['AppGuids'].Add($guid) | Out-Null
                $libraryMap[$key]['Findings'].Add($f)
            }
        } catch {
            Write-Warning "  Could not fetch SCA findings for '$(if ($null -ne $appNameMap[$guid]) { $appNameMap[$guid] } else { $guid })': $_"
        }
    }

    Write-Progress -Activity 'Scanning for SCA exposure' -Completed

    $rows = $libraryMap.Values | Where-Object { $_.AppGuids.Count -ge $MinAppCount } | ForEach-Object {
        $allCves  = @($_.Findings | ForEach-Object { $_.CveIds } | Where-Object { $_ } | Sort-Object -Unique)
        $maxCvss  = [Math]::Round(($_.Findings | Measure-Object MaxCvss -Maximum).Maximum, 1)
        $appNames = @($_.AppGuids | ForEach-Object { if ($null -ne $appNameMap[$_]) { $appNameMap[$_] } else { $_ } })

        [pscustomobject]@{
            Library     = $_.Library
            Version     = $_.Version
            AppCount    = $_.AppGuids.Count
            Apps        = ($appNames -join '; ')
            CveCount    = $allCves.Count
            CveList     = ($allCves -join ', ')
            MaxCvss     = $maxCvss
            IsCritical  = ($maxCvss -ge 7.0 -and $_.AppGuids.Count -ge 3)
        }
    } | Sort-Object { $_.AppCount * $_.MaxCvss } -Descending

    if ($rows.Count -eq 0) {
        Write-Host "  No libraries found in $MinAppCount+ applications$(if ($MinCvss -gt 0) { " with CVSS >= $MinCvss" })."
        return @()
    }

    $critical = @($rows | Where-Object { $_.IsCritical })

    Write-Host ""
    Write-Host "  SCA Org-Wide Exposure — $($rows.Count) libraries in $MinAppCount+ apps" -ForegroundColor Cyan
    if ($critical.Count -gt 0) {
        Write-Host "  CRITICAL: $($critical.Count) libraries with CVSS >= 7.0 in 3+ applications" -ForegroundColor Red
    }
    Write-Host ("  " + "─" * 85) -ForegroundColor DarkGray
    Write-Host ("  {0,-35}  {1,-10}  {2,4}  {3,5}  {4,5}  {5}" -f 'Library','Version','Apps','CVEs','MaxCVSS','Critical') -ForegroundColor DarkCyan

    foreach ($r in $rows) {
        $name  = if ($r.Library.Length -gt 34) { $r.Library.Substring(0,31) + '...' } else { $r.Library }
        $color = if ($r.IsCritical) { 'Red' } elseif ($r.MaxCvss -ge 7.0) { 'Yellow' } else { 'White' }
        $flag  = if ($r.IsCritical) { '⚠ CRITICAL' } else { '' }
        $ver = if ($null -ne $r.Version) { $r.Version } else { '?' }
        Write-Host ("  {0,-35}  {1,-10}  {2,4}  {3,5}  {4,5}  {5}" -f `
            $name, $ver, $r.AppCount, $r.CveCount, $r.MaxCvss, $flag) -ForegroundColor $color
        Write-Host ("    Apps: $($r.Apps)") -ForegroundColor DarkGray
    }
    Write-Host ""

    if ($Export) {
        $rows | Export-Csv -Path $Export -NoTypeInformation
        Write-Host "  Exported to '$Export'."
    }

    return $rows
}
