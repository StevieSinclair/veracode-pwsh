function Export-VcReport {
    <#
    .SYNOPSIS
        Generates a comprehensive org-wide snapshot report combining application compliance,
        finding severity counts, and scan health status.
    .PARAMETER OutputPath
        Destination file path. Extension determines format when -Format is omitted:
        .html → HTML, everything else → CSV.
    .PARAMETER Format
        Output format: CSV or HTML. Overrides extension detection.
    .PARAMETER PolicyNonCompliantOnly
        Include only applications that failed their policy.
    .PARAMETER MinSeverity
        Only count findings at or above this severity (0–5).
    .PARAMETER Title
        HTML report title. Defaults to 'Veracode Security Report'.
    .EXAMPLE
        Export-VcReport -OutputPath .\report.html
        Export-VcReport -OutputPath .\report.csv -PolicyNonCompliantOnly
        Export-VcReport -OutputPath .\report.html -MinSeverity 4
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('CSV','HTML')]
        [string]$Format,

        [switch]$PolicyNonCompliantOnly,

        [ValidateRange(0,5)]
        [int]$MinSeverity = 0,

        [string]$Title = 'Veracode Security Report',

        [string]$Profile = $script:VcCurrentProfile
    )

    # Determine output format
    if (-not $Format) {
        $Format = if ($OutputPath -match '\.html?$') { 'HTML' } else { 'CSV' }
    }

    Write-Host "Gathering application list..." -NoNewline
    $appParams = @{ Profile = $Profile }
    if ($PolicyNonCompliantOnly) { $appParams['PolicyCompliance'] = 'DID_NOT_PASS' }
    $apps = Get-VcApplications @appParams
    Write-Host " $($apps.Count) apps found."

    $results = [System.Collections.Generic.List[object]]::new()
    $i = 0

    foreach ($app in $apps) {
        $i++
        Write-Progress -Activity 'Building report' `
                       -Status "$($app.Name) ($i / $($apps.Count))" `
                       -PercentComplete ([int](($i / $apps.Count) * 100))

        $findingCounts = @{ VeryHigh=0; High=0; Medium=0; Low=0; VeryLow=0; Informational=0; Total=0 }
        $lastScanState = 'Unknown'
        $stuckScanCount = 0

        try {
            $findingParams = @{ AppGuid = $app.Guid; FlawStatus = 'OPEN'; Profile = $Profile }
            if ($MinSeverity -gt 0) { $findingParams['MinSeverity'] = $MinSeverity }
            $findings = Get-VcFindings @findingParams

            $bySev = $findings | Group-Object Severity
            foreach ($g in $bySev) {
                $label = $script:VcSeverityLabels[[int]$g.Name]
                $key   = $label -replace ' ',''
                if ($findingCounts.ContainsKey($key)) { $findingCounts[$key] = $g.Count }
            }
            $findingCounts['Total'] = $findings.Count
        } catch {
            Write-Warning "Could not fetch findings for '$($app.Name)': $_"
        }

        try {
            $scans = Get-VcScans -AppGuid $app.Guid -Profile $Profile
            if ($scans -and $scans.Count -gt 0) {
                $latest = $scans | Sort-Object SubmittedDate -Descending | Select-Object -First 1
                $lastScanState = $latest.Status
                $stuckScanCount = @($scans | Where-Object { $_.IsStuck }).Count
            }
        } catch {
            Write-Warning "Could not fetch scans for '$($app.Name)': $_"
        }

        $results.Add([pscustomobject]@{
            AppName          = $app.Name
            AppGuid          = $app.Guid
            PolicyName       = $app.PolicyName
            PolicyCompliance = $app.PolicyCompliance
            LastScanDate     = $app.LastScanDate
            LastScanStatus   = $lastScanState
            StuckScans       = $stuckScanCount
            VeryHigh         = $findingCounts['VeryHigh']
            High             = $findingCounts['High']
            Medium           = $findingCounts['Medium']
            Low              = $findingCounts['Low']
            VeryLow          = $findingCounts['VeryLow']
            Informational    = $findingCounts['Informational']
            TotalFindings    = $findingCounts['Total']
            GeneratedUtc     = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
        })
    }

    Write-Progress -Activity 'Building report' -Completed

    $data = $results.ToArray()

    if ($Format -eq 'HTML') {
        $html = New-VcHtmlReport -Title $Title -Data $data
        Set-Content -Path $OutputPath -Value $html -Encoding UTF8
    } else {
        $data | Export-Csv -Path $OutputPath -NoTypeInformation
    }

    Write-Host "Report exported to '$OutputPath' ($($data.Count) applications, format: $Format)."
    return $data
}

function New-VcHtmlReport {
    param(
        [string]$Title,
        [object[]]$Data
    )

    $generatedAt = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $totalApps   = $Data.Count
    $failedApps  = @($Data | Where-Object { $_.PolicyCompliance -eq 'DID_NOT_PASS' }).Count
    $stuckTotal  = ($Data | Measure-Object StuckScans -Sum).Sum
    $critTotal   = ($Data | Measure-Object VeryHigh -Sum).Sum + ($Data | Measure-Object High -Sum).Sum

    $rows = $Data | ForEach-Object {
        $compClass = switch ($_.PolicyCompliance) {
            'PASSED'       { 'pass' }
            'DID_NOT_PASS' { 'fail' }
            default        { '' }
        }
        $stuckClass = if ($_.StuckScans -gt 0) { 'warn' } else { '' }
        $critClass  = if ($_.VeryHigh -gt 0) { 'fail' } elseif ($_.High -gt 0) { 'warn' } else { '' }

        "<tr>
          <td>$($_.AppName)</td>
          <td class='$compClass'>$($_.PolicyCompliance)</td>
          <td>$($_.PolicyName)</td>
          <td>$($_.LastScanDate)</td>
          <td>$($_.LastScanStatus)</td>
          <td class='$stuckClass'>$($_.StuckScans)</td>
          <td class='$critClass'>$($_.VeryHigh)</td>
          <td class='$critClass'>$($_.High)</td>
          <td>$($_.Medium)</td>
          <td>$($_.Low)</td>
          <td>$($_.TotalFindings)</td>
        </tr>"
    }

    $rowsHtml = $rows -join "`n"

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$Title</title>
<style>
  body { font-family: Arial, sans-serif; font-size: 13px; margin: 20px; background: #f5f5f5; }
  h1   { color: #2c3e50; }
  .summary { display: flex; gap: 20px; margin-bottom: 20px; }
  .card    { background: white; border-radius: 6px; padding: 15px 25px; box-shadow: 0 1px 3px rgba(0,0,0,.15); min-width: 120px; }
  .card .num { font-size: 2em; font-weight: bold; color: #2c3e50; }
  .card .lbl { color: #666; font-size: 0.85em; }
  table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,.15); border-radius: 6px; overflow: hidden; }
  th    { background: #2c3e50; color: white; padding: 8px 10px; text-align: left; font-size: 12px; }
  td    { padding: 7px 10px; border-bottom: 1px solid #eee; }
  tr:last-child td { border-bottom: none; }
  tr:hover td      { background: #f0f4f8; }
  .pass { color: #27ae60; font-weight: bold; }
  .fail { color: #e74c3c; font-weight: bold; }
  .warn { color: #e67e22; font-weight: bold; }
  .footer { margin-top: 12px; color: #999; font-size: 0.8em; }
</style>
</head>
<body>
<h1>$Title</h1>
<div class="summary">
  <div class="card"><div class="num">$totalApps</div><div class="lbl">Applications</div></div>
  <div class="card"><div class="num fail">$failedApps</div><div class="lbl">Policy Failed</div></div>
  <div class="card"><div class="num warn">$stuckTotal</div><div class="lbl">Stuck Scans</div></div>
  <div class="card"><div class="num fail">$critTotal</div><div class="lbl">High+ Findings</div></div>
</div>
<table>
<thead>
  <tr>
    <th>Application</th><th>Compliance</th><th>Policy</th>
    <th>Last Scan</th><th>Scan Status</th><th>Stuck</th>
    <th>Very High</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th>
  </tr>
</thead>
<tbody>
$rowsHtml
</tbody>
</table>
<div class="footer">Generated $generatedAt</div>
</body>
</html>
"@
}
