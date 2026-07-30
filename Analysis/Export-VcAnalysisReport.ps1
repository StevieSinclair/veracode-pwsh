function Export-VcAnalysisReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML analysis report for an application covering
        severity breakdown, CWE heat map, category distribution, module hotspots,
        mitigation pipeline, and scan diff vs the previous build.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER OutputPath
        Destination HTML file path.
    .PARAMETER BuildId
        Specific build ID. Defaults to the most recent completed scan.
    .PARAMETER ScanType
        Limit analysis to one scan type.
    .PARAMETER IncludeSections
        Which sections to include. Default: all.
        Valid values: Severity, CWE, Category, Module, Mitigation, Diff
    .EXAMPLE
        Export-VcAnalysisReport -AppGuid 'abc' -OutputPath .\report.html
        Export-VcAnalysisReport -AppGuid 'abc' -OutputPath .\static.html -ScanType STATIC
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$BuildId,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateSet('Severity','CWE','Category','Module','Mitigation','Diff')]
        [string[]]$IncludeSections = @('Severity','CWE','Category','Module','Mitigation','Diff'),

        [string]$Profile = $script:VcCurrentProfile
    )

    Write-Host "Building analysis report for '$AppGuid'..."

    $app = Get-VcApplication -Guid $AppGuid -Profile $Profile

    # Collect finding data once and reuse
    $findParams = @{ AppGuid = $AppGuid; FlawStatus = 'OPEN'; Profile = $Profile }
    if ($ScanType) { $findParams['ScanType'] = $ScanType }
    $findings = @(Get-VcFindings @findParams)

    $sections = [System.Collections.Generic.List[string]]::new()

    # ── Severity Breakdown ─────────────────────────────────────────────────────
    if ('Severity' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'Severity breakdown...' -PercentComplete 10
        $sevRows = $findings | Group-Object Severity | ForEach-Object {
            $sev = [int]$_.Name
            [pscustomobject]@{ Severity=$sev; Label=$script:VcSeverityLabels[$sev]; Count=$_.Count }
        } | Sort-Object Severity -Descending

        $total    = $findings.Count
        $sevHtml  = $sevRows | ForEach-Object {
            $pct   = if ($total -gt 0) { [Math]::Round($_.Count / $total * 100, 1) } else { 0 }
            $cls   = switch ($_.Severity) { 5{'sev5'}; 4{'sev4'}; 3{'sev3'}; 2{'sev2'}; default{'sev0'} }
            $bar   = if ($total -gt 0 -and $_.Count -gt 0) {
                        "<div class='bar $cls' style='width:$([Math]::Max(2,[int]($_.Count/$total*200)))px'></div>"
                     } else { '' }
            "<tr><td class='$cls'>$($_.Label)</td><td>$($_.Count)</td><td>$pct%</td><td>$bar</td></tr>"
        }
        $sections.Add("<h2>Severity Breakdown</h2><table>
<thead><tr><th>Severity</th><th>Count</th><th>%</th><th>Distribution</th></tr></thead>
<tbody>$($sevHtml -join '')</tbody></table>")
    }

    # ── CWE Heat Map ───────────────────────────────────────────────────────────
    if ('CWE' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'CWE heat map...' -PercentComplete 25
        $cweRows = $findings | Group-Object CweId | Sort-Object Count -Descending | Select-Object -First 20
        $rank    = 0
        $cweHtml = $cweRows | ForEach-Object {
            $rank++
            $s    = $_.Group[0]
            $vhC  = @($_.Group | Where-Object { $_.Severity -eq 5 }).Count
            $hC   = @($_.Group | Where-Object { $_.Severity -eq 4 }).Count
            $cls  = if ($vhC -gt 0) { 'sev5' } elseif ($hC -gt 0) { 'sev4' } else { '' }
            "<tr class='$cls'><td>$rank</td><td>CWE-$($s.CweId)</td><td>$($s.CweName)</td><td>$($_.Count)</td><td>$vhC</td><td>$hC</td></tr>"
        }
        $sections.Add("<h2>CWE Heat Map (Top 20)</h2><table>
<thead><tr><th>#</th><th>CWE</th><th>Name</th><th>Count</th><th>VH</th><th>H</th></tr></thead>
<tbody>$($cweHtml -join '')</tbody></table>")
    }

    # ── Category Breakdown ─────────────────────────────────────────────────────
    if ('Category' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'Category breakdown...' -PercentComplete 40
        $catRows = $findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            $g   = $_.Group
            $vhC = @($g | Where-Object { $_.Severity -eq 5 }).Count
            $hC  = @($g | Where-Object { $_.Severity -eq 4 }).Count
            $cls = if ($vhC -gt 0) { 'sev5' } elseif ($hC -gt 0) { 'sev4' } else { '' }
            "<tr class='$cls'><td>$($_.Name)</td><td>$($_.Count)</td><td>$vhC</td><td>$hC</td><td>$(@($g|Where-Object{$_.Severity-eq 3}).Count)</td></tr>"
        }
        $sections.Add("<h2>Category Breakdown</h2><table>
<thead><tr><th>Category</th><th>Total</th><th>VH</th><th>H</th><th>M</th></tr></thead>
<tbody>$($catRows -join '')</tbody></table>")
    }

    # ── Module Hotspots ────────────────────────────────────────────────────────
    if ('Module' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'Module hotspots...' -PercentComplete 55
        $modRows = $findings | Group-Object { ($_.FileName -split '[/\\]')[0] } |
                   Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
            $g   = $_.Group
            $vhC = @($g | Where-Object { $_.Severity -eq 5 }).Count
            $hC  = @($g | Where-Object { $_.Severity -eq 4 }).Count
            $cls = if (($vhC+$hC) -gt 5) { 'sev4' } else { '' }
            "<tr class='$cls'><td>$($_.Name)</td><td>$($_.Count)</td><td>$vhC</td><td>$hC</td></tr>"
        }
        $sections.Add("<h2>Module Hotspots</h2><table>
<thead><tr><th>Module</th><th>Total</th><th>VH</th><th>H</th></tr></thead>
<tbody>$($modRows -join '')</tbody></table>")
    }

    # ── Mitigation Pipeline ────────────────────────────────────────────────────
    if ('Mitigation' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'Mitigation status...' -PercentComplete 70
        $annotated = @(Get-VcFindings -AppGuid $AppGuid -IncludeAnnotations -FlawStatus OPEN -Profile $Profile)
        $mitRows   = $annotated | Group-Object MitigationStatus | Sort-Object Name | ForEach-Object {
            $cls = switch ($_.Name) {
                'NONE'     { '' }
                'PROPOSED' { 'sev3' }
                'APPROVED' { 'pass' }
                'ACCEPTED' { 'pass' }
                'REJECTED' { 'sev4' }
                default    { '' }
            }
            "<tr class='$cls'><td>$($_.Name)</td><td>$($_.Count)</td></tr>"
        }
        $sections.Add("<h2>Mitigation Pipeline</h2><table>
<thead><tr><th>Status</th><th>Count</th></tr></thead>
<tbody>$($mitRows -join '')</tbody></table>")
    }

    # ── Scan Diff ─────────────────────────────────────────────────────────────
    if ('Diff' -in $IncludeSections) {
        Write-Progress -Activity 'Building report' -Status 'Scan diff...' -PercentComplete 85
        try {
            $diff = Compare-VcScans -AppGuid $AppGuid -Profile $Profile
            $diffSummary = "<p><span class='sev5'>+$($diff.NewCount) new</span>&nbsp;&nbsp;
                            <span class='pass'>-$($diff.FixedCount) fixed</span>&nbsp;&nbsp;
                            <span>=$($diff.PersistedCount) persisted</span></p>"
            $newHtml = ($diff.NewFindings | Sort-Object Severity -Descending | Select-Object -First 10 | ForEach-Object {
                $cls = if ($_.Severity -ge 4) { 'sev4' } else { 'sev3' }
                "<tr class='$cls'><td>$($_.IssueId)</td><td>$($_.SeverityLabel)</td><td>CWE-$($_.CweId)</td><td>$($_.CweName)</td><td>$($_.FileName):$($_.LineNumber)</td></tr>"
            }) -join ''
            $diffSection = "<h2>Scan Diff (vs previous build)</h2>$diffSummary"
            if ($newHtml) {
                $diffSection += "<h3>New Findings (top 10)</h3><table>
<thead><tr><th>ID</th><th>Severity</th><th>CWE</th><th>Name</th><th>Location</th></tr></thead>
<tbody>$newHtml</tbody></table>"
            }
            $sections.Add($diffSection)
        } catch {
            $sections.Add("<h2>Scan Diff</h2><p class='warn'>Could not compute diff: $_</p>")
        }
    }

    Write-Progress -Activity 'Building report' -Status 'Writing HTML...' -PercentComplete 95

    $generatedAt = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $title       = "Analysis Report — $($app.Name)"
    $sectionsHtml = $sections -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$title</title>
<style>
  body { font-family: Arial, sans-serif; font-size: 13px; margin: 20px; background: #1a1a2e; color: #e0e0e0; }
  h1   { color: #4fc3f7; border-bottom: 1px solid #333; padding-bottom: 8px; }
  h2   { color: #81d4fa; margin-top: 30px; }
  h3   { color: #b0bec5; }
  .meta { color: #888; font-size: 0.85em; margin-bottom: 20px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background: #16213e; border-radius: 6px; overflow: hidden; }
  th   { background: #0f3460; color: #81d4fa; padding: 8px 12px; text-align: left; font-size: 12px; }
  td   { padding: 6px 12px; border-bottom: 1px solid #1e2a4a; }
  tr:hover td { background: #1e3a5f; }
  .sev5 { color: #ff5252; }
  .sev4 { color: #ff9800; }
  .sev3 { color: #ffeb3b; }
  .sev2 { color: #4fc3f7; }
  .sev0 { color: #888; }
  .pass { color: #69f0ae; }
  .warn { color: #ff9800; font-style: italic; }
  tr.sev5 td { background: #2d0a0a; }
  tr.sev4 td { background: #2d1a00; }
  tr.sev3 td { background: #2d2800; }
  tr.pass td { background: #0a2d0a; }
  .bar { height: 12px; border-radius: 2px; display: inline-block; }
  .bar.sev5 { background: #ff5252; }
  .bar.sev4 { background: #ff9800; }
  .bar.sev3 { background: #ffeb3b; }
  .bar.sev2 { background: #4fc3f7; }
  .bar.sev0 { background: #555; }
  .footer { margin-top: 30px; color: #555; font-size: 0.8em; }
</style>
</head>
<body>
<h1>$title</h1>
<div class="meta">
  Application GUID: $AppGuid &nbsp;|&nbsp;
  Policy: $($app.PolicyName ?? 'None') &nbsp;|&nbsp;
  Compliance: $($app.PolicyCompliance ?? 'N/A') &nbsp;|&nbsp;
  Total open findings: $($findings.Count)$(if ($ScanType) { " [$ScanType]" })
</div>
$sectionsHtml
<div class="footer">Generated $generatedAt</div>
</body>
</html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
    Write-Progress -Activity 'Building report' -Completed
    Write-Host "Analysis report written to '$OutputPath' ($($findings.Count) findings, $($sections.Count) section(s))."
}
