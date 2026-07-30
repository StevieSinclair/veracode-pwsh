function Get-VcFindingTrend {
    <#
    .SYNOPSIS
        Shows finding counts by severity across the last N completed builds, enabling
        trend analysis over time.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER LastNBuilds
        Number of recent builds to include (default 10).
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcFindingTrend -AppGuid 'abc'
        Get-VcFindingTrend -AppGuid 'abc' -LastNBuilds 5 -Export .\trend.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [int]$LastNBuilds = 10,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $app = Get-VcApplication -Guid $AppGuid -Profile $Profile
        if (-not $app.LegacyId) {
            throw "Application '$AppGuid' does not have a legacy app ID — build list requires the XML API."
        }

        # Fetch build list
        Write-Verbose "Fetching build list for app $($app.LegacyId)..."
        $buildXml  = Invoke-VcXmlApi -Path '/api/5.0/getbuildlist.do' `
                                     -Params @{ app_id = $app.LegacyId } -Profile $Profile

        $builds = @($buildXml.SelectNodes('//build') | ForEach-Object {
            [pscustomobject]@{
                BuildId = $_.GetAttribute('build_id')
                Version = $_.GetAttribute('version')
                Date    = $_.GetAttribute('policy_compliance_status') # date may be in a sibling element
            }
        })

        if ($builds.Count -eq 0) {
            Write-Warning "No completed builds found for application '$($app.Name)'."
            return
        }

        # Take the last N builds
        $selected = $builds | Select-Object -Last $LastNBuilds

        $rows = [System.Collections.Generic.List[object]]::new()
        $i    = 0

        foreach ($build in $selected) {
            $i++
            Write-Progress -Activity 'Fetching trend data' `
                           -Status "Build $($build.BuildId) ($i / $($selected.Count))" `
                           -PercentComplete ([int](($i / $selected.Count) * 100))
            try {
                $summaryXml = Invoke-VcXmlApi -Path '/api/5.0/summaryreport.do' `
                                              -Params @{ build_id = $build.BuildId } -Profile $Profile

                # Parse severity counts from summary report XML
                $_node = $summaryXml.SelectSingleNode('//severity[@level="5"]')
                $vhCount = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }
                $_node = $summaryXml.SelectSingleNode('//severity[@level="4"]')
                $hCount  = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }
                $_node = $summaryXml.SelectSingleNode('//severity[@level="3"]')
                $mCount  = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }
                $_node = $summaryXml.SelectSingleNode('//severity[@level="2"]')
                $lCount  = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }
                $_node = $summaryXml.SelectSingleNode('//severity[@level="1"]')
                $vlCount = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }
                $_node = $summaryXml.SelectSingleNode('//severity[@level="0"]')
                $iCount  = if ($null -ne $_node) { [int]$_node.GetAttribute('count') } else { 0 }

                $rows.Add([pscustomobject]@{
                    BuildId       = $build.BuildId
                    Version       = $build.Version
                    VeryHigh      = $vhCount
                    High          = $hCount
                    Medium        = $mCount
                    Low           = $lCount
                    VeryLow       = $vlCount
                    Informational = $iCount
                    Total         = $vhCount + $hCount + $mCount + $lCount + $vlCount + $iCount
                })
            } catch {
                Write-Warning "Could not fetch summary for build $($build.BuildId): $_"
            }
        }

        Write-Progress -Activity 'Fetching trend data' -Completed

        $data = $rows.ToArray()

        Write-Host ""
        Write-Host "  Finding Trend — $($app.Name)  (last $($data.Count) builds)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 70) -ForegroundColor DarkGray
        Write-Host ("  {0,-12}  {1,-20}  {2,3}  {3,3}  {4,3}  {5,3}  {6,5}" -f `
            'Build ID','Version','VH','H','M','L','Total') -ForegroundColor DarkCyan

        foreach ($r in $data) {
            $color = if ($r.VeryHigh -gt 0) { 'Red' } elseif ($r.High -gt 0) { 'Yellow' } else { 'White' }
            $ver   = if ($r.Version.Length -gt 19) { $r.Version.Substring(0,16) + '...' } else { $r.Version }
            Write-Host ("  {0,-12}  {1,-20}  {2,3}  {3,3}  {4,3}  {5,3}  {6,5}" -f `
                $r.BuildId, $ver, $r.VeryHigh, $r.High, $r.Medium, $r.Low, $r.Total) -ForegroundColor $color
        }

        # ASCII sparkline for VH+H across builds
        if ($data.Count -gt 1) {
            $maxCrit = ($data | Measure-Object { $_.VeryHigh + $_.High } -Maximum).Maximum
            if ($maxCrit -gt 0) {
                Write-Host ""
                Write-Host "  High+VH trend sparkline:" -ForegroundColor DarkCyan
                $sparkHeight = 4
                for ($row = $sparkHeight; $row -ge 1; $row--) {
                    $line = "  "
                    foreach ($r in $data) {
                        $val    = $r.VeryHigh + $r.High
                        $scaled = if ($maxCrit -gt 0) { [int]($val / $maxCrit * $sparkHeight) } else { 0 }
                        $line  += if ($scaled -ge $row) { '▓ ' } else { '  ' }
                    }
                    Write-Host $line -ForegroundColor $(if ($row -eq $sparkHeight) { 'Red' } else { 'DarkRed' })
                }
                Write-Host ("  " + ("▔ " * $data.Count)) -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        if ($Export) {
            $data | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $data
    }
}
