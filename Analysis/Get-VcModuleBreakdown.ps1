function Get-VcModuleBreakdown {
    <#
    .SYNOPSIS
        Shows which uploaded modules (JARs, DLLs, etc.) contribute the most findings,
        helping identify high-risk components in a scan.
    .DESCRIPTION
        Uses the XML detailed report to get per-module finding counts. Falls back to
        grouping REST findings by source file prefix when the XML API is unavailable.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER BuildId
        Specific build ID. Defaults to the most recent build.
    .PARAMETER Threshold
        Flag modules with more than this many High+VeryHigh findings (default 5).
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcModuleBreakdown -AppGuid 'abc'
        Get-VcModuleBreakdown -AppGuid 'abc' -BuildId '12345' -Threshold 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$BuildId,

        [int]$Threshold = 5,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $rows = $null

        # Try XML detailed report first
        try {
            $app = Get-VcApplication -Guid $AppGuid -Profile $Profile
            if ($app.LegacyId) {
                $xmlParams = @{ app_id = $app.LegacyId }
                if ($BuildId) { $xmlParams['build_id'] = $BuildId }

                Write-Verbose "Fetching detailed report via XML API..."
                $xml = Invoke-VcXmlApi -Path '/api/5.0/detailedreport.do' -Params $xmlParams -Profile $Profile

                $moduleMap = @{}
                $xml.SelectNodes('//flaw') | ForEach-Object {
                    $mod = $_.GetAttribute('module')
                    $_sev = $_.GetAttribute('severity'); $sev = if ($_sev) { [int]$_sev } else { 0 }
                    if (-not $moduleMap.ContainsKey($mod)) {
                        $moduleMap[$mod] = @{ VH=0; H=0; M=0; L=0; Total=0 }
                    }
                    $moduleMap[$mod]['Total']++
                    switch ($sev) {
                        5 { $moduleMap[$mod]['VH']++ }
                        4 { $moduleMap[$mod]['H']++ }
                        3 { $moduleMap[$mod]['M']++ }
                        default { $moduleMap[$mod]['L']++ }
                    }
                }

                $rows = $moduleMap.GetEnumerator() | ForEach-Object {
                    [pscustomobject]@{
                        Module     = $_.Key
                        Total      = $_.Value['Total']
                        VeryHigh   = $_.Value['VH']
                        High       = $_.Value['H']
                        Medium     = $_.Value['M']
                        LowAndBelow = $_.Value['L']
                        IsHotspot  = ($_.Value['VH'] + $_.Value['H']) -gt $Threshold
                    }
                } | Sort-Object Total -Descending
            }
        } catch {
            Write-Verbose "XML API unavailable ($($_.Exception.Message)) — falling back to REST findings."
        }

        # REST fallback: group by FileName directory as a proxy for module
        if (-not $rows) {
            $findParams = @{ AppGuid = $AppGuid; FlawStatus = 'OPEN'; Profile = $Profile }
            $findings   = @(Get-VcFindings @findParams)

            $rows = $findings | Group-Object { ($_.FileName -split '[/\\]')[0] } | ForEach-Object {
                $g = $_.Group
                $vhC = @($g | Where-Object { $_.Severity -eq 5 }).Count
                $hC  = @($g | Where-Object { $_.Severity -eq 4 }).Count
                $mC  = @($g | Where-Object { $_.Severity -eq 3 }).Count
                $lC  = @($g | Where-Object { $_.Severity -le 2 }).Count
                [pscustomobject]@{
                    Module      = $_.Name
                    Total       = $_.Count
                    VeryHigh    = $vhC
                    High        = $hC
                    Medium      = $mC
                    LowAndBelow = $lC
                    IsHotspot   = ($vhC + $hC) -gt $Threshold
                }
            } | Sort-Object Total -Descending
        }

        $hotspots = @($rows | Where-Object { $_.IsHotspot })

        Write-Host ""
        Write-Host "  Module Breakdown — $($rows.Count) module(s)  [Hotspot threshold: >$Threshold High+VH]" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 75) -ForegroundColor DarkGray
        Write-Host ("  {0,-40}  {1,5}  {2,2}  {3,2}  {4,2}  {5,3}  {6}" -f 'Module','Total','VH','H','M','Low','Hotspot') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $name  = if ($r.Module.Length -gt 39) { $r.Module.Substring(0,36) + '...' } else { $r.Module }
            $color = if ($r.IsHotspot) { 'Red' } elseif ($r.VeryHigh -gt 0) { 'DarkRed' } elseif ($r.High -gt 0) { 'Yellow' } else { 'White' }
            $flag  = if ($r.IsHotspot) { '⚠ HOTSPOT' } else { '' }
            Write-Host ("  {0,-40}  {1,5}  {2,2}  {3,2}  {4,2}  {5,3}  {6}" -f `
                $name, $r.Total, $r.VeryHigh, $r.High, $r.Medium, $r.LowAndBelow, $flag) -ForegroundColor $color
        }

        if ($hotspots.Count -gt 0) {
            Write-Host ""
            Write-Host "  $($hotspots.Count) hotspot module(s) exceed the High+VH threshold of $Threshold." -ForegroundColor DarkYellow
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
