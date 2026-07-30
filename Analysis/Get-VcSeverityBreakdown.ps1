function Get-VcSeverityBreakdown {
    <#
    .SYNOPSIS
        Groups open findings by severity level, showing counts and percentage of total.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER SandboxGuid
        Scope to a sandbox scan.
    .PARAMETER ScanType
        Limit to one scan type: STATIC, DYNAMIC, MANUAL, SCA.
    .PARAMETER FlawStatus
        OPEN (default) or CLOSED.
    .PARAMETER BarWidth
        Maximum width of the console bar chart (default 40).
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcSeverityBreakdown -AppGuid 'abc'
        Get-VcSeverityBreakdown -AppGuid 'abc' -ScanType STATIC -Export .\sev.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$SandboxGuid,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus = 'OPEN',

        [int]$BarWidth = 40,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $params = @{ AppGuid = $AppGuid; FlawStatus = $FlawStatus; Profile = $Profile }
        if ($SandboxGuid) { $params['SandboxGuid'] = $SandboxGuid }
        if ($ScanType)    { $params['ScanType']    = $ScanType }

        $findings = @(Get-VcFindings @params)
        $total    = $findings.Count

        $rows = 0..5 | ForEach-Object {
            $sev   = $_
            $label = $script:VcSeverityLabels[$sev]
            $count = @($findings | Where-Object { $_.Severity -eq $sev }).Count
            $pct   = if ($total -gt 0) { [Math]::Round($count / $total * 100, 1) } else { 0 }
            $bar   = if ($total -gt 0 -and $count -gt 0) {
                         '█' * [int]($count / $total * $BarWidth)
                     } else { '' }

            [pscustomobject]@{
                Severity  = $sev
                Label     = $label
                Count     = $count
                PctTotal  = $pct
                Bar       = $bar
            }
        } | Sort-Object Severity -Descending

        Write-Host ""
        Write-Host "  Severity Breakdown — $total finding(s)$(if ($ScanType) { " [$ScanType]" })" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 65) -ForegroundColor DarkGray
        Write-Host ("  {0,-12} {1,6}  {2,6}  {3}" -f 'Severity','Count','%','Bar') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $color = switch ($r.Severity) {
                5 { 'Red' }; 4 { 'DarkRed' }; 3 { 'Yellow' }; 2 { 'Cyan' }; 1 { 'DarkCyan' }; 0 { 'DarkGray' }
            }
            Write-Host ("  {0,-12} {1,6}  {2,5}%  {3}" -f $r.Label, $r.Count, $r.PctTotal, $r.Bar) -ForegroundColor $color
        }
        Write-Host ""

        if ($Export) {
            $rows | Select-Object Severity,Label,Count,PctTotal | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
