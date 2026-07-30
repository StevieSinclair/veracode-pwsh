function Get-VcCategoryBreakdown {
    <#
    .SYNOPSIS
        Groups findings by Veracode vulnerability category with per-severity counts.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER ScanType
        Limit to one scan type: STATIC, DYNAMIC, MANUAL, SCA.
    .PARAMETER FlawStatus
        OPEN (default) or CLOSED.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcCategoryBreakdown -AppGuid 'abc'
        Get-VcCategoryBreakdown -AppGuid 'abc' -ScanType STATIC -Export .\cats.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus = 'OPEN',

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $params = @{ AppGuid = $AppGuid; FlawStatus = $FlawStatus; Profile = $Profile }
        if ($ScanType) { $params['ScanType'] = $ScanType }

        $findings = @(Get-VcFindings @params)

        $rows = $findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            $g    = $_.Group
            $catId = ($g | Select-Object -First 1).CategoryId

            [pscustomobject]@{
                CategoryId   = $catId
                CategoryName = $_.Name
                Total        = $_.Count
                VeryHigh     = @($g | Where-Object { $_.Severity -eq 5 }).Count
                High         = @($g | Where-Object { $_.Severity -eq 4 }).Count
                Medium       = @($g | Where-Object { $_.Severity -eq 3 }).Count
                Low          = @($g | Where-Object { $_.Severity -eq 2 }).Count
                VeryLow      = @($g | Where-Object { $_.Severity -eq 1 }).Count
                Informational = @($g | Where-Object { $_.Severity -eq 0 }).Count
            }
        }

        Write-Host ""
        Write-Host "  Category Breakdown — $($findings.Count) finding(s)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 80) -ForegroundColor DarkGray
        Write-Host ("  {0,-40}  {1,5}  {2,2}  {3,2}  {4,2}  {5,2}  {6,2}  {7,2}" -f `
            'Category','Total','VH','H','M','L','VL','I') -ForegroundColor DarkCyan

        foreach ($r in $rows) {
            $name  = if ($r.CategoryName.Length -gt 39) { $r.CategoryName.Substring(0,36) + '...' } else { $r.CategoryName }
            $color = if ($r.VeryHigh -gt 0) { 'Red' } elseif ($r.High -gt 0) { 'Yellow' } else { 'White' }
            Write-Host ("  {0,-40}  {1,5}  {2,2}  {3,2}  {4,2}  {5,2}  {6,2}  {7,2}" -f `
                $name, $r.Total, $r.VeryHigh, $r.High, $r.Medium, $r.Low, $r.VeryLow, $r.Informational) -ForegroundColor $color
        }
        Write-Host ""

        if ($Export) {
            $rows | Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported to '$Export'."
        }

        return $rows
    }
}
