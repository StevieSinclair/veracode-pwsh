function Get-VcPrescanModules {
    <#
    .SYNOPSIS
        Lists modules identified during prescan for an application build, showing
        which were selected for scanning and which were skipped.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER BuildId
        Specific build ID. Defaults to the most recent build for the app.
    .PARAMETER NotSelectedOnly
        Return only modules that were NOT selected for scanning.
    .EXAMPLE
        Get-VcPrescanModules -AppGuid 'abc'
        Get-VcPrescanModules -AppGuid 'abc' -BuildId '12345' -NotSelectedOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$BuildId,

        [switch]$NotSelectedOnly,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # Get legacy app ID required for XML API
        $app = Get-VcApplication -Guid $AppGuid -Profile $Profile
        if (-not $app.LegacyId) {
            throw "Application '$AppGuid' does not have a legacy ID — prescan results require the XML API."
        }

        $xmlParams = @{ app_id = $app.LegacyId }
        if ($BuildId) { $xmlParams['build_id'] = $BuildId }

        Write-Verbose "Fetching prescan results for app $($app.LegacyId)$(if ($BuildId) { " build $BuildId" })..."
        $xml = Invoke-VcXmlApi -Path '/api/5.0/getprescanresults.do' -Params $xmlParams -Profile $Profile

        $modules = $xml.SelectNodes('//module') | ForEach-Object {
            $node = $_
            [pscustomobject]@{
                ModuleName   = $node.GetAttribute('name')
                Platform     = $node.GetAttribute('platform')
                Size         = $node.GetAttribute('size')
                IsSelected   = $node.GetAttribute('is_selected') -eq 'true'
                WarnCount    = [int]($node.GetAttribute('num_issue') ?? 0)
                Status       = $node.GetAttribute('status')
            }
        }

        if ($NotSelectedOnly) {
            $modules = @($modules | Where-Object { -not $_.IsSelected })
        }

        $selectedCount   = @($modules | Where-Object { $_.IsSelected }).Count
        $unselectedCount = @($modules | Where-Object { -not $_.IsSelected }).Count

        Write-Host ""
        Write-Host "  Prescan Modules — $($modules.Count) total  (selected: $selectedCount, skipped: $unselectedCount)" -ForegroundColor Cyan
        Write-Host ("  " + "─" * 70) -ForegroundColor DarkGray
        Write-Host ("  {0,-40}  {1,-20}  {2,8}  {3,8}  {4,5}" -f 'Module','Platform','Size','Selected','Warns') -ForegroundColor DarkCyan

        foreach ($m in ($modules | Sort-Object IsSelected -Descending)) {
            $color = if (-not $m.IsSelected) { 'DarkGray' } elseif ($m.WarnCount -gt 0) { 'Yellow' } else { 'White' }
            $name  = if ($m.ModuleName.Length -gt 39) { $m.ModuleName.Substring(0,36) + '...' } else { $m.ModuleName }
            Write-Host ("  {0,-40}  {1,-20}  {2,8}  {3,8}  {4,5}" -f `
                $name, $m.Platform, $m.Size, $m.IsSelected, $m.WarnCount) -ForegroundColor $color
        }

        if ($unselectedCount -gt 0) {
            Write-Host ""
            Write-Host "  Note: $unselectedCount module(s) were not selected for scanning (shown in grey)." -ForegroundColor DarkYellow
        }
        Write-Host ""

        return $modules
    }
}
