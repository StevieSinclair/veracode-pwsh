function Compare-VcScans {
    <#
    .SYNOPSIS
        Compares two builds of the same application — NEW findings introduced,
        FIXED findings resolved, and PERSISTED findings unchanged between scans.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER CurrentBuildId
        Build ID of the newer/current scan. Omit to use the latest completed scan.
    .PARAMETER BaselineBuildId
        Build ID of the older/baseline scan. Omit to use the second-most-recent scan.
    .PARAMETER ScanType
        Limit comparison to one scan type: STATIC, DYNAMIC, MANUAL, SCA.
    .PARAMETER Export
        Path to write combined results as a CSV (adds a ChangeType column).
    .EXAMPLE
        Compare-VcScans -AppGuid 'abc'
        Compare-VcScans -AppGuid 'abc' -BaselineBuildId '1000' -CurrentBuildId '1001'
        Compare-VcScans -AppGuid 'abc' -Export .\diff.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$CurrentBuildId,
        [string]$BaselineBuildId,

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # Helper: fetch findings for a specific build
        function Get-BuildFindings_ {
            param([string]$BuildId, [string]$AppGuid, [string]$ScanType, [string]$Profile)
            $query = @{}
            if ($BuildId)  { $query['build_id']  = $BuildId }
            if ($ScanType) { $query['scan_type']  = $ScanType }
            $raw = Invoke-VcPagedApi -Path "/appsec/v2/applications/$AppGuid/findings" `
                                     -EmbeddedKey 'findings' -Query $query -Profile $Profile
            return @($raw | ForEach-Object { ConvertTo-VcFinding $_ $AppGuid })
        }

        # Resolve build IDs if not specified
        if (-not $CurrentBuildId -or -not $BaselineBuildId) {
            $app = Get-VcApplication -Guid $AppGuid -Profile $Profile
            if (-not $app.LegacyId) {
                Write-Warning "Cannot auto-resolve build IDs without a legacy app ID. Please specify -CurrentBuildId and -BaselineBuildId."
            } else {
                try {
                    $buildXml  = Invoke-VcXmlApi -Path '/api/5.0/getbuildlist.do' `
                                                 -Params @{ app_id = $app.LegacyId } -Profile $Profile
                    $buildList = $buildXml.SelectNodes('//build') |
                                 ForEach-Object {
                                     [pscustomobject]@{
                                         BuildId = $_.GetAttribute('build_id')
                                         Version = $_.GetAttribute('version')
                                     }
                                 }
                    if ($buildList.Count -lt 2) {
                        throw "Fewer than 2 completed builds found — cannot compute diff."
                    }
                    $sorted = @($buildList)
                    if (-not $CurrentBuildId)  { $CurrentBuildId  = $sorted[-1].BuildId }
                    if (-not $BaselineBuildId) { $BaselineBuildId = $sorted[-2].BuildId }
                } catch {
                    Write-Warning "Could not resolve build list: $_"
                }
            }
        }

        Write-Host ""
        Write-Host "  Comparing builds: Baseline=$BaselineBuildId  →  Current=$CurrentBuildId" -ForegroundColor Cyan

        Write-Verbose "Fetching baseline findings..."
        $baseFindings    = Get-BuildFindings_ -BuildId $BaselineBuildId -AppGuid $AppGuid -ScanType $ScanType -Profile $Profile
        Write-Verbose "Fetching current findings..."
        $currentFindings = Get-BuildFindings_ -BuildId $CurrentBuildId  -AppGuid $AppGuid -ScanType $ScanType -Profile $Profile

        $baseIds    = @($baseFindings    | Select-Object -ExpandProperty IssueId)
        $currentIds = @($currentFindings | Select-Object -ExpandProperty IssueId)

        $newFindings       = @($currentFindings | Where-Object { $_.IssueId -notin $baseIds })
        $fixedFindings     = @($baseFindings    | Where-Object { $_.IssueId -notin $currentIds })
        $persistedFindings = @($currentFindings | Where-Object { $_.IssueId -in $baseIds })

        Write-Host ("  +{0,4} new    -{1,4} fixed    ={2,4} persisted" -f `
            $newFindings.Count, $fixedFindings.Count, $persistedFindings.Count)
        Write-Host ""

        if ($newFindings.Count -gt 0) {
            $newHigh = @($newFindings | Where-Object { $_.Severity -ge 4 }).Count
            Write-Host "  NEW ($($newFindings.Count)):" -ForegroundColor Red
            $newFindings | Sort-Object Severity -Descending | Select-Object -First 10 | ForEach-Object {
                Write-Host ("    [{0}] CWE-{1} {2}  {3}:{4}" -f $_.SeverityLabel, $_.CweId, $_.CweName, $_.FileName, $_.LineNumber) -ForegroundColor $(if ($_.Severity -ge 4) { 'Red' } else { 'Yellow' })
            }
            if ($newFindings.Count -gt 10) { Write-Host "    ... and $($newFindings.Count - 10) more." -ForegroundColor DarkGray }
            Write-Host ""
        }

        if ($fixedFindings.Count -gt 0) {
            Write-Host "  FIXED ($($fixedFindings.Count)):" -ForegroundColor Green
            $fixedFindings | Sort-Object Severity -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Host ("    [{0}] CWE-{1} {2}" -f $_.SeverityLabel, $_.CweId, $_.CweName) -ForegroundColor Green
            }
            if ($fixedFindings.Count -gt 5) { Write-Host "    ... and $($fixedFindings.Count - 5) more." -ForegroundColor DarkGray }
            Write-Host ""
        }

        $result = [pscustomobject]@{
            AppGuid          = $AppGuid
            BaselineBuildId  = $BaselineBuildId
            CurrentBuildId   = $CurrentBuildId
            NewCount         = $newFindings.Count
            FixedCount       = $fixedFindings.Count
            PersistedCount   = $persistedFindings.Count
            NewFindings      = $newFindings
            FixedFindings    = $fixedFindings
            PersistedFindings = $persistedFindings
        }

        if ($Export) {
            $combined = @(
                @($newFindings       | Select-Object *, @{ N='ChangeType'; E={ 'NEW' } })
                @($fixedFindings     | Select-Object *, @{ N='ChangeType'; E={ 'FIXED' } })
                @($persistedFindings | Select-Object *, @{ N='ChangeType'; E={ 'PERSISTED' } })
            )
            $combined | Select-Object -ExcludeProperty _Raw,Annotations |
                Export-Csv -Path $Export -NoTypeInformation
            Write-Host "  Exported $($combined.Count) rows to '$Export'."
        }

        return $result
    }
}
