function Export-VcFindings {
    <#
    .SYNOPSIS
        Exports findings for one application (or all apps) to a CSV or JSON file.
        Pages through results incrementally to handle large finding sets without
        loading everything into memory at once.
    .PARAMETER AppGuid
        Application GUID. Mutually exclusive with -All.
    .PARAMETER All
        Export findings from every application in the org.
    .PARAMETER OutputPath
        Destination file path (e.g. .\findings.csv or .\findings.json).
    .PARAMETER Format
        Output format: CSV (default) or JSON.
    .PARAMETER ScanType
        Filter by scan type: STATIC, DYNAMIC, MANUAL, SCA.
    .PARAMETER MinSeverity
        Export only findings with severity >= this value (0–5).
    .PARAMETER FlawStatus
        Filter by status: OPEN or CLOSED.
    .EXAMPLE
        Export-VcFindings -AppGuid 'abc' -OutputPath .\findings.csv
        Export-VcFindings -All -OutputPath .\all-findings.csv -MinSeverity 4
        Export-VcFindings -AppGuid 'abc' -OutputPath .\findings.json -Format JSON
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [string]$AppGuid,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('CSV','JSON')]
        [string]$Format = 'CSV',

        [ValidateSet('STATIC','DYNAMIC','MANUAL','SCA')]
        [string]$ScanType,

        [ValidateRange(0,5)]
        [int]$MinSeverity = -1,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus,

        [string]$Profile = $script:VcCurrentProfile
    )

    $findingParams = @{ Profile = $Profile }
    if ($ScanType)          { $findingParams['ScanType']    = $ScanType }
    if ($MinSeverity -ge 0) { $findingParams['MinSeverity'] = $MinSeverity }
    if ($FlawStatus)        { $findingParams['FlawStatus']  = $FlawStatus }

    $appGuids = if ($All) {
        (Get-VcApplications -Profile $Profile).Guid
    } else {
        @($AppGuid)
    }

    if ($Format -eq 'JSON') {
        $allFindings = [System.Collections.Generic.List[object]]::new()

        $i = 0
        foreach ($guid in $appGuids) {
            $i++
            if ($All) {
                Write-Progress -Activity 'Exporting findings' `
                               -Status "App $i / $($appGuids.Count)" `
                               -PercentComplete ([int](($i / $appGuids.Count) * 100))
            }
            Get-VcFindings -AppGuid $guid @findingParams |
                ForEach-Object { $allFindings.Add($_) }
        }

        $allFindings | Select-Object -ExcludeProperty _Raw |
            ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath
        Write-Host "Exported $($allFindings.Count) finding(s) to '$OutputPath' (JSON)."

    } else {
        # CSV: stream page by page using -Append so memory stays flat
        $total   = 0
        $isFirst = $true
        $i       = 0

        foreach ($guid in $appGuids) {
            $i++
            if ($All) {
                Write-Progress -Activity 'Exporting findings' `
                               -Status "App $i / $($appGuids.Count)" `
                               -PercentComplete ([int](($i / $appGuids.Count) * 100))
            }

            $findings = Get-VcFindings -AppGuid $guid @findingParams
            if (-not $findings -or $findings.Count -eq 0) { continue }

            $rows = $findings | Select-Object -ExcludeProperty _Raw, Annotations

            if ($isFirst) {
                $rows | Export-Csv -Path $OutputPath -NoTypeInformation
                $isFirst = $false
            } else {
                $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Append
            }
            $total += $findings.Count
        }

        if ($All) { Write-Progress -Activity 'Exporting findings' -Completed }
        Write-Host "Exported $total finding(s) to '$OutputPath' (CSV)."
    }
}

function Get-VcFindingAge {
    <#
    .SYNOPSIS
        Shows open findings for an application sorted by age, highlighting those
        approaching or past the policy grace period deadline.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER GracePeriodDays
        Number of days after first-found before a finding is considered overdue.
        Defaults to 90 days (a common policy grace period).
    .EXAMPLE
        Get-VcFindingAge -AppGuid 'abc'
        Get-VcFindingAge -AppGuid 'abc' -GracePeriodDays 30 | Where-Object IsOverdue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [int]$GracePeriodDays = 90,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $findings = Get-VcFindings -AppGuid $AppGuid -FlawStatus OPEN -Profile $Profile

        $findings | ForEach-Object {
            $daysLeft = $GracePeriodDays - $_.DaysOpen
            $_ | Add-Member -NotePropertyName DaysUntilDue  -NotePropertyValue $daysLeft    -Force
            $_ | Add-Member -NotePropertyName IsOverdue     -NotePropertyValue ($daysLeft -lt 0) -Force
            $_ | Add-Member -NotePropertyName IsDueSoon     -NotePropertyValue ($daysLeft -ge 0 -and $daysLeft -le 14) -Force
            $_
        } | Sort-Object DaysOpen -Descending
    }
}
