# Scan states that indicate a scan may be stuck (not progressing).
$script:VcStuckScanStates = @(
    'INCOMPLETE'
    'PRESCAN_SUBMITTED'
    'SUBMITTED_TO_ENGINE'
    'SCAN_IN_PROGRESS'
    'SCAN_SUBMITTED'
)

function Get-VcScans {
    <#
    .SYNOPSIS
        Lists scans for an application or a specific sandbox.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER SandboxGuid
        When specified, lists scans for this sandbox only.
    .PARAMETER Status
        Filter to a specific scan status (e.g. SCAN_IN_PROGRESS, RESULTS_READY).
    .PARAMETER OlderThanHours
        Return only scans whose age exceeds this many hours.
    .PARAMETER StuckOnly
        Return only scans in a stuck/non-progressing state beyond the default 4-hour threshold.
    .EXAMPLE
        Get-VcScans -AppGuid 'abc'
        Get-VcScans -AppGuid 'abc' -SandboxGuid 'sb1' -StuckOnly
        Get-VcApplications | Get-VcScans -OlderThanHours 8
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$SandboxGuid,
        [string]$Status,
        [int]$OlderThanHours,
        [switch]$StuckOnly,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $basePath = if ($SandboxGuid) {
            "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid/scans"
        } else {
            "/appsec/v1/applications/$AppGuid/scans"
        }

        Write-Verbose "Fetching scans from $basePath..."
        $raw = Invoke-VcPagedApi -Path $basePath -EmbeddedKey 'scans' -Profile $Profile

        $scans = $raw | ForEach-Object { ConvertTo-VcScan $_ $AppGuid $SandboxGuid }

        if ($Status)       { $scans = $scans | Where-Object { $_.Status -eq $Status } }
        if ($OlderThanHours) { $scans = $scans | Where-Object { $_.AgeHours -ge $OlderThanHours } }
        if ($StuckOnly)    { $scans = $scans | Where-Object { $_.IsStuck } }

        return $scans
    }
}

function Get-VcScanHealth {
    <#
    .SYNOPSIS
        Fetches the latest scan status for every application in the org.
        Useful for spotting stuck scans or stale results across the entire portfolio.
    .PARAMETER ThresholdHours
        Number of hours after which an in-progress scan is flagged as stuck (default 4).
    .PARAMETER StuckOnly
        Return only apps with stuck scans.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcScanHealth
        Get-VcScanHealth -StuckOnly
        Get-VcScanHealth -Export .\scan-health.csv
    #>
    [CmdletBinding()]
    param(
        [int]$ThresholdHours = 4,
        [switch]$StuckOnly,
        [string]$Export,
        [string]$Profile = $script:VcCurrentProfile
    )

    $apps = Get-VcApplications -Profile $Profile
    $results = [System.Collections.Generic.List[object]]::new()
    $i = 0

    foreach ($app in $apps) {
        $i++
        Write-Progress -Activity 'Checking scan health' `
                       -Status "$($app.Name) ($i / $($apps.Count))" `
                       -PercentComplete ([int](($i / $apps.Count) * 100))
        try {
            $scans = Get-VcScans -AppGuid $app.Guid -Profile $Profile -ErrorAction Stop
            $latest = $scans | Sort-Object SubmittedDate -Descending | Select-Object -First 1

            $row = [pscustomobject]@{
                AppName      = $app.Name
                AppGuid      = $app.Guid
                Status       = $(if ($latest) { $latest.Status } else { 'NO_SCANS' })
                AgeHours     = $(if ($latest) { $latest.AgeHours } else { $null })
                IsStuck      = $(if ($latest) { $latest.AgeHours -gt $ThresholdHours -and $latest.IsStuck } else { $false })
                SubmittedDate = $(if ($latest) { $latest.SubmittedDate } else { $null })
                ScanId       = $(if ($latest) { $latest.ScanId } else { $null })
            }
            $results.Add($row)
        } catch {
            Write-Warning "Could not fetch scans for '$($app.Name)': $_"
        }
    }

    Write-Progress -Activity 'Checking scan health' -Completed

    $output = if ($StuckOnly) { $results | Where-Object IsStuck } else { $results.ToArray() }

    if ($Export) {
        $output | Export-Csv -Path $Export -NoTypeInformation
        Write-Host "Exported scan health report to '$Export'."
    }

    return $output
}

# Converts a raw API scan object to a flat, annotated PSCustomObject.
function ConvertTo-VcScan {
    param($Raw, [string]$AppGuid, [string]$SandboxGuid)

    $ageHours = Get-VcScanAgeHours $Raw.submitted_date
    $isStuck  = ($Raw.scan_status -in $script:VcStuckScanStates) -and ($ageHours -gt 0)

    [pscustomobject]@{
        ScanId        = $(if ($null -ne $Raw.scan_id) { $Raw.scan_id } else { $Raw.build_id })  # REST uses scan_id; XML legacy uses build_id
        AppGuid       = $AppGuid
        SandboxGuid   = $SandboxGuid
        Status        = $(if ($null -ne $Raw.scan_status) { $Raw.scan_status } else { $Raw.status })
        ScanType      = $Raw.scan_type
        SubmittedDate = $Raw.submitted_date
        AgeHours      = $ageHours
        IsStuck       = $isStuck
        ModuleCount   = $Raw.modules_count
        _Raw          = $Raw
    }
}

# Returns how many hours old a scan is, based on its submitted_date. Returns -1 on parse failure.
function Get-VcScanAgeHours {
    param([string]$SubmittedDate)
    if (-not $SubmittedDate) { return -1 }
    try {
        $dt = [DateTimeOffset]::Parse($SubmittedDate)
        return [Math]::Round(([DateTimeOffset]::UtcNow - $dt).TotalHours, 1)
    } catch { return -1 }
}
