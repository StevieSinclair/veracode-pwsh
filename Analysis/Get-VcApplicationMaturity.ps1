# Maturity level labels
$script:VcMaturityLevels = @{
    1 = 'Initial'
    2 = 'Developing'
    3 = 'Established'
    4 = 'Advanced'
    5 = 'Optimized'
}

function Get-VcApplicationMaturity {
    <#
    .SYNOPSIS
        Scores each application against a 5-level security maturity model and lists
        what needs to improve to reach the next level.

    .DESCRIPTION
        Evaluates five dimensions for each application:

          Dimension 1 — Scan Coverage  (0–3 pts)
            0 = Never scanned
            1 = STATIC only
            2 = STATIC + SCA
            3 = STATIC + SCA + DYNAMIC

          Dimension 2 — Scan Recency   (0–3 pts)
            0 = No scan history
            1 = Last scan > 180 days ago
            2 = Last scan 31–180 days ago
            3 = Last scan ≤ 30 days ago

          Dimension 3 — Policy Compliance  (0–3 pts)
            0 = NOT_ASSESSED
            1 = DID_NOT_PASS
            2 = PASSED (no-policy or free-tier)
            3 = PASSED with a named policy assigned

          Dimension 4 — Finding Severity Profile  (-2–2 pts)
           -2 = Open Very High findings
           -1 = Open High findings (no VH)
            0 = Open findings, all Medium or lower
            1 = Zero open High+ findings, some Medium/Low remain
            2 = Zero open findings

          Dimension 5 — Remediation Activity  (0–2 pts)
            0 = No mitigations at all
            1 = At least one mitigation proposed
            2 = At least one mitigation approved

        Total score → Level:
           ≤ 2 = Level 1 (Initial)
           3–5 = Level 2 (Developing)
           6–8 = Level 3 (Established)
           9–10 = Level 4 (Advanced)
          11–13 = Level 5 (Optimized)

    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER All
        Score all applications in the organisation.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcApplicationMaturity -AppGuid 'abc'
        Get-VcApplicationMaturity -All | Sort-Object Score | Format-Table
        Get-VcApplicationMaturity -All -Export .\maturity.csv
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single', ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    begin {
        $results = [System.Collections.Generic.List[object]]::new()
    }

    process {
        $appGuids = if ($All) {
            (Get-VcApplications -Profile $Profile) | ForEach-Object { [pscustomobject]@{ Guid = $_.Guid; Name = $_.Name; App = $_ } }
        } else {
            $app = Get-VcApplication -Guid $AppGuid -Profile $Profile
            @([pscustomobject]@{ Guid = $AppGuid; Name = $app.Name; App = $app })
        }

        $i = 0
        foreach ($item in $appGuids) {
            $i++
            if ($All) {
                Write-Progress -Activity 'Scoring application maturity' `
                               -Status "$($item.Name) ($i / $($appGuids.Count))" `
                               -PercentComplete ([int](($i / $appGuids.Count) * 100))
            }
            $result = Measure-VcAppMaturity_ -App $item.App -Profile $Profile
            $results.Add($result)
        }
    }

    end {
        if ($All) { Write-Progress -Activity 'Scoring application maturity' -Completed }

        $output = $results.ToArray()
        if ($Export) {
            $output | Select-Object -ExcludeProperty Improvements |
                Export-Csv -Path $Export -NoTypeInformation
            Write-Host "Maturity report exported to '$Export' ($($output.Count) applications)."
        }
        return $output
    }
}

function Measure-VcAppMaturity_ {
    param($App, [string]$Profile)

    $guid = $App.Guid
    $improvements = [System.Collections.Generic.List[string]]::new()

    # ── Dimension 1: Scan Coverage ────────────────────────────────────────────
    $scanTypes = @()
    try {
        $scans = Get-VcScans -AppGuid $guid -Profile $Profile
        $scanTypes = @($scans | Select-Object -ExpandProperty ScanType -Unique)
    } catch { }

    $hasStatic  = 'STATIC'  -in $scanTypes
    $hasSca     = 'SCA'     -in $scanTypes
    $hasDynamic = 'DYNAMIC' -in $scanTypes

    $d1 = if ($hasStatic -and $hasSca -and $hasDynamic) { 3 }
          elseif ($hasStatic -and $hasSca) { 2 }
          elseif ($hasStatic) { 1 }
          else { 0 }

    if (-not $hasStatic)  { $improvements.Add('Add STATIC (SAST) scanning') }
    if (-not $hasSca)     { $improvements.Add('Add SCA (Software Composition Analysis) scanning') }
    if (-not $hasDynamic) { $improvements.Add('Add DYNAMIC (DAST) scanning') }

    # ── Dimension 2: Scan Recency ─────────────────────────────────────────────
    $daysSinceScan = $null
    if ($App.LastScanDate) {
        try {
            $last          = [DateTime]::Parse($App.LastScanDate)
            $daysSinceScan = [int]([DateTime]::UtcNow - $last).TotalDays
        } catch { }
    }

    $d2 = if ($null -eq $daysSinceScan) { 0 }
          elseif ($daysSinceScan -gt 180) { 1 }
          elseif ($daysSinceScan -gt 30)  { 2 }
          else { 3 }

    if ($null -eq $daysSinceScan) {
        $improvements.Add('Submit at least one scan')
    } elseif ($daysSinceScan -gt 180) {
        $improvements.Add("Scan more frequently (last scan was $daysSinceScan days ago; target: ≤30 days)")
    } elseif ($daysSinceScan -gt 30) {
        $improvements.Add("Increase scan frequency (last scan was $daysSinceScan days ago; target: ≤30 days)")
    }

    # ── Dimension 3: Policy Compliance ───────────────────────────────────────
    $hasNamedPolicy = $App.PolicyName -and $App.PolicyName -ne 'No Policy'

    $d3 = switch ($App.PolicyCompliance) {
        'PASSED'       { if ($hasNamedPolicy) { 3 } else { 2 } }
        'DID_NOT_PASS' { 1 }
        default        { 0 }   # NOT_ASSESSED or null
    }

    if ($App.PolicyCompliance -ne 'PASSED') {
        $improvements.Add("Achieve policy compliance (current: $(if ($null -ne $App.PolicyCompliance) { $App.PolicyCompliance } else { 'NOT_ASSESSED' }))")
    }
    if (-not $hasNamedPolicy) {
        $improvements.Add('Assign a named security policy to the application')
    }

    # ── Dimension 4: Finding Severity Profile ─────────────────────────────────
    $openFindings = @()
    try {
        $openFindings = @(Get-VcFindings -AppGuid $guid -FlawStatus OPEN -Profile $Profile)
    } catch { }

    $vhCount   = @($openFindings | Where-Object { $_.Severity -eq 5 }).Count
    $highCount = @($openFindings | Where-Object { $_.Severity -eq 4 }).Count
    $midCount  = @($openFindings | Where-Object { $_.Severity -le 3 }).Count

    $d4 = if ($vhCount -gt 0)                            { -2 }
          elseif ($highCount -gt 0)                      { -1 }
          elseif ($openFindings.Count -eq 0)             {  2 }
          else                                           {  1 }

    if ($vhCount -gt 0)   { $improvements.Add("Remediate $vhCount Very High severity finding(s) — policy-blocking") }
    if ($highCount -gt 0) { $improvements.Add("Remediate $highCount High severity finding(s)") }
    if ($midCount -gt 0)  { $improvements.Add("Address $midCount Medium/Low severity finding(s)") }

    # ── Dimension 5: Remediation Activity ────────────────────────────────────
    $mitigationScore = 0
    try {
        $annotated = @(Get-VcFindings -AppGuid $guid -IncludeAnnotations -Profile $Profile)
        $proposed  = @($annotated | Where-Object { $_.MitigationStatus -eq 'PROPOSED' }).Count
        $approved  = @($annotated | Where-Object { $_.MitigationStatus -in @('APPROVED','ACCEPTED') }).Count

        $mitigationScore = if ($approved -gt 0) { 2 } elseif ($proposed -gt 0) { 1 } else { 0 }
    } catch { }

    $d5 = $mitigationScore

    if ($d5 -eq 0 -and $openFindings.Count -gt 0) {
        $improvements.Add('Submit mitigation proposals for open findings to show active remediation')
    }

    # ── Score → Level ─────────────────────────────────────────────────────────
    $total = $d1 + $d2 + $d3 + $d4 + $d5

    $level = if    ($total -le 2)  { 1 }
             elseif ($total -le 5)  { 2 }
             elseif ($total -le 8)  { 3 }
             elseif ($total -le 10) { 4 }
             else                   { 5 }

    $nextLevel = [Math]::Min(5, $level + 1)
    $nextThreshold = @{ 1 = 3; 2 = 6; 3 = 9; 4 = 11; 5 = 13 }
    $ptsToNext = [Math]::Max(0, $nextThreshold[$nextLevel] - $total)

    [pscustomobject]@{
        AppName            = $App.Name
        AppGuid            = $guid
        Level              = $level
        LevelLabel         = $script:VcMaturityLevels[$level]
        Score              = $total
        PointsToNextLevel  = $ptsToNext
        # Dimension breakdown
        ScanCoverage       = $d1
        ScanRecency        = $d2
        PolicyCompliance   = $d3
        FindingProfile     = $d4
        RemediationActivity = $d5
        # Raw context
        HasStatic          = $hasStatic
        HasSca             = $hasSca
        HasDynamic         = $hasDynamic
        DaysSinceScan      = $daysSinceScan
        OpenVeryHigh       = $vhCount
        OpenHigh           = $highCount
        OpenTotal          = $openFindings.Count
        PolicyStatus       = $App.PolicyCompliance
        PolicyName         = $App.PolicyName
        # Improvement list (array; not in CSV export)
        Improvements       = $improvements.ToArray()
    }
}

function Show-VcMaturityReport {
    <#
    .SYNOPSIS
        Prints a formatted maturity report for one or more applications to the console,
        including a level bar and prioritised improvement list.
    .PARAMETER AppGuid
        Application GUID. If omitted, reports on all applications.
    .PARAMETER All
        Score every application in the org.
    .EXAMPLE
        Show-VcMaturityReport -AppGuid 'abc'
        Show-VcMaturityReport -All
        Get-VcApplications -Name 'PaymentApp' | Show-VcMaturityReport
    #>
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single', ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [string]$Profile = $script:VcCurrentProfile
    )

    $maturityParams = @{ Profile = $Profile }
    if ($All) { $maturityParams['All'] = $true } else { $maturityParams['AppGuid'] = $AppGuid }

    $apps = Get-VcApplicationMaturity @maturityParams

    foreach ($app in ($apps | Sort-Object Score)) {
        $bar  = ('█' * $app.Level) + ('░' * (5 - $app.Level))
        $line = "  [$bar] Level $($app.Level) — $($app.LevelLabel)  (score $($app.Score)/13)"

        Write-Host ""
        Write-Host "══════════════════════════════════════════════════" -ForegroundColor DarkCyan
        Write-Host "  $($app.AppName)" -ForegroundColor Cyan
        Write-Host $line

        Write-Host ""
        Write-Host "  Dimension Scores:"
        Write-Host "    Scan Coverage        : $($app.ScanCoverage)/3  (Static=$($app.HasStatic), SCA=$($app.HasSca), DAST=$($app.HasDynamic))"
        Write-Host "    Scan Recency         : $($app.ScanRecency)/3  (Last scan: $(if ($app.DaysSinceScan -ne $null) { "$($app.DaysSinceScan) days ago" } else { 'never' }))"
        Write-Host "    Policy Compliance    : $($app.PolicyCompliance)/3  ($(if ($null -ne $app.PolicyStatus) { $app.PolicyStatus } else { 'NOT_ASSESSED' }), Policy: $(if ($null -ne $app.PolicyName) { $app.PolicyName } else { 'none' }))"

        $severityColor = if ($app.FindingProfile -lt 0) { 'Red' } elseif ($app.FindingProfile -lt 2) { 'Yellow' } else { 'Green' }
        Write-Host "    Finding Severity     : $($app.FindingProfile)  (VH=$($app.OpenVeryHigh), H=$($app.OpenHigh), Total=$($app.OpenTotal))" -ForegroundColor $severityColor
        Write-Host "    Remediation Activity : $($app.RemediationActivity)/2"

        if ($app.Improvements.Count -gt 0) {
            Write-Host ""
            Write-Host "  Improvements needed to reach Level $([Math]::Min(5, $app.Level + 1)):" -ForegroundColor Yellow
            foreach ($imp in $app.Improvements) {
                Write-Host "    • $imp"
            }
        } else {
            Write-Host ""
            Write-Host "  No further improvements identified — application is at peak maturity." -ForegroundColor Green
        }
    }

    Write-Host ""

    if ($apps.Count -gt 1) {
        Write-Host "══ ORG SUMMARY ═══════════════════════════════════" -ForegroundColor DarkCyan
        $byLevel = $apps | Group-Object Level | Sort-Object Name
        foreach ($g in $byLevel) {
            $lbl = $script:VcMaturityLevels[[int]$g.Name]
            Write-Host ("  Level {0} ({1,-12}): {2} app(s)" -f $g.Name, $lbl, $g.Count)
        }
        $avgScore = [Math]::Round(($apps | Measure-Object Score -Average).Average, 1)
        Write-Host "  Average score: $avgScore / 13"
        Write-Host ""
    }
}
