# ──────────────────────────────────────────────────────────────────────────────
# Veracode TUI Dashboard — Show-VcDashboard.ps1
# No external dependencies; uses Write-Host + ANSI codes + Console.ReadKey
# ──────────────────────────────────────────────────────────────────────────────

# ANSI helpers ─────────────────────────────────────────────────────────────────
$script:Esc = [char]27
function _c { param($code) "$($script:Esc)[$code`m" }

$script:R  = _c 0     # reset
$script:BW = _c '1;97'  # bold white
$script:CY = _c 96    # cyan
$script:GR = _c 92    # green
$script:YE = _c 93    # yellow
$script:RE = _c 91    # red
$script:DG = _c 90    # dark grey
$script:BL = _c '1;94' # bold blue

function Write-VcDashLine_ {
    param([string]$Text = '', [string]$Color = '', [switch]$NoNewline)
    $out = "$Color$Text$($script:R)"
    if ($NoNewline) { Write-Host $out -NoNewline } else { Write-Host $out }
}

function Show-VcHeader_ {
    param([string]$Profile, [string]$Subtitle = '')
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    [Console]::Clear()
    Write-Host "$($script:BL)╔══════════════════════════════════════════════════════════════╗$($script:R)"
    Write-Host "$($script:BL)║$($script:BW)              VERACODE MANAGEMENT CONSOLE                    $($script:BL)║$($script:R)"
    Write-Host "$($script:BL)╠══════════════════════════════════════════════════════════════╣$($script:R)"
    $profilePad = "  Profile: $Profile"
    $timePad    = "$ts  "
    $mid        = $profilePad.PadRight(40) + $timePad.PadLeft(22)
    Write-Host "$($script:BL)║$($script:DG)$($mid)$($script:BL)║$($script:R)"
    if ($Subtitle) {
        $subPad = "  $Subtitle".PadRight(62)
        Write-Host "$($script:BL)║$($script:CY)$subPad$($script:BL)║$($script:R)"
    }
    Write-Host "$($script:BL)╚══════════════════════════════════════════════════════════════╝$($script:R)"
    Write-Host ""
}

function Read-VcKey_ {
    # Read a single keypress; returns the char uppercased
    $key = [Console]::ReadKey($true)
    return [char]::ToUpper($key.KeyChar)
}

function Invoke-VcPaged_ {
    # Display an array of objects as a paged table and return the selected index (or -1)
    param(
        [object[]]$Items,
        [string[]]$Columns,
        [int]$PageSize = 20,
        [string]$Prompt = 'Enter # to select, N=next, P=prev, B=back'
    )

    if (-not $Items -or $Items.Count -eq 0) {
        Write-Host "  (no items)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Press any key to go back..."
        [void][Console]::ReadKey($true)
        return -1
    }

    $page     = 0
    $pageCount = [Math]::Ceiling($Items.Count / $PageSize)

    while ($true) {
        $start = $page * $PageSize
        $end   = [Math]::Min($start + $PageSize - 1, $Items.Count - 1)
        $slice = $Items[$start..$end]

        # Header row
        $header = ('#'.PadRight(5))
        foreach ($col in $Columns) { $header += $col.PadRight(25) }
        Write-Host "  $header" -ForegroundColor DarkCyan
        Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray

        for ($r = 0; $r -lt $slice.Count; $r++) {
            $num  = ($start + $r + 1).ToString().PadRight(5)
            $row  = "  $num"
            foreach ($col in $Columns) {
                $val = if ($null -ne $slice[$r].$col) { "$($slice[$r].$col)" } else { '' }
                if ($val.Length -gt 23) { $val = $val.Substring(0,20) + '...' }
                $row += $val.PadRight(25)
            }

            # Compliance colour hinting
            $color = $null
            if ($slice[$r].PSObject.Properties['PolicyCompliance']) {
                $color = switch ($slice[$r].PolicyCompliance) {
                    'PASSED'       { $script:GR }
                    'DID_NOT_PASS' { $script:RE }
                    default        { $script:DG }
                }
            }
            if ($slice[$r].PSObject.Properties['IsStuck'] -and $slice[$r].IsStuck) {
                $color = $script:RE
            }
            if ($color) { Write-Host "$color$row$($script:R)" }
            else        { Write-Host $row }
        }

        Write-Host ""
        Write-Host "  Page $($page+1)/$pageCount  ($($Items.Count) total)" -ForegroundColor DarkGray
        Write-Host "  $Prompt" -ForegroundColor Yellow
        $input = (Read-Host "  >").Trim()

        if ($input -match '^\d+$') {
            $idx = [int]$input - 1
            if ($idx -ge 0 -and $idx -lt $Items.Count) { return $idx }
        }
        switch ($input.ToUpper()) {
            'N' { if ($page -lt $pageCount - 1) { $page++ } }
            'P' { if ($page -gt 0) { $page-- } }
            'B' { return -1 }
        }
    }
}

# ── Sub-menus ────────────────────────────────────────────────────────────────

function Show-VcAppMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Applications'

        Write-Host "  Loading applications..." -ForegroundColor DarkGray
        try {
            $apps = Get-VcApplications -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Write-Host "  Press any key to return..."
            [void][Console]::ReadKey($true)
            return
        }

        Show-VcHeader_ -Profile $Profile -Subtitle "Applications ($($apps.Count))"

        $idx = Invoke-VcPaged_ -Items $apps `
                               -Columns @('Name','PolicyCompliance','LastScanDate','BusinessUnit') `
                               -Prompt '[#] View/sandboxes  [C]reate  [D]elete  [M]aturity  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $selected = $apps[$idx]
            Write-Host ""
            Write-Host "  Selected: $($selected.Name)" -ForegroundColor Cyan
            Write-Host "  [S]andboxes  [F]indings  [M]aturity  [D]elete  [B]ack"
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'C' {
                try {
                    $name  = Read-Host "  New app name"
                    $crit  = Read-Host "  Business Criticality [VERY_HIGH/HIGH/MEDIUM/LOW/VERY_LOW]"
                    New-VcApplication -Name $name -BusinessCriticality $crit -Profile $Profile -Confirm:$false
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'D' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  Delete '$($selected.Name)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Remove-VcApplication -Guid $selected.Guid -Profile $Profile -Force
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'S' {
                if ($idx -ge 0) { Show-VcSandboxMenu_ -AppGuid $selected.Guid -AppName $selected.Name -Profile $Profile }
            }
            'F' {
                if ($idx -ge 0) { Show-VcFindingsMenu_ -AppGuid $selected.Guid -AppName $selected.Name -Profile $Profile }
            }
            'M' {
                if ($idx -ge 0) {
                    Show-VcHeader_ -Profile $Profile -Subtitle "Maturity: $($selected.Name)"
                    Show-VcMaturityReport -AppGuid $selected.Guid -Profile $Profile
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                }
            }
        }
    }
}

function Show-VcSandboxMenu_ {
    param([string]$AppGuid, [string]$AppName, [string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle "Sandboxes — $AppName"
        try {
            $sandboxes = Get-VcSandboxes -AppGuid $AppGuid -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Start-Sleep 2; return
        }

        $idx = Invoke-VcPaged_ -Items $sandboxes `
                               -Columns @('Name','SandboxType','LastModifiedDate','AutoRecreate') `
                               -Prompt '[#] Select  [C]reate  [P]romote  [D]elete  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $sel = $sandboxes[$idx]
            Write-Host "  Selected: $($sel.Name)" -ForegroundColor Cyan
            Write-Host "  [P]romote to policy  [D]elete  [B]ack"
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'C' {
                try {
                    $n = Read-Host "  Sandbox name"
                    New-VcSandbox -AppGuid $AppGuid -Name $n -Profile $Profile -Confirm:$false
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'P' {
                if ($idx -ge 0) {
                    try {
                        Invoke-VcSandboxPromotion -AppGuid $AppGuid -SandboxGuid $sel.SandboxGuid -Profile $Profile -Confirm:$false
                        Start-Sleep 2
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'D' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  Delete sandbox '$($sel.Name)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Remove-VcSandbox -AppGuid $AppGuid -SandboxGuid $sel.SandboxGuid -Profile $Profile -Force
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
        }
    }
}

function Show-VcScanMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Scan Health'
        Write-Host "  Loading scan health (this may take a moment)..." -ForegroundColor DarkGray
        try {
            $health = Get-VcScanHealth -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Write-Host "  Press any key to return..."
            [void][Console]::ReadKey($true)
            return
        }

        Show-VcHeader_ -Profile $Profile -Subtitle "Scan Health ($($health.Count) apps)"

        $stuck  = @($health | Where-Object { $_.IsStuck })
        $active = @($health | Where-Object { $_.Status -notin @('RESULTS_READY','','Unknown') -and -not $_.IsStuck })

        if ($stuck.Count -gt 0) {
            Write-Host "  $($script:RE)STUCK SCANS: $($stuck.Count)$($script:R)"
        }

        $idx = Invoke-VcPaged_ -Items $health `
                               -Columns @('AppName','Status','AgeHours','IsStuck') `
                               -Prompt '[F]ix all stuck  [R]epair selected  [W]atch  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $sel = $health[$idx]
            Write-Host "  Selected: $($sel.AppName)  Status: $($sel.Status)" -ForegroundColor Cyan
            Write-Host "  [R]epair/delete scan  [W]atch  [B]ack"
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'F' {
                try {
                    Repair-VcStuckScan -All -Profile $Profile
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'R' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  Delete latest scan for '$($sel.AppName)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Resume-VcScan -AppGuid $sel.AppGuid -Profile $Profile -Force
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'W' {
                if ($idx -ge 0) {
                    Show-VcHeader_ -Profile $Profile -Subtitle "Watching: $($sel.AppName)"
                    Watch-VcScan -AppGuid $sel.AppGuid -Profile $Profile -IntervalSeconds 30
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                }
            }
        }
    }
}

function Show-VcUserMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Users'
        $emailFilter = Read-Host "  Search by email (wildcard, blank = all)"
        if (-not $emailFilter) { $emailFilter = '*' }

        try {
            $users = Get-VcUsers -Email $emailFilter -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Start-Sleep 2; return
        }

        Show-VcHeader_ -Profile $Profile -Subtitle "Users ($($users.Count) found)"

        $idx = Invoke-VcPaged_ -Items $users `
                               -Columns @('Email','FirstName','LoginEnabled','LastLoginDate') `
                               -Prompt '[#] View/edit  [C]reate  [D]eactivate  [X]Delete  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $sel = $users[$idx]
            Write-Host "  Selected: $($sel.Email)  Roles: $($sel.Roles -join ', ')" -ForegroundColor Cyan
            Write-Host "  [D]eactivate  [X]Delete  [R]oles  [B]ack"
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'C' {
                try {
                    $email = Read-Host "  Email"
                    $first = Read-Host "  First name"
                    $last  = Read-Host "  Last name"
                    New-VcUser -Email $email -FirstName $first -LastName $last -Profile $Profile -Confirm:$false
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'D' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  Deactivate '$($sel.Email)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Remove-VcUser -UserId $sel.UserId -Deactivate -Profile $Profile -Force
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'X' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  PERMANENTLY DELETE '$($sel.Email)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Remove-VcUser -UserId $sel.UserId -Profile $Profile -Force
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'R' {
                if ($idx -ge 0) {
                    try {
                        Write-Host "  Current roles: $($sel.Roles -join ', ')"
                        $add    = (Read-Host "  Roles to add (comma-separated, blank to skip)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        $remove = (Read-Host "  Roles to remove (comma-separated, blank to skip)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        Set-VcUserRoles -UserId $sel.UserId -AddRoles $add -RemoveRoles $remove -Profile $Profile
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
        }
    }
}

function Show-VcTeamMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Teams'
        try {
            $teams = Get-VcTeams -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Start-Sleep 2; return
        }

        $idx = Invoke-VcPaged_ -Items $teams `
                               -Columns @('TeamName','MemberCount','BusinessUnit') `
                               -Prompt '[#] Manage members  [C]reate  [D]elete  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $sel = $teams[$idx]
            Write-Host "  Selected: $($sel.TeamName)  Members: $($sel.MemberCount)" -ForegroundColor Cyan
            Write-Host "  [A]dd user  [R]emove user  [D]elete team  [B]ack"
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'C' {
                try {
                    $n = Read-Host "  Team name"
                    New-VcTeam -Name $n -Profile $Profile -Confirm:$false
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'D' {
                if ($idx -ge 0) {
                    try {
                        $confirm = Read-Host "  Delete team '$($sel.TeamName)'? [y/N]"
                        if ($confirm -match '^[yY]') {
                            Remove-VcTeam -TeamId $sel.TeamId -TeamName $sel.TeamName -Force -Profile $Profile
                        }
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'A' {
                if ($idx -ge 0) {
                    try {
                        $emails = (Read-Host "  Email(s) to add (comma-separated)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        Set-VcTeamMembers -TeamId $sel.TeamId -AddEmails $emails -Profile $Profile -Confirm:$false
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
            'R' {
                if ($idx -ge 0) {
                    try {
                        $emails = (Read-Host "  Email(s) to remove (comma-separated)") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        Set-VcTeamMembers -TeamId $sel.TeamId -RemoveEmails $emails -Profile $Profile -Confirm:$false
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
        }
    }
}

function Show-VcFindingsMenu_ {
    param([string]$AppGuid, [string]$AppName, [string]$Profile)

    Show-VcHeader_ -Profile $Profile -Subtitle "Findings — $AppName"
    Write-Host "  Loading findings..." -ForegroundColor DarkGray

    try {
        $findings = Get-VcFindings -AppGuid $AppGuid -FlawStatus OPEN -Profile $Profile
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        Write-Host "  Press any key to return..."; [void][Console]::ReadKey($true)
        return
    }

    Show-VcHeader_ -Profile $Profile -Subtitle "Findings — $AppName ($($findings.Count) open)"

    $idx = Invoke-VcPaged_ -Items $findings `
                           -Columns @('SeverityLabel','CweName','FileName','FlawStatus') `
                           -Prompt '[#] Detail  [E]xport CSV  [A]ge report  [B]ack'

    if ($idx -eq -1) {
        $ch = Read-VcKey_
    } else {
        $sel = $findings[$idx]
        Write-Host "  Finding $($sel.IssueId): $($sel.CweName)  File: $($sel.FileName):$($sel.LineNumber)" -ForegroundColor Cyan
        $ch = Read-VcKey_
    }

    switch ($ch) {
        'E' {
            try {
                $path = Read-Host "  Output path (e.g. .\findings.csv)"
                Export-VcFindings -AppGuid $AppGuid -OutputPath $path -Profile $Profile
            } catch { Write-Host "  ERROR: $_" -ForegroundColor Red }
            Start-Sleep 2
        }
        'A' {
            $grace = Read-Host "  Grace period days (default 90)"
            if (-not $grace) { $grace = 90 }
            $aged = Get-VcFindingAge -AppGuid $AppGuid -GracePeriodDays ([int]$grace) -Profile $Profile
            $aged | Select-Object IssueId,CweName,DaysOpen,IsOverdue,IsDueSoon | Format-Table -AutoSize
            Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
        }
    }
}

function Show-VcPolicyMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Policies'
        try {
            $policies = Get-VcPolicies -Profile $Profile
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            Start-Sleep 2; return
        }

        $idx = Invoke-VcPaged_ -Items $policies `
                               -Columns @('PolicyName','Type','ScanFrequencyDays','FindingRuleCount') `
                               -Prompt '[#] Evaluate app  [C]ompliance overview  [B]ack'

        if ($idx -eq -1) {
            $ch = Read-VcKey_
        } else {
            $sel = $policies[$idx]
            Write-Host "  Selected: $($sel.PolicyName)" -ForegroundColor Cyan
            $ch = Read-VcKey_
        }

        switch ($ch) {
            'B' { return }
            'C' {
                try {
                    Show-VcHeader_ -Profile $Profile -Subtitle 'Compliance Overview'
                    $comp = Get-VcApplicationCompliance -Profile $Profile
                    $comp | Format-Table AppName,PolicyCompliance,PolicyName,Passed -AutoSize
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            default {
                if ($idx -ge 0) {
                    try {
                        $appGuid = Read-Host "  App GUID to evaluate against '$($sel.PolicyName)'"
                        $result  = Invoke-VcPolicyEvaluation -AppGuid $appGuid -PolicyGuid $sel.PolicyGuid -Profile $Profile -Confirm:$false
                        $color   = if ($result.Passed) { $script:GR } else { $script:RE }
                        Write-Host "  Result: ${color}$($result.PolicyCompliance)$($script:R)"
                        Start-Sleep 2
                    } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
                }
            }
        }
    }
}

function Show-VcAdminMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Admin & Reporting'
        Write-Host "  [1] Export org-wide report (HTML)"
        Write-Host "  [2] Export org-wide report (CSV)"
        Write-Host "  [3] View audit log"
        Write-Host "  [4] Export findings summary"
        Write-Host "  [5] Org maturity overview"
        Write-Host "  [B] Back"
        Write-Host ""
        $ch = Read-VcKey_

        switch ($ch) {
            '1' {
                try {
                    $path = Read-Host "  Output path (e.g. .\report.html)"
                    Export-VcReport -OutputPath $path -Format HTML -Profile $Profile
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '2' {
                try {
                    $path = Read-Host "  Output path (e.g. .\report.csv)"
                    Export-VcReport -OutputPath $path -Format CSV -Profile $Profile
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '3' {
                try {
                    Show-VcHeader_ -Profile $Profile -Subtitle 'Audit Log (last 30 days)'
                    $log = Get-VcAuditLog -Profile $Profile
                    $log | Select-Object -First 50 EventDate,EventType,ActorEmail,Description | Format-Table -AutoSize
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '4' {
                try {
                    $path = Read-Host "  Output path (e.g. .\findings-summary.csv)"
                    Get-VcFindingsSummary -Export $path -Profile $Profile
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '5' {
                try {
                    Show-VcHeader_ -Profile $Profile -Subtitle 'Org Maturity Overview'
                    Show-VcMaturityReport -All -Profile $Profile
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'B' { return }
        }
    }
}

function Show-VcAnalysisMenu_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Analysis'
        Write-Host "  [1] Application Maturity Report"
        Write-Host "  [2] Findings Summary (org-wide)"
        Write-Host "  [3] Scan Health Summary"
        Write-Host "  [4] Finding Age / SLA report"
        Write-Host "  [B] Back"
        Write-Host ""
        $ch = Read-VcKey_

        switch ($ch) {
            '1' {
                $guid = Read-Host "  App GUID (blank = org-wide)"
                try {
                    if ($guid) {
                        Show-VcMaturityReport -AppGuid $guid -Profile $Profile
                    } else {
                        Show-VcMaturityReport -All -Profile $Profile
                    }
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '2' {
                try {
                    Show-VcHeader_ -Profile $Profile -Subtitle 'Findings Summary'
                    $summary = Get-VcFindingsSummary -Profile $Profile
                    $summary | Format-Table AppName,VeryHigh,High,Medium,Low,Total -AutoSize
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '3' {
                try {
                    Show-VcHeader_ -Profile $Profile -Subtitle 'Scan Health'
                    $health = Get-VcScanHealth -Profile $Profile
                    $health | Format-Table AppName,Status,AgeHours,IsStuck -AutoSize
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '4' {
                $guid  = Read-Host "  App GUID"
                $grace = Read-Host "  Grace period days (default 90)"
                if (-not $grace) { $grace = 90 }
                try {
                    $aged = Get-VcFindingAge -AppGuid $guid -GracePeriodDays ([int]$grace) -Profile $Profile
                    $aged | Format-Table IssueId,CweName,DaysOpen,DaysUntilDue,IsOverdue,IsDueSoon -AutoSize
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'B' { return }
        }
    }
}

function Show-VcQuickActions_ {
    param([string]$Profile)

    while ($true) {
        Show-VcHeader_ -Profile $Profile -Subtitle 'Quick Actions'
        Write-Host "  [1] Fix all stuck scans"
        Write-Host "  [2] Export findings for an app"
        Write-Host "  [3] Promote sandbox scan"
        Write-Host "  [4] Add user to team"
        Write-Host "  [5] Watch a scan live"
        Write-Host "  [6] Clone an application"
        Write-Host "  [B] Back"
        Write-Host ""
        $ch = Read-VcKey_

        switch ($ch) {
            '1' {
                try {
                    $h = Read-Host "  Threshold hours (default 4)"
                    if (-not $h) { $h = 4 }
                    Repair-VcStuckScan -All -ThresholdHours ([int]$h) -Profile $Profile
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '2' {
                try {
                    $guid = Read-Host "  App GUID"
                    $path = Read-Host "  Output path (e.g. .\findings.csv)"
                    Export-VcFindings -AppGuid $guid -OutputPath $path -Profile $Profile
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '3' {
                try {
                    $appGuid = Read-Host "  App GUID"
                    $sbGuid  = Read-Host "  Sandbox GUID"
                    Invoke-VcSandboxPromotion -AppGuid $appGuid -SandboxGuid $sbGuid -Profile $Profile -Confirm:$false
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '4' {
                try {
                    $email  = Read-Host "  User email"
                    $teamId = Read-Host "  Team ID"
                    Set-VcTeamMembers -TeamId $teamId -AddEmails @($email) -Profile $Profile -Confirm:$false
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '5' {
                try {
                    $guid = Read-Host "  App GUID"
                    Watch-VcScan -AppGuid $guid -Profile $Profile
                    Write-Host "  Press any key to continue..."; [void][Console]::ReadKey($true)
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            '6' {
                try {
                    $src  = Read-Host "  Source app GUID"
                    $name = Read-Host "  New app name"
                    Copy-VcApplication -SourceGuid $src -NewName $name -Profile $Profile -Confirm:$false
                    Start-Sleep 2
                } catch { Write-Host "  ERROR: $_" -ForegroundColor Red; Start-Sleep 2 }
            }
            'B' { return }
        }
    }
}

# ── Main Entry Point ──────────────────────────────────────────────────────────

function Show-VcDashboard {
    <#
    .SYNOPSIS
        Opens the interactive Veracode Management Console TUI.
    .PARAMETER Profile
        Credential profile to use (default: current session profile).
    .EXAMPLE
        Show-VcDashboard
        Show-VcDashboard -Profile 'production'
    #>
    [CmdletBinding()]
    param(
        [string]$Profile = $script:VcCurrentProfile
    )

    while ($true) {
        Show-VcHeader_ -Profile $Profile

        Write-Host "  $($script:CY)[1]$($script:R) Applications      $($script:CY)[2]$($script:R) Sandboxes"
        Write-Host "  $($script:CY)[3]$($script:R) Scans / Health    $($script:CY)[4]$($script:R) Users"
        Write-Host "  $($script:CY)[5]$($script:R) Teams             $($script:CY)[6]$($script:R) Findings"
        Write-Host "  $($script:CY)[7]$($script:R) Policy            $($script:CY)[8]$($script:R) Admin & Reports"
        Write-Host "  $($script:CY)[9]$($script:R) Analysis          $($script:CY)[Q]$($script:R) Quick Actions"
        Write-Host "  $($script:DG)[X] Exit$($script:R)"
        Write-Host ""
        Write-Host "  Select an option: " -NoNewline
        $ch = Read-VcKey_
        Write-Host $ch

        switch ($ch) {
            '1' { Show-VcAppMenu_      -Profile $Profile }
            '2' {
                $guid = Read-Host "  App GUID"
                Show-VcSandboxMenu_ -AppGuid $guid -AppName $guid -Profile $Profile
            }
            '3' { Show-VcScanMenu_     -Profile $Profile }
            '4' { Show-VcUserMenu_     -Profile $Profile }
            '5' { Show-VcTeamMenu_     -Profile $Profile }
            '6' {
                $guid = Read-Host "  App GUID"
                Show-VcFindingsMenu_ -AppGuid $guid -AppName $guid -Profile $Profile
            }
            '7' { Show-VcPolicyMenu_   -Profile $Profile }
            '8' { Show-VcAdminMenu_    -Profile $Profile }
            '9' { Show-VcAnalysisMenu_ -Profile $Profile }
            'Q' { Show-VcQuickActions_ -Profile $Profile }
            'X' {
                [Console]::Clear()
                Write-Host "Goodbye."
                return
            }
        }
    }
}
