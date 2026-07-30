#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'DAST/Get-VcDastScans.ps1')
    . (Join-Path $ModuleRoot 'DAST/Start-VcDastScan.ps1')
    . (Join-Path $ModuleRoot 'DAST/Stop-VcDastScan.ps1')
    . (Join-Path $ModuleRoot 'DAST/Get-VcDastFindings.ps1')
    . (Join-Path $ModuleRoot 'DAST/Get-VcDastAnalysis.ps1')
    . (Join-Path $ModuleRoot 'DAST/Compare-VcDastSast.ps1')
    . (Join-Path $ModuleRoot 'DAST/Repair-VcDastScan.ps1')

    # ── Raw DAST analysis payloads ──────────────────────────────────────────
    $script:RunningRaw = [pscustomobject]@{
        analysis_id   = 'ana-001'
        analysis_name = 'Prod Web App Scan'
        status        = 'RUNNING'
        analysis_type = 'DYNAMIC'
        app_id        = 'app-111'
        scan_url      = 'https://prod.example.com'
        start_time    = [DateTimeOffset]::UtcNow.AddHours(-10).ToString('o')
        finish_time   = $null
        finding_count = 5
        schedule      = [pscustomobject]@{ start_time = [DateTimeOffset]::UtcNow.AddHours(-10).ToString('o') }
    }

    $script:FinishedRaw = [pscustomobject]@{
        analysis_id   = 'ana-002'
        analysis_name = 'Staging Scan'
        status        = 'FINISHED'
        analysis_type = 'DYNAMIC'
        app_id        = 'app-222'
        scan_url      = 'https://staging.example.com'
        start_time    = [DateTimeOffset]::UtcNow.AddHours(-3).ToString('o')
        finish_time   = [DateTimeOffset]::UtcNow.ToString('o')
        finding_count = 12
        schedule      = [pscustomobject]@{ start_time = [DateTimeOffset]::UtcNow.AddHours(-3).ToString('o') }
    }

    $script:QueuedRaw = [pscustomobject]@{
        analysis_id   = 'ana-003'
        analysis_name = 'Dev Scan'
        status        = 'QUEUED'
        analysis_type = 'DYNAMIC'
        app_id        = 'app-333'
        scan_url      = 'https://dev.example.com'
        start_time    = [DateTimeOffset]::UtcNow.AddHours(-12).ToString('o')
        finish_time   = $null
        finding_count = 0
        schedule      = $null
    }

    # ── Raw DAST finding payloads ───────────────────────────────────────────
    $script:SqliRaw = [pscustomobject]@{
        issue_id  = 301
        severity  = 5
        cwe_id    = 89
        finding_details = [pscustomobject]@{
            url           = 'https://prod.example.com/api/search?q=1'
            http_method   = 'GET'
            attack_vector = 'URL Parameter'
            attack_payload = "' OR 1=1--"
            cwe           = [pscustomobject]@{ id=89; name='SQL Injection' }
            finding_category = [pscustomobject]@{ id=72; name='SQL Injection' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-30).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }

    $script:XssRaw = [pscustomobject]@{
        issue_id  = 302
        severity  = 4
        cwe_id    = 79
        finding_details = [pscustomobject]@{
            url           = 'https://prod.example.com/profile'
            http_method   = 'POST'
            attack_vector = 'Form Field'
            attack_payload = '<script>alert(1)</script>'
            cwe           = [pscustomobject]@{ id=79; name='Cross-Site Scripting' }
            finding_category = [pscustomobject]@{ id=80; name='Cross-Site Scripting (XSS)' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-10).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }

    $script:InfoRaw = [pscustomobject]@{
        issue_id  = 303
        severity  = 2
        cwe_id    = 200
        finding_details = [pscustomobject]@{
            url           = 'https://prod.example.com/api/debug'
            http_method   = 'GET'
            attack_vector = 'URL Parameter'
            attack_payload = ''
            cwe           = [pscustomobject]@{ id=200; name='Information Exposure' }
            finding_category = [pscustomobject]@{ id=45; name='Information Disclosure' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-5).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-VcDastScan' {
    It 'maps analysis_id and analysis_name correctly' {
        $s = ConvertTo-VcDastScan $script:RunningRaw
        $s.AnalysisId | Should -Be 'ana-001'
        $s.Name       | Should -Be 'Prod Web App Scan'
    }

    It 'computes AgeHours from start_time' {
        $s = ConvertTo-VcDastScan $script:RunningRaw
        $s.AgeHours   | Should -BeGreaterThan 9
    }

    It 'marks RUNNING scan as stuck when age > 0' {
        $s = ConvertTo-VcDastScan $script:RunningRaw
        $s.IsStuck    | Should -Be $true
    }

    It 'does not mark FINISHED scan as stuck' {
        $s = ConvertTo-VcDastScan $script:FinishedRaw
        $s.IsStuck    | Should -Be $false
    }

    It 'returns -1 AgeHours when start_time is null' {
        $raw = [pscustomobject]@{
            analysis_id='x'; analysis_name='X'; status='SCHEDULED';
            analysis_type='DYNAMIC'; app_id='a'; scan_url=$null;
            start_time=$null; finish_time=$null; finding_count=0; schedule=$null
        }
        $s = ConvertTo-VcDastScan $raw
        $s.AgeHours | Should -Be -1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcDastScans' {
    It 'calls the WAS analyses endpoint' {
        Mock Invoke-VcPagedApi { @($script:RunningRaw, $script:FinishedRaw) } -ParameterFilter {
            $Path -like '*/analyses*'
        }
        $results = Get-VcDastScans
        $results.Count | Should -Be 2
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'passes Status filter in query' {
        Mock Invoke-VcPagedApi { @($script:RunningRaw) } -ParameterFilter {
            $Query -and $Query['status'] -eq 'RUNNING'
        }
        $results = Get-VcDastScans -Status RUNNING
        $results.Count | Should -Be 1
    }

    It 'filters stuck scans with -StuckOnly' {
        Mock Invoke-VcPagedApi { @($script:RunningRaw, $script:QueuedRaw, $script:FinishedRaw) }
        $results = Get-VcDastScans -StuckOnly -ThresholdHours 8
        # RunningRaw is 10h old (stuck), QueuedRaw is 12h old (stuck), FinishedRaw is not in stuck states
        $results.Count | Should -Be 2
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcDastScan' {
    It 'fetches a single analysis by ID' {
        Mock Invoke-VcApi { $script:FinishedRaw } -ParameterFilter {
            $Method -eq 'GET' -and $Path -like '*/ana-002'
        }
        $result = Get-VcDastScan -AnalysisId 'ana-002'
        $result.AnalysisId | Should -Be 'ana-002'
        $result.Status     | Should -Be 'FINISHED'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Start-VcDastScan' {
    It 'PUTs updated schedule with current time' {
        Mock Invoke-VcApi {
            if ($Method -eq 'GET') { return $script:FinishedRaw }
            return $script:FinishedRaw
        }
        Start-VcDastScan -AnalysisId 'ana-002' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter { $Method -eq 'PUT' }
    }

    It 'supports -WhatIf without calling the API' {
        Mock Invoke-VcApi { }
        Start-VcDastScan -AnalysisId 'ana-002' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Stop-VcDastScan' {
    It 'calls DELETE on the scans sub-resource' {
        Mock Invoke-VcApi { }
        Stop-VcDastScan -AnalysisId 'ana-001' -Force -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -like '*/ana-001/scans'
        }
    }

    It 'supports -WhatIf without calling the API' {
        Mock Invoke-VcApi { }
        Stop-VcDastScan -AnalysisId 'ana-001' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-VcDastFinding' {
    It 'extracts URL and HTTP method' {
        $f = ConvertTo-VcDastFinding $script:SqliRaw 'app-111'
        $f.Url        | Should -Be 'https://prod.example.com/api/search?q=1'
        $f.HttpMethod | Should -Be 'GET'
    }

    It 'parses AbsolutePath from URL' {
        $f = ConvertTo-VcDastFinding $script:SqliRaw 'app-111'
        $f.Path | Should -Be '/api/search'
    }

    It 'extracts attack vector and payload' {
        $f = ConvertTo-VcDastFinding $script:SqliRaw 'app-111'
        $f.AttackVector  | Should -Be 'URL Parameter'
        $f.AttackPayload | Should -Not -BeNullOrEmpty
    }

    It 'computes DaysOpen from first_found_date' {
        $f = ConvertTo-VcDastFinding $script:SqliRaw 'app-111'
        $f.DaysOpen | Should -BeGreaterThan 29
    }

    It 'maps severity and CWE' {
        $f = ConvertTo-VcDastFinding $script:SqliRaw 'app-111'
        $f.Severity | Should -Be 5
        $f.CweId    | Should -Be 89
        $f.CweName  | Should -Be 'SQL Injection'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcDastFindings' {
    It 'calls findings endpoint with scan_type=DYNAMIC' {
        Mock Invoke-VcPagedApi { @($script:SqliRaw, $script:XssRaw) } -ParameterFilter {
            $Query -and $Query['scan_type'] -eq 'DYNAMIC'
        }
        $results = Get-VcDastFindings -AppGuid 'app-111'
        $results.Count | Should -Be 2
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'passes severity_gte in query when -MinSeverity is set' {
        Mock Invoke-VcPagedApi { @($script:SqliRaw, $script:XssRaw) } -ParameterFilter {
            $Query -and $Query['severity_gte'] -eq 4
        }
        $results = Get-VcDastFindings -AppGuid 'app-111' -MinSeverity 4
        Should -Invoke Invoke-VcPagedApi -Times 1 -ParameterFilter { $Query -and $Query['severity_gte'] -eq 4 }
    }

    It 'applies URL wildcard filter client-side' {
        Mock Invoke-VcPagedApi { @($script:SqliRaw, $script:XssRaw, $script:InfoRaw) }
        $results = Get-VcDastFindings -AppGuid 'app-111' -Url '*/api/*'
        $results.Count | Should -Be 2   # search and debug are under /api/
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcDastAnalysis' {
    BeforeEach {
        Mock Get-VcDastFindings {
            @(
                (ConvertTo-VcDastFinding $script:SqliRaw  'app-111')
                (ConvertTo-VcDastFinding $script:XssRaw   'app-111')
                (ConvertTo-VcDastFinding $script:InfoRaw  'app-111')
            )
        }
    }

    It 'returns an object with TotalFindings' {
        $r = Get-VcDastAnalysis -AppGuid 'app-111'
        $r.TotalFindings | Should -Be 3
    }

    It 'includes severity breakdown with 6 rows' {
        $r = Get-VcDastAnalysis -AppGuid 'app-111'
        $r.SeverityBreakdown.Count | Should -Be 6
    }

    It 'endpoint heat map has at most Top rows' {
        $r = Get-VcDastAnalysis -AppGuid 'app-111' -Top 2
        $r.EndpointHeatMap.Count | Should -BeLessOrEqual 2
    }

    It 'exports endpoint heat map to CSV' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Get-VcDastAnalysis -AppGuid 'app-111' -Export $tmp
        (Import-Csv $tmp).Count | Should -BeGreaterThan 0
        Remove-Item $tmp -Force
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Compare-VcDastSast' {
    BeforeEach {
        # SAST finding: SQL Injection (CWE 89) and XSS (CWE 79) overlap; only SAST has Information Exposure (CWE 200) via SAST
        Mock Get-VcFindings {
            @(
                [pscustomobject]@{ IssueId=1; ScanType='STATIC'; Severity=5; CweId=89; CweName='SQL Injection' }
                [pscustomobject]@{ IssueId=2; ScanType='STATIC'; Severity=4; CweId=79; CweName='Cross-Site Scripting' }
                [pscustomobject]@{ IssueId=3; ScanType='STATIC'; Severity=3; CweId=22; CweName='Path Traversal' }
            )
        }
        Mock Get-VcDastFindings {
            @(
                (ConvertTo-VcDastFinding $script:SqliRaw 'app-111')   # CWE 89
                (ConvertTo-VcDastFinding $script:XssRaw  'app-111')   # CWE 79
            )
        }
    }

    It 'returns overlapping CWEs flagged as Overlap=$true' {
        $r = Compare-VcDastSast -AppGuid 'app-111'
        $overlaps = @($r.Rows | Where-Object { $_.Overlap })
        $overlaps.Count | Should -Be 2   # CWE 89 and 79 appear in both
    }

    It 'returns SAST-only CWEs with DastCount=0' {
        $r = Compare-VcDastSast -AppGuid 'app-111'
        $sastOnly = @($r.Rows | Where-Object { $_.SastCount -gt 0 -and $_.DastCount -eq 0 })
        $sastOnly.Count | Should -Be 1   # CWE 22 only in SAST
    }

    It 'reports correct overlap count' {
        $r = Compare-VcDastSast -AppGuid 'app-111'
        $r.OverlapCount | Should -Be 2
    }

    It 'exports to CSV' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Compare-VcDastSast -AppGuid 'app-111' -Export $tmp
        (Import-Csv $tmp).Count | Should -BeGreaterThan 0
        Remove-Item $tmp -Force
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Repair-VcDastScan' {
    It 'reports no stuck scans when none are found' {
        Mock Get-VcDastScans { @() }
        $output = Repair-VcDastScan -All 6>&1 4>&1
        $output | Should -Match 'No stuck'
    }

    It 'calls Stop-VcDastScan for each stuck analysis with -Force' {
        Mock Get-VcDastScans {
            @(ConvertTo-VcDastScan $script:RunningRaw)
        }
        Mock Stop-VcDastScan { }
        Repair-VcDastScan -All -Force -Confirm:$false
        Should -Invoke Stop-VcDastScan -Times 1
    }

    It 'handles single -AnalysisId with stuck status' {
        Mock Get-VcDastScan { ConvertTo-VcDastScan $script:RunningRaw }
        Mock Stop-VcDastScan { }
        Repair-VcDastScan -AnalysisId 'ana-001' -Force -Confirm:$false
        Should -Invoke Stop-VcDastScan -Times 1
    }
}
