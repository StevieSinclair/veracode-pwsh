#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'Findings/Export-VcFindings.ps1')

    $script:NowUtc = [DateTimeOffset]::UtcNow

    # A high-severity static finding open for 45 days
    $script:SampleFindingRaw = [pscustomobject]@{
        issue_id  = 101
        scan_type = 'STATIC'
        severity  = 4
        cwe_id    = 89
        finding_details = [pscustomobject]@{
            file_name        = 'Dao.java'
            file_line_number = 42
            attack_vector    = 'Network'
            cwe              = [pscustomobject]@{ id = 89; name = 'SQL Injection' }
            finding_category = [pscustomobject]@{ id = 22; name = 'SQL Injection' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = $script:NowUtc.AddDays(-45).ToString('o')
            last_seen_date           = $script:NowUtc.ToString('o')
        }
        annotations = @()
    }

    # A very-high severity SCA finding
    $script:ScaFindingRaw = [pscustomobject]@{
        issue_id  = 202
        scan_type = 'SCA'
        severity  = 5
        cwe_id    = 937
        finding_details = [pscustomobject]@{
            file_name        = 'pom.xml'
            file_line_number = $null
            attack_vector    = $null
            cwe              = [pscustomobject]@{ id = 937; name = 'Using Components with Known Vulnerabilities' }
            finding_category = [pscustomobject]@{ id = 86; name = 'Third-party component vulnerabilities' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'PROPOSED'
            first_found_date         = $script:NowUtc.AddDays(-10).ToString('o')
            last_seen_date           = $script:NowUtc.ToString('o')
        }
        annotations = @()
    }
}

Describe 'ConvertTo-VcFinding' {
    It 'flattens a static finding correctly' {
        $f = ConvertTo-VcFinding $script:SampleFindingRaw 'app-1'
        $f.IssueId       | Should -Be 101
        $f.AppGuid       | Should -Be 'app-1'
        $f.Severity      | Should -Be 4
        $f.SeverityLabel | Should -Be 'High'
        $f.CweId         | Should -Be 89
        $f.CweName       | Should -Be 'SQL Injection'
        $f.FileName      | Should -Be 'Dao.java'
        $f.LineNumber    | Should -Be 42
        $f.FlawStatus    | Should -Be 'OPEN'
        $f.DaysOpen      | Should -BeGreaterThan 44
    }

    It 'maps severity label correctly for all levels' {
        $labels = @{ 0 = 'Informational'; 1 = 'Very Low'; 2 = 'Low'
                     3 = 'Medium';        4 = 'High';     5 = 'Very High' }

        foreach ($sev in 0..5) {
            $raw = $script:SampleFindingRaw | Select-Object *
            $raw.severity = $sev
            $f = ConvertTo-VcFinding $raw 'app-1'
            $f.SeverityLabel | Should -Be $labels[$sev]
        }
    }

    It 'handles SCA finding without line number' {
        $f = ConvertTo-VcFinding $script:ScaFindingRaw 'app-1'
        $f.ScanType   | Should -Be 'SCA'
        $f.LineNumber | Should -BeNullOrEmpty
    }
}

Describe 'Get-VcFindings' {
    It 'passes scan_type to the query' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query['scan_type'] -eq 'STATIC'
        }
        Get-VcFindings -AppGuid 'app-1' -ScanType STATIC
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'passes severity_gte to the query' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query['severity_gte'] -eq 4
        }
        Get-VcFindings -AppGuid 'app-1' -MinSeverity 4
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'passes context param for sandbox findings' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query['context'] -eq 'sb-1'
        }
        Get-VcFindings -AppGuid 'app-1' -SandboxGuid 'sb-1'
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'returns converted findings objects' {
        Mock Invoke-VcPagedApi { @($script:SampleFindingRaw, $script:ScaFindingRaw) }
        $results = Get-VcFindings -AppGuid 'app-1'
        $results.Count | Should -Be 2
        $results | ForEach-Object { $_.AppGuid | Should -Be 'app-1' }
    }

    It 'accepts pipeline input from Get-VcApplications' {
        Mock Invoke-VcPagedApi { @($script:SampleFindingRaw) }
        $app = [pscustomobject]@{ Guid = 'app-1'; Name = 'MyApp' }
        $results = $app | Get-VcFindings
        $results.Count | Should -Be 1
    }
}

Describe 'Get-VcFindingAge' {
    It 'marks a finding past the grace period as overdue' {
        Mock Get-VcFindings { @(ConvertTo-VcFinding $script:SampleFindingRaw 'app-1') }
        $results = Get-VcFindingAge -AppGuid 'app-1' -GracePeriodDays 30
        $results[0].IsOverdue  | Should -Be $true    # 45 days open, 30-day grace
        $results[0].DaysUntilDue | Should -BeLessThan 0
    }

    It 'marks a finding within the grace period as not overdue' {
        Mock Get-VcFindings { @(ConvertTo-VcFinding $script:ScaFindingRaw 'app-1') }
        $results = Get-VcFindingAge -AppGuid 'app-1' -GracePeriodDays 30
        $results[0].IsOverdue | Should -Be $false    # only 10 days open
    }

    It 'marks a finding due within 14 days as IsDueSoon' {
        Mock Get-VcFindings { @(ConvertTo-VcFinding $script:ScaFindingRaw 'app-1') }
        # 10 days open, 30-day grace → 20 days left → not DueSoon (needs ≤14 days left)
        $results = Get-VcFindingAge -AppGuid 'app-1' -GracePeriodDays 24
        # 24 - 10 = 14 days left → IsDueSoon = true
        $results[0].IsDueSoon | Should -Be $true
    }
}

Describe 'Export-VcFindings' {
    It 'writes a CSV file with findings columns' {
        Mock Get-VcFindings { @(
            ConvertTo-VcFinding $script:SampleFindingRaw 'app-1'
            ConvertTo-VcFinding $script:ScaFindingRaw 'app-1'
        )}
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Export-VcFindings -AppGuid 'app-1' -OutputPath $tmp
        $rows = Import-Csv $tmp
        $rows.Count      | Should -Be 2
        $rows[0].IssueId | Should -Be '101'
        $rows[0].CweName | Should -Be 'SQL Injection'
        Remove-Item $tmp -Force
    }

    It 'writes a JSON file when -Format JSON' {
        Mock Get-VcFindings { @(ConvertTo-VcFinding $script:SampleFindingRaw 'app-1') }
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.json'
        Export-VcFindings -AppGuid 'app-1' -OutputPath $tmp -Format JSON
        $data = Get-Content $tmp | ConvertFrom-Json
        $data.Count      | Should -Be 1
        $data[0].IssueId | Should -Be 101
        Remove-Item $tmp -Force
    }
}
