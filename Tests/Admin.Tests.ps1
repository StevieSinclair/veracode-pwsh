#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'Scans/Get-VcScans.ps1')
    . (Join-Path $ModuleRoot 'Admin/Get-VcAuditLog.ps1')
    . (Join-Path $ModuleRoot 'Admin/Export-VcReport.ps1')

    $script:SampleAuditRaw = [pscustomobject]@{
        id               = 'evt-1'
        event_timestamp  = '2026-07-29T10:00:00Z'
        event_type       = 'USER_CREATED'
        actor_email      = 'admin@acme.com'
        actor_name       = 'Admin User'
        target_user_email = 'newuser@acme.com'
        target_user_name  = 'New User'
        description      = 'User account created'
        ip_address       = '10.0.0.1'
    }

    $script:SampleAppRow = [pscustomobject]@{
        Guid             = 'app-1'
        Name             = 'MyApp'
        PolicyName       = 'PCI Policy'
        PolicyCompliance = 'PASSED'
        LastScanDate     = '2026-07-01'
    }
}

Describe 'Get-VcAuditLog' {
    It 'calls the audit log API and returns structured entries' {
        Mock Invoke-VcPagedApi { @($script:SampleAuditRaw) }
        $entries = Get-VcAuditLog
        $entries.Count          | Should -Be 1
        $entries[0].EventType   | Should -Be 'USER_CREATED'
        $entries[0].ActorEmail  | Should -Be 'admin@acme.com'
    }

    It 'passes date range to the query' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query.ContainsKey('start_date') -and $Query.ContainsKey('end_date')
        }
        $start = (Get-Date).AddDays(-7)
        Get-VcAuditLog -StartDate $start
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'passes user_email filter when specified' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query['user_email'] -eq 'admin@acme.com'
        }
        Get-VcAuditLog -UserEmail 'admin@acme.com'
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'exports to CSV when -Export is given' {
        Mock Invoke-VcPagedApi { @($script:SampleAuditRaw) }
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Get-VcAuditLog -Export $tmp
        $rows = Import-Csv $tmp
        $rows.Count          | Should -Be 1
        $rows[0].EventType   | Should -Be 'USER_CREATED'
        Remove-Item $tmp -Force
    }
}

Describe 'Export-VcReport' {
    BeforeEach {
        Mock Get-VcApplications {
            @(
                [pscustomobject]@{ Guid='app-1'; Name='MyApp';    PolicyName='PCI';  PolicyCompliance='PASSED';       LastScanDate='2026-07-01' }
                [pscustomobject]@{ Guid='app-2'; Name='LegacyApp'; PolicyName='OWASP'; PolicyCompliance='DID_NOT_PASS'; LastScanDate='2026-06-01' }
            )
        }
        Mock Get-VcFindings { @() }
        Mock Get-VcScans    { @() }
    }

    It 'writes a CSV file with one row per application' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Export-VcReport -OutputPath $tmp -Format CSV
        $rows = Import-Csv $tmp
        $rows.Count              | Should -Be 2
        $rows[0].AppName         | Should -Be 'MyApp'
        $rows[1].PolicyCompliance | Should -Be 'DID_NOT_PASS'
        Remove-Item $tmp -Force
    }

    It 'writes an HTML file containing app names' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'
        Export-VcReport -OutputPath $tmp -Format HTML
        $content = Get-Content $tmp -Raw
        $content | Should -Match 'MyApp'
        $content | Should -Match 'LegacyApp'
        $content | Should -Match '<!DOCTYPE html'
        Remove-Item $tmp -Force
    }

    It 'auto-detects HTML format from .html extension' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'
        Export-VcReport -OutputPath $tmp
        $content = Get-Content $tmp -Raw
        $content | Should -Match '<!DOCTYPE html'
        Remove-Item $tmp -Force
    }

    It 'auto-detects CSV format from .csv extension' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Export-VcReport -OutputPath $tmp
        $rows = Import-Csv $tmp
        $rows.Count | Should -Be 2
        Remove-Item $tmp -Force
    }
}

Describe 'New-VcHtmlReport' {
    It 'produces HTML with summary card values' {
        $data = @(
            [pscustomobject]@{ AppName='App1'; PolicyCompliance='PASSED';       PolicyName='P1'; LastScanDate=''; LastScanStatus=''; StuckScans=0; VeryHigh=0; High=1; Medium=2; Low=0; VeryLow=0; Informational=0; TotalFindings=3; GeneratedUtc='' }
            [pscustomobject]@{ AppName='App2'; PolicyCompliance='DID_NOT_PASS'; PolicyName='P2'; LastScanDate=''; LastScanStatus=''; StuckScans=1; VeryHigh=2; High=0; Medium=0; Low=0; VeryLow=0; Informational=0; TotalFindings=2; GeneratedUtc='' }
        )
        $html = New-VcHtmlReport -Title 'Test Report' -Data $data
        $html | Should -Match 'Test Report'
        $html | Should -Match 'App1'
        $html | Should -Match 'App2'
        $html | Should -Match 'DID_NOT_PASS'
    }
}
