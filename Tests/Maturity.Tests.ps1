#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Scans/Get-VcScans.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcApplicationMaturity.ps1')

    # A well-configured application (should score high)
    $script:MatureApp = [pscustomobject]@{
        Guid             = 'app-mature'
        Name             = 'MatureApp'
        PolicyCompliance = 'PASSED'
        PolicyName       = 'PCI Compliance Policy'
        LastScanDate     = [DateTime]::UtcNow.AddDays(-10).ToString('o')
        BusinessCriticality = 'HIGH'
        PolicyGuid       = 'pol-1'
        Description      = ''
        BusinessUnitGuid = $null
        TeamGuids        = @()
    }

    # A neglected application (should score low)
    $script:NeglectedApp = [pscustomobject]@{
        Guid             = 'app-neglected'
        Name             = 'NeglectedApp'
        PolicyCompliance = 'NOT_ASSESSED'
        PolicyName       = $null
        LastScanDate     = $null
        BusinessCriticality = 'LOW'
        PolicyGuid       = $null
        Description      = ''
        BusinessUnitGuid = $null
        TeamGuids        = @()
    }

    $script:StaticScan = [pscustomobject]@{
        ScanId = 's1'; AppGuid = 'app-mature'; ScanType = 'STATIC'
        Status = 'RESULTS_READY'; SubmittedDate = [DateTimeOffset]::UtcNow.AddDays(-10).ToString('o')
        AgeHours = 240; IsStuck = $false; SandboxGuid = $null
    }
    $script:ScaScan = [pscustomobject]@{
        ScanId = 's2'; AppGuid = 'app-mature'; ScanType = 'SCA'
        Status = 'RESULTS_READY'; SubmittedDate = [DateTimeOffset]::UtcNow.AddDays(-10).ToString('o')
        AgeHours = 240; IsStuck = $false; SandboxGuid = $null
    }
    $script:DastScan = [pscustomobject]@{
        ScanId = 's3'; AppGuid = 'app-mature'; ScanType = 'DYNAMIC'
        Status = 'RESULTS_READY'; SubmittedDate = [DateTimeOffset]::UtcNow.AddDays(-10).ToString('o')
        AgeHours = 240; IsStuck = $false; SandboxGuid = $null
    }

    # A Medium-severity finding with approved mitigation
    $script:MedFinding = [pscustomobject]@{
        IssueId           = 1; AppGuid = 'app-mature'; Severity = 3; SeverityLabel = 'Medium'
        CweId = 79; CweName = 'XSS'; FileName = 'foo.java'; LineNumber = 10
        FlawStatus = 'OPEN'; MitigationStatus = 'APPROVED'; DaysOpen = 5
    }
}

Describe 'Get-VcApplicationMaturity — mature app' {
    BeforeEach {
        Mock Get-VcApplication { $script:MatureApp }
        Mock Get-VcScans       { @($script:StaticScan, $script:ScaScan, $script:DastScan) }
        Mock Get-VcFindings    { @($script:MedFinding) }
    }

    It 'scores scan coverage = 3 for Static+SCA+DAST' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.ScanCoverage | Should -Be 3
        $result.HasStatic    | Should -Be $true
        $result.HasSca       | Should -Be $true
        $result.HasDynamic   | Should -Be $true
    }

    It 'scores scan recency = 3 for a scan 10 days ago' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.ScanRecency | Should -Be 3
    }

    It 'scores policy compliance = 3 for PASSED with named policy' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.PolicyCompliance | Should -Be 3
    }

    It 'scores finding profile = 1 for open findings all Medium or lower' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.FindingProfile | Should -Be 1
    }

    It 'scores remediation activity = 2 for approved mitigation' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.RemediationActivity | Should -Be 2
    }

    It 'reaches Level 4 or 5' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.Level | Should -BeGreaterThan 3
    }
}

Describe 'Get-VcApplicationMaturity — neglected app' {
    BeforeEach {
        Mock Get-VcApplication { $script:NeglectedApp }
        Mock Get-VcScans       { @() }
        Mock Get-VcFindings    { @() }
    }

    It 'scores scan coverage = 0 when no scans' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-neglected'
        $result.ScanCoverage | Should -Be 0
    }

    It 'scores scan recency = 0 when never scanned' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-neglected'
        $result.ScanRecency | Should -Be 0
    }

    It 'scores policy compliance = 0 for NOT_ASSESSED' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-neglected'
        $result.PolicyCompliance | Should -Be 0
    }

    It 'stays at Level 1' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-neglected'
        $result.Level | Should -Be 1
    }

    It 'reports improvements including scan and policy gaps' {
        $result = Get-VcApplicationMaturity -AppGuid 'app-neglected'
        $result.Improvements.Count | Should -BeGreaterThan 0
        $result.Improvements | Should -Contain 'Add STATIC (SAST) scanning'
    }
}

Describe 'Get-VcApplicationMaturity — Very High findings' {
    It 'scores finding profile = -2 when Very High findings are open' {
        $vhFinding = [pscustomobject]@{
            IssueId = 99; Severity = 5; SeverityLabel = 'Very High'
            MitigationStatus = 'NONE'; FlawStatus = 'OPEN'
        }
        Mock Get-VcApplication { $script:MatureApp }
        Mock Get-VcScans       { @($script:StaticScan) }
        Mock Get-VcFindings    { @($vhFinding) }

        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $result.FindingProfile | Should -Be -2
        $result.Improvements   | Should -Contain "Remediate 1 Very High severity finding(s) — policy-blocking"
    }
}

Describe 'Get-VcApplicationMaturity — score math' {
    It 'total score equals sum of all dimensions' {
        Mock Get-VcApplication { $script:MatureApp }
        Mock Get-VcScans       { @($script:StaticScan, $script:ScaScan, $script:DastScan) }
        Mock Get-VcFindings    { @($script:MedFinding) }

        $result = Get-VcApplicationMaturity -AppGuid 'app-mature'
        $expected = $result.ScanCoverage + $result.ScanRecency + $result.PolicyCompliance +
                    $result.FindingProfile + $result.RemediationActivity
        $result.Score | Should -Be $expected
    }
}
