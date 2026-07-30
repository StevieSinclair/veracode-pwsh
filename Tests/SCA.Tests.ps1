#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'SCA/Get-VcScaFindings.ps1')
    . (Join-Path $ModuleRoot 'SCA/Get-VcScaLibrarySummary.ps1')
    . (Join-Path $ModuleRoot 'SCA/Get-VcScaUpgrades.ps1')
    . (Join-Path $ModuleRoot 'SCA/Get-VcScaLicenses.ps1')
    . (Join-Path $ModuleRoot 'SCA/Get-VcScaExposure.ps1')

    # Raw SCA API payloads (as the REST API would return them)
    $script:Log4jRaw = [pscustomobject]@{
        issue_id  = 201
        scan_type = 'SCA'
        severity  = 5
        cwe_id    = 937
        finding_details = [pscustomobject]@{
            component_filename = 'log4j-core-2.14.1.jar'
            component_version  = '2.14.1'
            fixed_version      = '2.17.0'
            cvss_score         = 10.0
            cvss3_score        = 10.0
            cve_ids            = @('CVE-2021-44228')
            cwe                = [pscustomobject]@{ id=937; name='Using Components with Known Vulnerabilities' }
            license            = [pscustomobject]@{ name='Apache 2.0'; risk_level='LOW' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-15).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }

    $script:SpringRaw = [pscustomobject]@{
        issue_id  = 202
        scan_type = 'SCA'
        severity  = 4
        cwe_id    = 937
        finding_details = [pscustomobject]@{
            component_filename = 'spring-core-5.3.0.jar'
            component_version  = '5.3.0'
            fixed_version      = '5.3.18'
            cvss_score         = 7.5
            cvss3_score        = 7.5
            cve_ids            = @('CVE-2022-22965')
            cwe                = [pscustomobject]@{ id=937; name='Using Components with Known Vulnerabilities' }
            license            = [pscustomobject]@{ name='Apache 2.0'; risk_level='LOW' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-5).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }

    $script:GplRaw = [pscustomobject]@{
        issue_id  = 203
        scan_type = 'SCA'
        severity  = 2
        cwe_id    = 937
        finding_details = [pscustomobject]@{
            component_filename = 'gpl-lib-1.0.0.jar'
            component_version  = '1.0.0'
            fixed_version      = $null
            cvss_score         = 3.0
            cvss3_score        = 3.0
            cve_ids            = @()
            cwe                = [pscustomobject]@{ id=937; name='Using Components with Known Vulnerabilities' }
            license            = [pscustomobject]@{ name='GPL-3.0'; risk_level='HIGH' }
        }
        finding_status = [pscustomobject]@{
            status                   = 'OPEN'
            mitigation_review_status = 'NONE'
            first_found_date         = [DateTimeOffset]::UtcNow.AddDays(-30).ToString('o')
            last_seen_date           = [DateTimeOffset]::UtcNow.ToString('o')
        }
        annotations = @()
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-VcScaFinding' {
    It 'flattens library and CVE fields' {
        $f = ConvertTo-VcScaFinding $script:Log4jRaw 'app-1'
        $f.Library       | Should -Be 'log4j-core-2.14.1.jar'
        $f.Version       | Should -Be '2.14.1'
        $f.FixedInVersion | Should -Be '2.17.0'
        $f.HasFix        | Should -Be $true
        $f.CvssScore     | Should -Be 10.0
    }

    It 'extracts CVE list as array and string' {
        $f = ConvertTo-VcScaFinding $script:Log4jRaw 'app-1'
        $f.CveIds        | Should -Contain 'CVE-2021-44228'
        $f.CveList       | Should -Be 'CVE-2021-44228'
    }

    It 'extracts license info' {
        $f = ConvertTo-VcScaFinding $script:Log4jRaw 'app-1'
        $f.LicenseName   | Should -Be 'Apache 2.0'
        $f.LicenseRisk   | Should -Be 'LOW'
    }

    It 'computes MaxCvss as max of CVSS2 and CVSS3' {
        $f = ConvertTo-VcScaFinding $script:Log4jRaw 'app-1'
        $f.MaxCvss       | Should -Be 10.0
    }

    It 'handles missing fix version gracefully' {
        $f = ConvertTo-VcScaFinding $script:GplRaw 'app-1'
        $f.HasFix        | Should -Be $false
        $f.FixedInVersion | Should -BeNullOrEmpty
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcScaFindings' {
    It 'calls the SCA findings endpoint with scan_type=SCA' {
        Mock Invoke-VcPagedApi { @($script:Log4jRaw, $script:SpringRaw) } -ParameterFilter {
            $Query -and $Query['scan_type'] -eq 'SCA'
        }
        $results = Get-VcScaFindings -AppGuid 'app-1'
        $results.Count | Should -Be 2
        Should -Invoke Invoke-VcPagedApi -Times 1
    }

    It 'filters by MinCvss' {
        Mock Invoke-VcPagedApi { @($script:Log4jRaw, $script:SpringRaw, $script:GplRaw) }
        $results = Get-VcScaFindings -AppGuid 'app-1' -MinCvss 7.0
        $results.Count | Should -Be 2   # Log4j (10.0) and Spring (7.5) pass; GPL (3.0) fails
    }

    It 'filters by LicenseRisk' {
        Mock Invoke-VcPagedApi { @($script:Log4jRaw, $script:SpringRaw, $script:GplRaw) }
        $results = Get-VcScaFindings -AppGuid 'app-1' -LicenseRisk HIGH
        $results.Count | Should -Be 1
        $results[0].Library | Should -Be 'gpl-lib-1.0.0.jar'
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcScaLibrarySummary' {
    BeforeEach {
        Mock Get-VcScaFindings {
            @(
                (ConvertTo-VcScaFinding $script:Log4jRaw  'app-1')
                (ConvertTo-VcScaFinding $script:SpringRaw 'app-1')
                (ConvertTo-VcScaFinding $script:GplRaw    'app-1')
            )
        }
    }

    It 'returns one row per distinct library+version' {
        $rows = Get-VcScaLibrarySummary -AppGuid 'app-1'
        $rows.Count | Should -Be 3
    }

    It 'marks log4j as having a fix' {
        $rows = Get-VcScaLibrarySummary -AppGuid 'app-1'
        $log4j = $rows | Where-Object { $_.Library -like '*log4j*' }
        $log4j.HasFix | Should -Be $true
        $log4j.FixedInVersion | Should -Be '2.17.0'
    }

    It 'exports to CSV' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Get-VcScaLibrarySummary -AppGuid 'app-1' -Export $tmp
        $rows = Import-Csv $tmp
        $rows.Count | Should -Be 3
        Remove-Item $tmp -Force
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcScaUpgrades' {
    BeforeEach {
        Mock Get-VcScaFindings {
            @(
                (ConvertTo-VcScaFinding $script:Log4jRaw  'app-1')
                (ConvertTo-VcScaFinding $script:SpringRaw 'app-1')
                (ConvertTo-VcScaFinding $script:GplRaw    'app-1')   # no fix
            )
        }
    }

    It 'returns only libraries with known fix versions' {
        $rows = Get-VcScaUpgrades -AppGuid 'app-1'
        $rows.Count | Should -Be 2   # Log4j and Spring have fixes; GPL does not
    }

    It 'assigns CRITICAL priority to log4j (CVSS 10)' {
        $rows = Get-VcScaUpgrades -AppGuid 'app-1'
        $log4j = $rows | Where-Object { $_.Library -like '*log4j*' }
        $log4j.Priority | Should -Be 'CRITICAL'
    }

    It 'assigns HIGH priority to spring (CVSS 7.5)' {
        $rows = Get-VcScaUpgrades -AppGuid 'app-1'
        $spring = $rows | Where-Object { $_.Library -like '*spring*' }
        $spring.Priority | Should -Be 'HIGH'
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcScaLicenses' {
    BeforeEach {
        Mock Get-VcScaFindings {
            @(
                (ConvertTo-VcScaFinding $script:Log4jRaw  'app-1')
                (ConvertTo-VcScaFinding $script:GplRaw    'app-1')
            )
        }
    }

    It 'returns distinct library+license entries' {
        $rows = Get-VcScaLicenses -AppGuid 'app-1'
        $rows.Count | Should -Be 2
    }

    It 'identifies the GPL library as HIGH risk' {
        $rows = Get-VcScaLicenses -AppGuid 'app-1'
        $gpl = $rows | Where-Object { $_.RiskLevel -eq 'HIGH' }
        $gpl.Library | Should -Be 'gpl-lib-1.0.0.jar'
    }

    It 'filters by -RiskLevel' {
        $rows = Get-VcScaLicenses -AppGuid 'app-1' -RiskLevel HIGH
        $rows.Count | Should -Be 1
    }

    It 'exports to CSV' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Get-VcScaLicenses -AppGuid 'app-1' -Export $tmp
        (Import-Csv $tmp).Count | Should -Be 2
        Remove-Item $tmp -Force
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcScaExposure' {
    It 'identifies a library appearing in multiple apps' {
        Mock Get-VcApplications {
            @(
                [pscustomobject]@{ Guid='app-1'; Name='AppOne' }
                [pscustomobject]@{ Guid='app-2'; Name='AppTwo' }
            )
        }
        Mock Get-VcScaFindings {
            @(ConvertTo-VcScaFinding $script:Log4jRaw $AppGuid)
        }

        $rows = Get-VcScaExposure -MinAppCount 2
        $log4j = $rows | Where-Object { $_.Library -like '*log4j*' }
        $log4j | Should -Not -BeNullOrEmpty
        $log4j.AppCount | Should -Be 2
    }

    It 'marks library as critical when CVSS >= 7 in 3+ apps' {
        Mock Get-VcApplications {
            @(
                [pscustomobject]@{ Guid='app-1'; Name='App1' }
                [pscustomobject]@{ Guid='app-2'; Name='App2' }
                [pscustomobject]@{ Guid='app-3'; Name='App3' }
            )
        }
        Mock Get-VcScaFindings {
            @(ConvertTo-VcScaFinding $script:Log4jRaw $AppGuid)
        }

        $rows = Get-VcScaExposure -MinAppCount 3
        $log4j = $rows | Where-Object { $_.Library -like '*log4j*' }
        $log4j.IsCritical | Should -Be $true
    }

    It 'respects -MinCvss filter' {
        Mock Get-VcApplications {
            @(
                [pscustomobject]@{ Guid='app-1'; Name='App1' }
                [pscustomobject]@{ Guid='app-2'; Name='App2' }
            )
        }
        # When MinCvss >= 7.0 is passed, return nothing (GPL CVSS is only 3.0)
        Mock Get-VcScaFindings { @() } -ParameterFilter { $MinCvss -ge 7.0 }
        # Without a MinCvss filter, return the GPL finding
        Mock Get-VcScaFindings { @(ConvertTo-VcScaFinding $script:GplRaw $AppGuid) }

        $rows = Get-VcScaExposure -MinCvss 7.0 -MinAppCount 2
        # GPL CVSS is 3.0 so is filtered out by Get-VcScaFindings before exposure aggregation
        $gpl = $rows | Where-Object { $_.Library -like '*gpl*' }
        $gpl | Should -BeNullOrEmpty
    }
}
