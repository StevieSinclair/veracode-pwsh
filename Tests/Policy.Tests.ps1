#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Policy/Get-VcPolicies.ps1')
    . (Join-Path $ModuleRoot 'Policy/Invoke-VcPolicyEvaluation.ps1')

    $script:SamplePolicyRaw = [pscustomobject]@{
        guid                      = 'pol-guid-1'
        name                      = 'PCI Policy'
        description               = 'Compliance for PCI DSS'
        policy_compliance_driver  = 'CUSTOMER'
        scan_frequency_days       = 90
        grace_period_days         = 30
        custom_severity           = $null
        finding_rules             = @(
            [pscustomobject]@{
                type              = 'FAIL_ON_SEVERITY'
                scan_type         = 'STATIC'
                severity          = 4
                grace_period_days = 30
            }
        )
        created  = '2024-01-01T00:00:00Z'
        modified = '2024-06-15T00:00:00Z'
    }

    $script:BuiltinPolicyRaw = [pscustomobject]@{
        guid                      = 'pol-guid-2'
        name                      = 'Veracode Recommended Very High'
        description               = 'Veracode built-in policy'
        policy_compliance_driver  = 'VERACODE'
        scan_frequency_days       = 365
        grace_period_days         = 90
        custom_severity           = $null
        finding_rules             = @()
        created  = '2020-01-01T00:00:00Z'
        modified = '2020-01-01T00:00:00Z'
    }
}

Describe 'ConvertTo-VcPolicy' {
    It 'flattens a customer policy correctly' {
        $p = ConvertTo-VcPolicy $script:SamplePolicyRaw
        $p.PolicyGuid        | Should -Be 'pol-guid-1'
        $p.PolicyName        | Should -Be 'PCI Policy'
        $p.Type              | Should -Be 'CUSTOMER'
        $p.ScanFrequencyDays | Should -Be 90
        $p.GracePeriodDays   | Should -Be 30
        $p.FindingRuleCount  | Should -Be 1
    }

    It 'converts finding rules correctly' {
        $p = ConvertTo-VcPolicy $script:SamplePolicyRaw
        $p.FindingRules[0].Severity | Should -Be 4
        $p.FindingRules[0].ScanType | Should -Be 'STATIC'
    }

    It 'handles a policy with no finding rules' {
        $p = ConvertTo-VcPolicy $script:BuiltinPolicyRaw
        $p.FindingRuleCount | Should -Be 0
        $p.Type             | Should -Be 'VERACODE'
    }
}

Describe 'Get-VcPolicies' {
    It 'returns all policies when no filter given' {
        Mock Invoke-VcPagedApi { @($script:SamplePolicyRaw, $script:BuiltinPolicyRaw) }
        $policies = Get-VcPolicies
        $policies.Count | Should -Be 2
    }

    It 'filters by name wildcard client-side' {
        Mock Invoke-VcPagedApi { @($script:SamplePolicyRaw, $script:BuiltinPolicyRaw) }
        $policies = Get-VcPolicies -Name 'PCI*'
        $policies.Count         | Should -Be 1
        $policies[0].PolicyName | Should -Be 'PCI Policy'
    }

    It 'passes type filter to query' {
        Mock Invoke-VcPagedApi { @($script:SamplePolicyRaw) } -ParameterFilter {
            $Query -and $Query['policy_compliance'] -eq 'CUSTOMER'
        }
        $policies = Get-VcPolicies -Type CUSTOMER
        Should -Invoke Invoke-VcPagedApi -Times 1
    }
}

Describe 'Get-VcPolicy' {
    It 'fetches a single policy by GUID' {
        Mock Invoke-VcApi { $script:SamplePolicyRaw } -ParameterFilter {
            $Method -eq 'GET' -and $Path -eq '/appsec/v1/policies/pol-guid-1'
        }
        $p = Get-VcPolicy -PolicyGuid 'pol-guid-1'
        $p.PolicyGuid | Should -Be 'pol-guid-1'
        Should -Invoke Invoke-VcApi -Times 1
    }
}

Describe 'Invoke-VcPolicyEvaluation' {
    It 'posts to the correct endpoint' {
        Mock Invoke-VcApi {
            [pscustomobject]@{
                policy                          = [pscustomobject]@{ guid = 'pol-1'; name = 'PCI Policy' }
                policy_compliance_status        = 'PASSED'
                last_policy_compliance_check_date = '2026-07-30T00:00:00Z'
            }
        } -ParameterFilter {
            $Method -eq 'POST' -and $Path -eq '/appsec/v1/applications/app-1/policy_evaluations'
        }

        $result = Invoke-VcPolicyEvaluation -AppGuid 'app-1' -Confirm:$false
        $result.Passed           | Should -Be $true
        $result.PolicyCompliance | Should -Be 'PASSED'
        Should -Invoke Invoke-VcApi -Times 1
    }

    It 'includes PolicyGuid in body when supplied' {
        Mock Invoke-VcApi {
            [pscustomobject]@{
                policy                          = [pscustomobject]@{ guid = 'pol-2'; name = 'Other' }
                policy_compliance_status        = 'DID_NOT_PASS'
                last_policy_compliance_check_date = '2026-07-30T00:00:00Z'
            }
        } -ParameterFilter {
            $Method -eq 'POST' -and $Body.ContainsKey('policy_guid') -and $Body['policy_guid'] -eq 'pol-2'
        }

        $result = Invoke-VcPolicyEvaluation -AppGuid 'app-1' -PolicyGuid 'pol-2' -Confirm:$false
        $result.Passed | Should -Be $false
        Should -Invoke Invoke-VcApi -Times 1
    }

    It 'does nothing with -WhatIf' {
        Mock Invoke-VcApi { }
        Invoke-VcPolicyEvaluation -AppGuid 'app-1' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'Get-VcApplicationCompliance' {
    It 'returns compliance row for a single app' {
        Mock Get-VcApplication {
            [pscustomobject]@{
                Guid             = 'app-1'
                Name             = 'MyApp'
                PolicyName       = 'PCI Policy'
                PolicyCompliance = 'PASSED'
                LastScanDate     = '2026-07-01'
            }
        }
        $result = Get-VcApplicationCompliance -AppGuid 'app-1'
        $result.AppGuid | Should -Be 'app-1'
        $result.Passed  | Should -Be $true
    }

    It 'returns rows for all apps' {
        Mock Get-VcApplications {
            @(
                [pscustomobject]@{ Guid='app-1'; Name='App1'; PolicyName='P1'; PolicyCompliance='PASSED';       LastScanDate='2026-07-01' }
                [pscustomobject]@{ Guid='app-2'; Name='App2'; PolicyName='P1'; PolicyCompliance='DID_NOT_PASS'; LastScanDate='2026-06-01' }
            )
        }
        $results = Get-VcApplicationCompliance
        $results.Count                 | Should -Be 2
        $results[1].PolicyCompliance   | Should -Be 'DID_NOT_PASS'
        $results[1].Passed             | Should -Be $false
    }
}
