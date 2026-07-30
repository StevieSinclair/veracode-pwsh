#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    # Dot-source core layer
    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')

    # Dot-source domain files
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Applications/New-VcApplication.ps1')
    . (Join-Path $ModuleRoot 'Applications/Set-VcApplication.ps1')
    . (Join-Path $ModuleRoot 'Applications/Remove-VcApplication.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Get-VcSandboxes.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/New-VcSandbox.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Set-VcSandbox.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Remove-VcSandbox.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Invoke-VcSandboxPromotion.ps1')

    # Sample raw API payloads
    $script:SampleAppRaw = [pscustomobject]@{
        guid = 'app-guid-1'
        id   = 12345
        profile = [pscustomobject]@{
            name                    = 'MyApp'
            description             = 'A test app'
            business_criticality    = 'HIGH'
            policy_compliance_status = 'PASSED'
            last_completed_scan_date = '2026-07-01'
            policies = @([pscustomobject]@{ guid = 'pol-guid'; name = 'Default Policy' })
            teams    = @([pscustomobject]@{ guid = 'team-guid'; team_name = 'Alpha' })
            business_unit = [pscustomobject]@{ guid = 'bu-guid'; name = 'Engineering' }
        }
    }

    $script:SampleSandboxRaw = [pscustomobject]@{
        guid          = 'sb-guid-1'
        name          = 'feature-branch'
        sandbox_type  = 'Development'
        auto_recreate = $false
        modified_date = '2026-07-20'
        custom_fields = $null
    }
}

Describe 'ConvertTo-VcApplication' {
    It 'flattens a raw API response into a PSCustomObject' {
        $app = ConvertTo-VcApplication $script:SampleAppRaw
        $app.Guid              | Should -Be 'app-guid-1'
        $app.LegacyId          | Should -Be 12345
        $app.Name              | Should -Be 'MyApp'
        $app.PolicyCompliance  | Should -Be 'PASSED'
        $app.BusinessUnit      | Should -Be 'Engineering'
        $app.Teams             | Should -Be 'Alpha'
        $app.PolicyName        | Should -Be 'Default Policy'
    }
}

Describe 'Get-VcApplications' {
    It 'filters by name wildcard client-side' {
        Mock Invoke-VcPagedApi {
            @($script:SampleAppRaw, [pscustomobject]@{
                guid = 'other-guid'
                id   = 99
                profile = [pscustomobject]@{
                    name = 'OtherApp'
                    description = ''
                    business_criticality = 'LOW'
                    policy_compliance_status = 'NOT_ASSESSED'
                    last_completed_scan_date = $null
                    policies = @()
                    teams = @()
                    business_unit = [pscustomobject]@{ guid = ''; name = '' }
                }
            })
        }
        $results = Get-VcApplications -Name 'MyApp*'
        $results.Count | Should -Be 1
        $results[0].Name | Should -Be 'MyApp'
    }

    It 'passes PolicyCompliance filter to the query' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Query -and $Query['policy_compliance_status'] -eq 'DID_NOT_PASS'
        }
        Get-VcApplications -PolicyCompliance DID_NOT_PASS
        Should -Invoke Invoke-VcPagedApi -Times 1
    }
}

Describe 'New-VcApplication' {
    It 'sends a POST with the correct body structure' {
        Mock Invoke-VcApi { $script:SampleAppRaw }

        $result = New-VcApplication -Name 'TestApp' -BusinessCriticality HIGH -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'POST' -and $Path -eq '/appsec/v1/applications'
        }
        $result.Name | Should -Be 'MyApp'
    }

    It 'includes optional fields when provided' {
        Mock Invoke-VcApi { $script:SampleAppRaw }

        New-VcApplication -Name 'App' -BusinessCriticality LOW `
            -PolicyGuid 'p1' -BusinessUnitGuid 'bu1' -TeamGuids 't1','t2' `
            -Description 'desc' -Confirm:$false

        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Body.profile.ContainsKey('policies') -and
            $Body.profile.ContainsKey('business_unit') -and
            $Body.profile.ContainsKey('teams')
        }
    }

    It 'does nothing when -WhatIf is passed' {
        Mock Invoke-VcApi { }
        New-VcApplication -Name 'App' -BusinessCriticality LOW -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'Remove-VcApplication' {
    It 'sends DELETE to the correct path' {
        Mock Invoke-VcApi { $null }
        Remove-VcApplication -Guid 'app-guid-1' -Name 'MyApp' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -eq '/appsec/v1/applications/app-guid-1'
        }
    }

    It 'does nothing when -WhatIf is passed' {
        Mock Invoke-VcApi { }
        Remove-VcApplication -Guid 'x' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'ConvertTo-VcSandbox' {
    It 'flattens a raw sandbox API response' {
        $sb = ConvertTo-VcSandbox $script:SampleSandboxRaw 'app-guid-1'
        $sb.SandboxGuid  | Should -Be 'sb-guid-1'
        $sb.AppGuid      | Should -Be 'app-guid-1'
        $sb.Name         | Should -Be 'feature-branch'
        $sb.AutoRecreate | Should -Be $false
    }
}

Describe 'New-VcSandbox' {
    It 'sends POST to the correct sandbox endpoint' {
        Mock Invoke-VcApi { $script:SampleSandboxRaw }
        New-VcSandbox -AppGuid 'app-guid-1' -Name 'sprint-42' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'POST' -and $Path -eq '/appsec/v1/applications/app-guid-1/sandboxes'
        }
    }
}

Describe 'Remove-VcSandbox' {
    It 'sends DELETE to the correct sandbox endpoint' {
        Mock Invoke-VcApi { $null }
        Remove-VcSandbox -AppGuid 'app-guid-1' -SandboxGuid 'sb-guid-1' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -like '*/sandboxes/sb-guid-1'
        }
    }
}

Describe 'Invoke-VcSandboxPromotion' {
    It 'sends POST to the promote endpoint' {
        Mock Invoke-VcApi { $null }
        Invoke-VcSandboxPromotion -AppGuid 'app-guid-1' -SandboxGuid 'sb-guid-1' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'POST' -and $Path -like '*/promote'
        }
    }
}
