#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Users/Get-VcUsers.ps1')
    . (Join-Path $ModuleRoot 'Users/New-VcUser.ps1')
    . (Join-Path $ModuleRoot 'Users/Set-VcUser.ps1')
    . (Join-Path $ModuleRoot 'Users/Remove-VcUser.ps1')
    . (Join-Path $ModuleRoot 'Users/Set-VcUserRoles.ps1')
    . (Join-Path $ModuleRoot 'Users/Export-VcUsers.ps1')

    $script:SampleUserRaw = [pscustomobject]@{
        user_id         = 'user-guid-1'
        email_address   = 'alice@acme.com'
        first_name      = 'Alice'
        last_name       = 'Smith'
        login_enabled   = $true
        saml_user       = $false
        user_type       = 'HUMAN'
        last_login_date = '2026-07-01'
        roles  = @([pscustomobject]@{ role_name = 'Reviewer' }, [pscustomobject]@{ role_name = 'SecurityLead' })
        teams  = @([pscustomobject]@{ team_id = 'team-1'; team_name = 'Alpha' })
    }
}

Describe 'ConvertTo-VcUser' {
    It 'flattens a raw API user response' {
        $user = ConvertTo-VcUser $script:SampleUserRaw
        $user.UserId       | Should -Be 'user-guid-1'
        $user.Email        | Should -Be 'alice@acme.com'
        $user.Roles        | Should -Contain 'Reviewer'
        $user.Roles        | Should -Contain 'SecurityLead'
        $user.Teams        | Should -Contain 'Alpha'
        $user.LoginEnabled | Should -Be $true
    }
}

Describe 'Get-VcUsers' {
    It 'filters by email wildcard client-side' {
        Mock Invoke-VcPagedApi {
            @(
                $script:SampleUserRaw,
                [pscustomobject]@{
                    user_id = 'user-2'; email_address = 'bob@other.com'
                    first_name = 'Bob'; last_name = 'Jones'
                    login_enabled = $true; saml_user = $false; user_type = 'HUMAN'
                    last_login_date = $null; roles = @(); teams = @()
                }
            )
        }
        $results = Get-VcUsers -Email '*@acme.com'
        $results.Count | Should -Be 1
        $results[0].Email | Should -Be 'alice@acme.com'
    }

    It 'filters by role client-side' {
        Mock Invoke-VcPagedApi { @($script:SampleUserRaw) }
        $results = Get-VcUsers -Role 'Reviewer'
        $results.Count | Should -Be 1
    }

    It 'filters inactive users' {
        $inactiveRaw = $script:SampleUserRaw | Select-Object -Property * | ForEach-Object {
            $clone = $_ | Select-Object *
            $clone.login_enabled = $false
            $clone
        }
        Mock Invoke-VcPagedApi { @($script:SampleUserRaw, $inactiveRaw) }
        $results = Get-VcUsers -Inactive
        $results.Count | Should -Be 1
        $results[0].LoginEnabled | Should -Be $false
    }
}

Describe 'New-VcUser' {
    It 'sends POST with correct body structure' {
        Mock Invoke-VcApi { $script:SampleUserRaw }

        $result = New-VcUser -Email 'alice@acme.com' -FirstName 'Alice' -LastName 'Smith' `
                             -Roles 'Reviewer' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'POST' -and
            $Path   -eq '/api/authn/v2/users' -and
            $Body.email_address -eq 'alice@acme.com'
        }
        $result.Email | Should -Be 'alice@acme.com'
    }

    It 'sets user_type to API when -Type API is passed' {
        Mock Invoke-VcApi { $script:SampleUserRaw }

        New-VcUser -Email 'bot@acme.com' -FirstName 'CI' -LastName 'Bot' -Type API -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Body.user_type -eq 'API'
        }
    }

    It 'does nothing with -WhatIf' {
        Mock Invoke-VcApi { }
        New-VcUser -Email 'x@x.com' -FirstName 'X' -LastName 'X' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'Set-VcUser' {
    It 'fetches current state then sends PUT' {
        Mock Invoke-VcApi { $script:SampleUserRaw } -ParameterFilter { $Method -eq 'GET' -or -not $Method }
        Mock Invoke-VcApi { $script:SampleUserRaw } -ParameterFilter { $Method -eq 'PUT' }

        Set-VcUser -UserId 'user-guid-1' -LoginEnabled $false -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'PUT' -and $Body.login_enabled -eq $false
        }
    }

    It 'preserves existing roles when -Roles not specified' {
        Mock Invoke-VcApi { $script:SampleUserRaw }

        Set-VcUser -UserId 'user-guid-1' -LoginEnabled $true -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'PUT' -and $Body.roles.Count -eq 2
        }
    }
}

Describe 'Remove-VcUser' {
    It 'sends DELETE when no -Deactivate' {
        Mock Invoke-VcApi { $null }
        Remove-VcUser -UserId 'user-guid-1' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -eq '/api/authn/v2/users/user-guid-1'
        }
    }

    It 'calls Set-VcUser with LoginEnabled=false when -Deactivate' {
        Mock Invoke-VcApi { $script:SampleUserRaw }
        Mock Set-VcUser { $null }

        Remove-VcUser -UserId 'user-guid-1' -Deactivate -Force
        Should -Invoke Set-VcUser -Times 1 -ParameterFilter {
            $LoginEnabled -eq $false
        }
    }
}

Describe 'Set-VcUserRoles' {
    It 'adds a role without removing existing ones' {
        Mock Invoke-VcApi { $script:SampleUserRaw }
        Mock Set-VcUser { $null }

        Set-VcUserRoles -UserId 'user-guid-1' -AddRoles 'MitigationApprover' -Confirm:$false
        Should -Invoke Set-VcUser -Times 1 -ParameterFilter {
            $Roles -contains 'Reviewer' -and
            $Roles -contains 'SecurityLead' -and
            $Roles -contains 'MitigationApprover'
        }
    }

    It 'removes a role while keeping others' {
        Mock Invoke-VcApi { $script:SampleUserRaw }
        Mock Set-VcUser { $null }

        Set-VcUserRoles -UserId 'user-guid-1' -RemoveRoles 'Reviewer' -Confirm:$false
        Should -Invoke Set-VcUser -Times 1 -ParameterFilter {
            $Roles -notcontains 'Reviewer' -and
            $Roles -contains 'SecurityLead'
        }
    }
}

Describe 'Export-VcUsers' {
    It 'writes a CSV file with the correct columns' {
        Mock Get-VcUsers { @(ConvertTo-VcUser $script:SampleUserRaw) }

        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Export-VcUsers -OutputPath $tmp
        $rows = Import-Csv $tmp
        $rows[0].Email     | Should -Be 'alice@acme.com'
        $rows[0].Roles     | Should -Be 'Reviewer; SecurityLead'
        Remove-Item $tmp -Force
    }
}
