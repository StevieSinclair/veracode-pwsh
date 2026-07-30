#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Users/Get-VcUsers.ps1')   # needed by Set-VcTeamMembers
    . (Join-Path $ModuleRoot 'Teams/Get-VcTeams.ps1')
    . (Join-Path $ModuleRoot 'Teams/New-VcTeam.ps1')
    . (Join-Path $ModuleRoot 'Teams/Set-VcTeamMembers.ps1')
    . (Join-Path $ModuleRoot 'Teams/Remove-VcTeam.ps1')

    $script:SampleTeamRaw = [pscustomobject]@{
        team_id       = 'team-guid-1'
        team_name     = 'Alpha'
        business_unit = [pscustomobject]@{ bu_id = 'bu-1'; bu_name = 'Engineering' }
        users         = @(
            [pscustomobject]@{ user_id = 'u1'; user_name = 'alice@acme.com' }
            [pscustomobject]@{ user_id = 'u2'; user_name = 'bob@acme.com'   }
        )
    }

    $script:EmptyTeamRaw = [pscustomobject]@{
        team_id       = 'team-guid-2'
        team_name     = 'Beta'
        business_unit = [pscustomobject]@{ bu_id = $null; bu_name = $null }
        users         = @()
    }
}

Describe 'ConvertTo-VcTeam' {
    It 'flattens a raw API team response' {
        $team = ConvertTo-VcTeam $script:SampleTeamRaw
        $team.TeamId       | Should -Be 'team-guid-1'
        $team.TeamName     | Should -Be 'Alpha'
        $team.BusinessUnit | Should -Be 'Engineering'
        $team.MemberCount  | Should -Be 2
        $team.Members[0].UserId | Should -Be 'u1'
    }

    It 'handles a team with no members' {
        $team = ConvertTo-VcTeam $script:EmptyTeamRaw
        $team.MemberCount | Should -Be 0
        $team.Members     | Should -BeNullOrEmpty
    }
}

Describe 'Get-VcTeams' {
    It 'returns all teams when no filter given' {
        Mock Invoke-VcPagedApi { @($script:SampleTeamRaw, $script:EmptyTeamRaw) }
        $teams = Get-VcTeams
        $teams.Count | Should -Be 2
    }

    It 'filters by name wildcard client-side' {
        Mock Invoke-VcPagedApi { @($script:SampleTeamRaw, $script:EmptyTeamRaw) }
        $teams = Get-VcTeams -Name 'Alpha*'
        $teams.Count    | Should -Be 1
        $teams[0].TeamName | Should -Be 'Alpha'
    }
}

Describe 'New-VcTeam' {
    It 'sends POST to the correct endpoint' {
        Mock Invoke-VcApi { $script:SampleTeamRaw }
        New-VcTeam -Name 'Alpha' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'POST' -and $Path -eq '/api/authn/v2/teams'
        }
    }

    It 'includes business unit when specified' {
        Mock Invoke-VcApi { $script:SampleTeamRaw }
        New-VcTeam -Name 'Alpha' -BusinessUnitId 'bu-1' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Body.ContainsKey('business_unit') -and $Body.business_unit.bu_id -eq 'bu-1'
        }
    }

    It 'does nothing with -WhatIf' {
        Mock Invoke-VcApi { }
        New-VcTeam -Name 'Test' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'Set-VcTeamMembers' {
    It 'adds a user ID without removing existing members' {
        # GET (fetch current team)
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -ne 'PUT' }
        # PUT (update team)
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -eq 'PUT' }

        Set-VcTeamMembers -TeamId 'team-guid-1' -AddUserIds 'u3' -Confirm:$false

        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'PUT' -and
            ($Body.users | ForEach-Object { $_.user_id }) -contains 'u1' -and
            ($Body.users | ForEach-Object { $_.user_id }) -contains 'u3'
        }
    }

    It 'removes a user ID without affecting others' {
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -ne 'PUT' }
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -eq 'PUT' }

        Set-VcTeamMembers -TeamId 'team-guid-1' -RemoveUserIds 'u1' -Confirm:$false

        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'PUT' -and
            ($Body.users | ForEach-Object { $_.user_id }) -notcontains 'u1' -and
            ($Body.users | ForEach-Object { $_.user_id }) -contains 'u2'
        }
    }

    It 'does not add a user who is already a member' {
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -ne 'PUT' }
        Mock Invoke-VcApi { $script:SampleTeamRaw } -ParameterFilter { $Method -eq 'PUT' }

        Set-VcTeamMembers -TeamId 'team-guid-1' -AddUserIds 'u1' -Confirm:$false

        # u1 already exists; final list should still only have 2 entries (u1, u2)
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'PUT' -and $Body.users.Count -eq 2
        }
    }
}

Describe 'Remove-VcTeam' {
    It 'sends DELETE to the correct endpoint' {
        Mock Invoke-VcApi { $null }
        Remove-VcTeam -TeamId 'team-guid-1' -TeamName 'Alpha' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -eq '/api/authn/v2/teams/team-guid-1'
        }
    }

    It 'does nothing with -WhatIf' {
        Mock Invoke-VcApi { }
        Remove-VcTeam -TeamId 'x' -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}
