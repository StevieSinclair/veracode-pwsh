function Set-VcTeamMembers {
    <#
    .SYNOPSIS
        Adds or removes users from a team without replacing the entire member list.
    .DESCRIPTION
        Users can be specified by user ID or by email address. Email addresses are
        resolved to user IDs via Get-VcUser before the team is updated.
        The Veracode team endpoint requires the full member list on PUT, so the
        function fetches the current list, applies the delta, then writes it back.
    .PARAMETER TeamId
        Team ID. Accepts pipeline input from Get-VcTeams.
    .PARAMETER AddUserIds
        User IDs to add to the team.
    .PARAMETER RemoveUserIds
        User IDs to remove from the team.
    .PARAMETER AddEmails
        Email addresses to add — resolved to user IDs automatically.
    .PARAMETER RemoveEmails
        Email addresses to remove — resolved to user IDs automatically.
    .EXAMPLE
        Set-VcTeamMembers -TeamId 'abc' -AddEmails 'alice@acme.com','bob@acme.com'
        Get-VcTeams -Name 'Dev*' | Set-VcTeamMembers -RemoveEmails 'ex-employee@acme.com'
        Set-VcTeamMembers -TeamId 'abc' -AddUserIds 'uid1','uid2' -RemoveUserIds 'uid3' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$TeamId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$TeamName,

        [string[]]$AddUserIds,
        [string[]]$RemoveUserIds,
        [string[]]$AddEmails,
        [string[]]$RemoveEmails,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # Resolve emails to user IDs
        $resolvedAdd    = [System.Collections.Generic.List[string]]::new()
        $resolvedRemove = [System.Collections.Generic.List[string]]::new()

        if ($AddUserIds)    { $resolvedAdd.AddRange([string[]]$AddUserIds) }
        if ($RemoveUserIds) { $resolvedRemove.AddRange([string[]]$RemoveUserIds) }

        foreach ($email in $AddEmails) {
            $user = Get-VcUser -Email $email -Profile $Profile
            $resolvedAdd.Add($user.UserId)
        }
        foreach ($email in $RemoveEmails) {
            $user = Get-VcUser -Email $email -Profile $Profile
            $resolvedRemove.Add($user.UserId)
        }

        # Fetch current team to get existing member list
        Write-Verbose "Fetching current members of team $TeamId..."
        $current = Invoke-VcApi -Path "/api/authn/v2/teams/$TeamId" -Profile $Profile

        $currentIds = @($current.users | ForEach-Object { $_.user_id })

        # Apply delta using array operations (avoids .NET collection constructor issues)
        $kept   = if ($resolvedRemove.Count -gt 0) {
                      @($currentIds | Where-Object { $_ -notin $resolvedRemove })
                  } else { $currentIds }
        $added  = if ($resolvedAdd.Count -gt 0) {
                      @($resolvedAdd | Where-Object { $_ -notin $currentIds })
                  } else { @() }
        $newIds = @($kept) + @($added)

        $teamBody = @{
            team_name = $current.team_name
            users     = @($newIds | ForEach-Object { @{ user_id = $_ } })
        }
        if ($current.business_unit.bu_id) {
            $teamBody['business_unit'] = @{ bu_id = $current.business_unit.bu_id }
        }

        $label = if ($TeamName) { "'$TeamName' ($TeamId)" } else { $TeamId }
        if (-not $PSCmdlet.ShouldProcess($label, 'Update team members')) { return }

        Write-Verbose "Updating team $label — $($newIds.Count) member(s)..."
        $raw = Invoke-VcApi -Method PUT -Path "/api/authn/v2/teams/$TeamId" -Body $teamBody -Profile $Profile
        return ConvertTo-VcTeam $raw
    }
}
