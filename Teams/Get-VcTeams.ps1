function Get-VcTeams {
    <#
    .SYNOPSIS
        Lists all teams in the Veracode organisation.
    .PARAMETER Name
        Wildcard filter applied client-side (e.g. 'Dev*').
    .EXAMPLE
        Get-VcTeams
        Get-VcTeams -Name 'Platform*'
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Profile = $script:VcCurrentProfile
    )

    Write-Verbose 'Fetching all teams (paged)...'
    $raw   = Invoke-VcPagedApi -Path '/api/authn/v2/teams' -EmbeddedKey 'teams' -Profile $Profile
    $teams = $raw | ForEach-Object { ConvertTo-VcTeam $_ }

    if ($Name) { $teams = $teams | Where-Object { $_.TeamName -like $Name } }

    return $teams
}

function Get-VcTeam {
    <#
    .SYNOPSIS
        Gets a single team by team ID.
    .EXAMPLE
        Get-VcTeam -TeamId 'abc-123'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TeamId,
        [string]$Profile = $script:VcCurrentProfile
    )

    $raw = Invoke-VcApi -Path "/api/authn/v2/teams/$TeamId" -Profile $Profile
    return ConvertTo-VcTeam $raw
}

# Converts a raw identity API team object to a flat PSCustomObject.
function ConvertTo-VcTeam {
    param($Raw)
    [pscustomobject]@{
        TeamId          = $Raw.team_id
        TeamName        = $Raw.team_name
        BusinessUnit    = $Raw.business_unit.bu_name
        BusinessUnitId  = $Raw.business_unit.bu_id
        MemberCount     = $(if ($Raw.users) { @($Raw.users).Count } else { 0 })
        Members         = @($Raw.users | ForEach-Object {
                              [pscustomobject]@{ UserId = $_.user_id; UserName = $_.user_name }
                          })
        _Raw            = $Raw
    }
}
