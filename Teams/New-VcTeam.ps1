function New-VcTeam {
    <#
    .SYNOPSIS
        Creates a new team.
    .PARAMETER Name
        Team display name.
    .PARAMETER BusinessUnitId
        Optional GUID of the business unit to associate with the team.
    .EXAMPLE
        New-VcTeam -Name 'Platform Security'
        New-VcTeam -Name 'Mobile Team' -BusinessUnitId 'bu-guid'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string]$BusinessUnitId,
        [string]$Profile = $script:VcCurrentProfile
    )

    $teamBody = @{ team_name = $Name }
    if ($BusinessUnitId) { $teamBody['business_unit'] = @{ bu_id = $BusinessUnitId } }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create team')) { return }

    Write-Verbose "Creating team '$Name'..."
    $raw = Invoke-VcApi -Method POST -Path '/api/authn/v2/teams' -Body $teamBody -Profile $Profile
    return ConvertTo-VcTeam $raw
}
