function Remove-VcTeam {
    <#
    .SYNOPSIS
        Deletes a team. Users that belong only to this team lose their team membership.
    .PARAMETER TeamId
        Team ID. Accepts pipeline input from Get-VcTeams.
    .PARAMETER Force
        Bypasses confirmation.
    .EXAMPLE
        Remove-VcTeam -TeamId 'abc'
        Get-VcTeams -Name 'old-*' | Remove-VcTeam -WhatIf
        Get-VcTeams -Name 'old-*' | Remove-VcTeam -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$TeamId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$TeamName,

        [switch]$Force,
        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if ($Force) { $ConfirmPreference = 'None' }

        $label = if ($TeamName) { "'$TeamName' ($TeamId)" } else { $TeamId }
        if (-not $PSCmdlet.ShouldProcess($label, 'Permanently delete team')) { return }

        Write-Verbose "Deleting team $label..."
        Invoke-VcApi -Method DELETE -Path "/api/authn/v2/teams/$TeamId" -Profile $Profile | Out-Null
        Write-Verbose "Team $label deleted."
    }
}
