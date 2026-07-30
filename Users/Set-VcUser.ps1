function Set-VcUser {
    <#
    .SYNOPSIS
        Updates a user's roles, team assignments, or login status.
        Fetches the current user state and merges in the supplied changes.
    .PARAMETER UserId
        User ID. Accepts pipeline input from Get-VcUsers.
    .PARAMETER Roles
        Replacement role list. Replaces all current roles.
    .PARAMETER TeamGuids
        Replacement team list (by GUID). Replaces all current teams.
    .PARAMETER LoginEnabled
        Enable or disable the account. Cannot be changed for SAML users.
    .EXAMPLE
        Set-VcUser -UserId 'abc' -LoginEnabled $false
        Get-VcUsers -Email 'alice*' | Set-VcUser -Roles 'Reviewer','SecurityLead'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$UserId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Email,

        [string[]]$Roles,
        [string[]]$TeamGuids,
        [Nullable[bool]]$LoginEnabled,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        Write-Verbose "Fetching current state for user $UserId..."
        $current = Invoke-VcApi -Path "/api/authn/v2/users/$UserId" -Profile $Profile

        $userBody = @{
            email_address = $current.email_address
            first_name    = $current.first_name
            last_name     = $current.last_name
            user_type     = $current.user_type
            login_enabled = $(if ($PSBoundParameters.ContainsKey('LoginEnabled')) { $LoginEnabled } else { $current.login_enabled })
        }

        $userBody['roles'] = if ($PSBoundParameters.ContainsKey('Roles')) {
            @($Roles | ForEach-Object { @{ role_name = $_ } })
        } else {
            @($current.roles)
        }

        $userBody['teams'] = if ($PSBoundParameters.ContainsKey('TeamGuids')) {
            @($TeamGuids | ForEach-Object { @{ team_id = $_ } })
        } else {
            @($current.teams | ForEach-Object { @{ team_id = $_.team_id } })
        }

        $label = if ($Email) { "$Email ($UserId)" } else { $UserId }
        if (-not $PSCmdlet.ShouldProcess($label, 'Update user')) { return }

        Write-Verbose "Updating user $label..."
        $raw = Invoke-VcApi -Method PUT -Path "/api/authn/v2/users/$UserId" -Body $userBody -Profile $Profile
        return ConvertTo-VcUser $raw
    }
}
