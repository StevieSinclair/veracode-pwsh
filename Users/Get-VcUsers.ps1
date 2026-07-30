function Get-VcUsers {
    <#
    .SYNOPSIS
        Lists users in the Veracode organisation.
    .PARAMETER Email
        Wildcard filter applied client-side (e.g. 'alice*@example.com').
    .PARAMETER Role
        Return only users who hold this role name.
    .PARAMETER TeamGuid
        Return only users who belong to this team GUID.
    .PARAMETER Inactive
        Return only users with login_enabled = false.
    .EXAMPLE
        Get-VcUsers
        Get-VcUsers -Email '*@acme.com' -Role Administrator
        Get-VcUsers -Inactive
    #>
    [CmdletBinding()]
    param(
        [string]$Email,
        [string]$Role,
        [string]$TeamGuid,
        [switch]$Inactive,
        [string]$Profile = $script:VcCurrentProfile
    )

    $query = @{}
    if ($TeamGuid) { $query['team_id'] = $TeamGuid }

    Write-Verbose 'Fetching all users (paged)...'
    $raw   = Invoke-VcPagedApi -Path '/api/authn/v2/users' -EmbeddedKey 'users' `
                               -Query $query -Profile $Profile
    $users = $raw | ForEach-Object { ConvertTo-VcUser $_ }

    if ($Email)    { $users = $users | Where-Object { $_.Email -like $Email } }
    if ($Role)     { $users = $users | Where-Object { $_.Roles -contains $Role } }
    if ($Inactive) { $users = $users | Where-Object { -not $_.LoginEnabled } }

    return $users
}

function Get-VcUser {
    <#
    .SYNOPSIS
        Gets a single user by user ID or email address.
    .EXAMPLE
        Get-VcUser -UserId 'abc-123'
        Get-VcUser -Email 'alice@example.com'
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string]$UserId,

        [Parameter(Mandatory, ParameterSetName = 'ByEmail')]
        [string]$Email,

        [string]$Profile = $script:VcCurrentProfile
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByEmail') {
        $match = Get-VcUsers -Email $Email -Profile $Profile | Select-Object -First 1
        if (-not $match) { throw "User with email '$Email' not found." }
        return $match
    }

    $raw = Invoke-VcApi -Path "/api/authn/v2/users/$UserId" -Profile $Profile
    return ConvertTo-VcUser $raw
}

# Converts a raw identity API user object to a flat PSCustomObject.
function ConvertTo-VcUser {
    param($Raw)
    [pscustomobject]@{
        UserId        = $Raw.user_id
        Email         = $Raw.email_address
        FirstName     = $Raw.first_name
        LastName      = $Raw.last_name
        LoginEnabled  = $Raw.login_enabled
        SamlUser      = $Raw.saml_user
        UserType      = $Raw.user_type
        LastLoginDate = $Raw.last_login_date
        Roles         = @($Raw.roles | ForEach-Object { $_.role_name })
        Teams         = @($Raw.teams | ForEach-Object { $_.team_name })
        TeamGuids     = @($Raw.teams | ForEach-Object { $_.team_id })
        _Raw          = $Raw
    }
}
