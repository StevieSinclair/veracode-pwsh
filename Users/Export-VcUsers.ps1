function Export-VcUsers {
    <#
    .SYNOPSIS
        Exports the full user roster to a CSV file.
    .PARAMETER OutputPath
        Destination file path (e.g. .\users.csv).
    .PARAMETER Email
        Optional wildcard to export only matching users.
    .PARAMETER Role
        Optional role filter.
    .PARAMETER Inactive
        Export only deactivated accounts.
    .EXAMPLE
        Export-VcUsers -OutputPath .\all-users.csv
        Export-VcUsers -OutputPath .\inactive.csv -Inactive
        Export-VcUsers -OutputPath .\reviewers.csv -Role Reviewer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$Email,
        [string]$Role,
        [switch]$Inactive,

        [string]$Profile = $script:VcCurrentProfile
    )

    $params = @{ Profile = $Profile }
    if ($Email)    { $params['Email']    = $Email }
    if ($Role)     { $params['Role']     = $Role }
    if ($Inactive) { $params['Inactive'] = $true }

    Write-Verbose 'Fetching users...'
    $users = Get-VcUsers @params

    # Flatten array properties for CSV compatibility
    $users |
        Select-Object UserId, Email, FirstName, LastName, LoginEnabled, SamlUser, UserType,
                      LastLoginDate,
                      @{ N = 'Roles';  E = { $_.Roles  -join '; ' } },
                      @{ N = 'Teams';  E = { $_.Teams  -join '; ' } } |
        Export-Csv -Path $OutputPath -NoTypeInformation

    Write-Host "Exported $($users.Count) user(s) to '$OutputPath'."
}
