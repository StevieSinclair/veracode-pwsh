function New-VcUser {
    <#
    .SYNOPSIS
        Creates a new Veracode user (human or API service account).
    .PARAMETER Email
        User's email address (used as the login name).
    .PARAMETER FirstName
        User's first name.
    .PARAMETER LastName
        User's last name.
    .PARAMETER Roles
        One or more role names to assign (e.g. 'Reviewer', 'SecurityLead').
    .PARAMETER TeamGuids
        One or more team GUIDs to assign the user to.
    .PARAMETER Type
        Account type: HUMAN (default) or API.
    .EXAMPLE
        New-VcUser -Email 'alice@acme.com' -FirstName Alice -LastName Smith -Roles 'Reviewer'
        New-VcUser -Email 'ci-bot@acme.com' -FirstName CI -LastName Bot -Roles 'Creator','Submitter' -Type API
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$Email,
        [Parameter(Mandatory)] [string]$FirstName,
        [Parameter(Mandatory)] [string]$LastName,

        [string[]]$Roles,
        [string[]]$TeamGuids,

        [ValidateSet('HUMAN','API')]
        [string]$Type = 'HUMAN',

        [string]$Profile = $script:VcCurrentProfile
    )

    $userBody = @{
        email_address = $Email
        first_name    = $FirstName
        last_name     = $LastName
        user_type     = $Type
        login_enabled = $true
    }

    if ($Roles)     { $userBody['roles'] = @($Roles     | ForEach-Object { @{ role_name = $_ } }) }
    if ($TeamGuids) { $userBody['teams'] = @($TeamGuids | ForEach-Object { @{ team_id   = $_ } }) }

    if (-not $PSCmdlet.ShouldProcess($Email, 'Create Veracode user')) { return }

    Write-Verbose "Creating user '$Email'..."
    $raw = Invoke-VcApi -Method POST -Path '/api/authn/v2/users' -Body $userBody -Profile $Profile
    return ConvertTo-VcUser $raw
}

function Import-VcUsers {
    <#
    .SYNOPSIS
        Bulk-creates users from a CSV file.
    .DESCRIPTION
        CSV columns: Email (required), FirstName (required), LastName (required),
        Roles (semicolon-separated), TeamGuids (semicolon-separated), Type (HUMAN or API).
    .EXAMPLE
        Import-VcUsers -CsvPath .\users.csv
        Import-VcUsers -CsvPath .\users.csv -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CsvPath,

        [string]$Profile = $script:VcCurrentProfile
    )

    $rows    = Import-Csv -Path $CsvPath
    $success = 0
    $failed  = 0

    foreach ($row in $rows) {
        if (-not $row.Email -or -not $row.FirstName -or -not $row.LastName) {
            Write-Warning "Skipping row — missing Email, FirstName, or LastName: $($row | ConvertTo-Json -Compress)"
            $failed++
            continue
        }

        $params = @{
            Email     = $row.Email
            FirstName = $row.FirstName
            LastName  = $row.LastName
            Profile   = $Profile
        }
        if ($row.Type)      { $params['Type']      = $row.Type }
        if ($row.Roles)     { $params['Roles']     = $row.Roles     -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
        if ($row.TeamGuids) { $params['TeamGuids'] = $row.TeamGuids -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

        try {
            if ($PSCmdlet.ShouldProcess($row.Email, 'Create user')) {
                New-VcUser @params -Confirm:$false | Out-Null
                $success++
                Write-Host "  [OK] $($row.Email)"
            }
        } catch {
            $failed++
            Write-Warning "  [FAIL] $($row.Email): $_"
        }
    }

    Write-Host "`nImport complete: $success created, $failed failed."
}
