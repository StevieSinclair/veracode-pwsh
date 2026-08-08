function New-VcApplication {
    <#
    .SYNOPSIS
        Creates a new application in Veracode.
    .PARAMETER Name
        Application name (must be unique within the org).
    .PARAMETER BusinessCriticality
        Risk level: VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW.
    .PARAMETER PolicyGuid
        GUID of the policy to assign. If omitted the org default policy is applied.
    .PARAMETER TeamGuids
        One or more team GUIDs to associate with the application.
    .PARAMETER BusinessUnitGuid
        GUID of the business unit.
    .PARAMETER Description
        Optional description.
    .EXAMPLE
        New-VcApplication -Name 'MyApp' -BusinessCriticality HIGH
        New-VcApplication -Name 'MyApp' -BusinessCriticality MEDIUM -PolicyGuid 'abc' -TeamGuids 'guid1','guid2'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('VERY_HIGH','HIGH','MEDIUM','LOW','VERY_LOW')]
        [string]$BusinessCriticality,

        [string]$PolicyGuid,
        [string[]]$TeamGuids,
        [string]$BusinessUnitGuid,
        [string]$Description,

        [string]$Profile = $script:VcCurrentProfile
    )

    $appProfile = @{
        name                 = $Name
        business_criticality = $BusinessCriticality
    }

    if ($Description)      { $appProfile['description']   = $Description }
    if ($BusinessUnitGuid) { $appProfile['business_unit'] = @{ guid = $BusinessUnitGuid } }
    if ($PolicyGuid)       { $appProfile['policies']      = @(@{ guid = $PolicyGuid }) }
    if ($TeamGuids)        { $appProfile['teams']         = @($TeamGuids | ForEach-Object { @{ guid = $_ } }) }

    $body = @{ profile = $appProfile }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create Veracode application')) { return }

    Write-Verbose "Creating application '$Name'..."
    $raw = Invoke-VcApi -Method POST -Path '/appsec/v1/applications' -Body $body -Profile $Profile
    $app = ConvertTo-VcApplication $raw
    Write-Verbose "Created application '$Name' with GUID $($app.Guid)."
    return $app
}

function Import-VcApplications {
    <#
    .SYNOPSIS
        Bulk-creates applications from a CSV file.
    .DESCRIPTION
        CSV columns: Name (required), BusinessCriticality (required), PolicyGuid, BusinessUnitGuid,
        TeamGuids (semicolon-separated GUIDs), Description.
    .EXAMPLE
        Import-VcApplications -CsvPath .\apps.csv
        Import-VcApplications -CsvPath .\apps.csv -WhatIf
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
    $errors  = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $rows) {
        if (-not $row.Name -or -not $row.BusinessCriticality) {
            $errors.Add("Skipped row — missing Name or BusinessCriticality: $($row | ConvertTo-Json -Compress)")
            $failed++
            continue
        }

        $params = @{
            Name                = $row.Name
            BusinessCriticality = $row.BusinessCriticality
            Profile             = $Profile
        }
        if ($row.PolicyGuid)       { $params['PolicyGuid']       = $row.PolicyGuid }
        if ($row.BusinessUnitGuid) { $params['BusinessUnitGuid'] = $row.BusinessUnitGuid }
        if ($row.Description)      { $params['Description']      = $row.Description }
        if ($row.TeamGuids) {
            $params['TeamGuids'] = $row.TeamGuids -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }

        try {
            if ($PSCmdlet.ShouldProcess($row.Name, 'Create application')) {
                New-VcApplication @params -Confirm:$false | Out-Null
                $success++
                Write-Host "  [OK] $($row.Name)"
            }
        } catch {
            $failed++
            $errors.Add("  [FAIL] $($row.Name): $_")
            Write-Warning "Failed to create '$($row.Name)': $_"
        }
    }

    Write-Host "`nImport complete: $success created, $failed failed."
    if ($errors.Count -gt 0) {
        Write-Host 'Errors:'
        $errors | ForEach-Object { Write-Host "  $_" }
    }
}
