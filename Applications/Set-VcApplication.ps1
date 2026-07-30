function Set-VcApplication {
    <#
    .SYNOPSIS
        Updates an existing application's profile. Fetches current state and merges supplied changes.
    .PARAMETER Guid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER Name
        New display name.
    .PARAMETER BusinessCriticality
        New business criticality.
    .PARAMETER PolicyGuid
        Replace the assigned policy.
    .PARAMETER TeamGuids
        Replace all team assignments. Pass an empty array to remove all teams.
    .PARAMETER BusinessUnitGuid
        Replace the business unit assignment.
    .PARAMETER Description
        Update the description.
    .EXAMPLE
        Set-VcApplication -Guid 'abc' -Name 'NewName'
        Get-VcApplications -Name 'Old*' | Set-VcApplication -BusinessCriticality LOW
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Guid,

        [string]$Name,
        [ValidateSet('VERY_HIGH','HIGH','MEDIUM','LOW','VERY_LOW')]
        [string]$BusinessCriticality,
        [string]$PolicyGuid,
        [string[]]$TeamGuids,
        [string]$BusinessUnitGuid,
        [string]$Description,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # Fetch current state to build a complete PUT body (Veracode uses full-replace PUT).
        Write-Verbose "Fetching current state for application $Guid..."
        $current = Invoke-VcApi -Path "/appsec/v1/applications/$Guid" -Profile $Profile
        $p = $current.profile

        $updatedProfile = @{
            name                 = if ($Name)                { $Name }                else { $p.name }
            business_criticality = if ($BusinessCriticality) { $BusinessCriticality } else { $p.business_criticality }
        }

        # Description — only set if explicitly provided; preserve existing otherwise
        $desc = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $p.description }
        if ($desc) { $updatedProfile['description'] = $desc }

        # Business unit
        $buGuid = if ($PSBoundParameters.ContainsKey('BusinessUnitGuid')) {
            $BusinessUnitGuid
        } elseif ($p.business_unit.guid) {
            $p.business_unit.guid
        }
        if ($buGuid) { $updatedProfile['business_unit'] = @{ guid = $buGuid } }

        # Policy
        $policyGuidValue = if ($PSBoundParameters.ContainsKey('PolicyGuid')) {
            $PolicyGuid
        } elseif ($p.policies) {
            ($p.policies | Select-Object -First 1).guid
        }
        if ($policyGuidValue) { $updatedProfile['policies'] = @(@{ guid = $policyGuidValue }) }

        # Teams
        if ($PSBoundParameters.ContainsKey('TeamGuids')) {
            $updatedProfile['teams'] = @($TeamGuids | ForEach-Object { @{ guid = $_ } })
        } elseif ($p.teams) {
            $updatedProfile['teams'] = @($p.teams | ForEach-Object { @{ guid = $_.guid } })
        }

        $body = @{ profile = $updatedProfile }

        if (-not $PSCmdlet.ShouldProcess($Guid, 'Update Veracode application')) { return }

        Write-Verbose "Updating application $Guid..."
        $raw = Invoke-VcApi -Method PUT -Path "/appsec/v1/applications/$Guid" -Body $body -Profile $Profile
        return ConvertTo-VcApplication $raw
    }
}
