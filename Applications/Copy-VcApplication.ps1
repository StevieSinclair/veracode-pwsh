function Copy-VcApplication {
    <#
    .SYNOPSIS
        Creates a new application by cloning the profile of an existing one.
        Copies: business criticality, policy, teams, business unit, and description.
    .PARAMETER SourceGuid
        GUID of the application to clone.
    .PARAMETER NewName
        Name for the new application.
    .PARAMETER PolicyGuid
        Override the policy GUID (if omitted, uses the source app's policy).
    .EXAMPLE
        Copy-VcApplication -SourceGuid 'abc' -NewName 'MyApp-v2'
        Copy-VcApplication -SourceGuid 'abc' -NewName 'MyApp-sandbox' -PolicyGuid 'none'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourceGuid,

        [Parameter(Mandatory)]
        [string]$NewName,

        [string]$PolicyGuid,

        [string]$Profile = $script:VcCurrentProfile
    )

    Write-Verbose "Fetching source application '$SourceGuid'..."
    $source = Get-VcApplication -Guid $SourceGuid -Profile $Profile

    if (-not $source) {
        throw "Source application '$SourceGuid' not found."
    }

    $effectivePolicyGuid = if ($PSBoundParameters.ContainsKey('PolicyGuid')) { $PolicyGuid } else { $source.PolicyGuid }

    $cloneParams = @{
        Name                = $NewName
        BusinessCriticality = $source.BusinessCriticality
        Profile             = $Profile
    }
    if ($effectivePolicyGuid)     { $cloneParams['PolicyGuid']      = $effectivePolicyGuid }
    if ($source.Description)      { $cloneParams['Description']     = $source.Description }
    if ($source.TeamGuids)        { $cloneParams['TeamGuids']        = $source.TeamGuids }
    if ($source.BusinessUnitGuid) { $cloneParams['BusinessUnitGuid'] = $source.BusinessUnitGuid }

    if (-not $PSCmdlet.ShouldProcess($NewName, "Clone application from '$($source.Name)'")) { return }

    Write-Verbose "Creating clone '$NewName' from '$($source.Name)'..."
    $new = New-VcApplication @cloneParams -Confirm:$false
    Write-Host "Cloned '$($source.Name)' → '$NewName' (GUID: $($new.Guid))"
    return $new
}
