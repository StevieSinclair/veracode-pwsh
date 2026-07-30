function Invoke-VcPolicyEvaluation {
    <#
    .SYNOPSIS
        Triggers a policy compliance evaluation for an application and returns the result.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER PolicyGuid
        Optional override policy GUID. If omitted the application's assigned policy is used.
    .EXAMPLE
        Invoke-VcPolicyEvaluation -AppGuid 'abc'
        Invoke-VcPolicyEvaluation -AppGuid 'abc' -PolicyGuid 'pol-guid'
        Get-VcApplications | Invoke-VcPolicyEvaluation
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [string]$PolicyGuid,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $body = @{}
        if ($PolicyGuid) { $body['policy_guid'] = $PolicyGuid }

        if (-not $PSCmdlet.ShouldProcess($AppGuid, 'Run policy evaluation')) { return }

        Write-Verbose "Running policy evaluation for application '$AppGuid'..."
        $raw = Invoke-VcApi -Method POST -Path "/appsec/v1/applications/$AppGuid/policy_evaluations" -Body $body -Profile $Profile

        [pscustomobject]@{
            AppGuid          = $AppGuid
            PolicyGuid       = $(if ($null -ne $raw.policy) { $raw.policy.guid } else { $null })
            PolicyName       = $(if ($null -ne $raw.policy) { $raw.policy.name } else { $null })
            PolicyCompliance = $raw.policy_compliance_status
            Passed           = ($raw.policy_compliance_status -eq 'PASSED')
            ScanDate         = $raw.last_policy_compliance_check_date
            _Raw             = $raw
        }
    }
}

function Get-VcApplicationCompliance {
    <#
    .SYNOPSIS
        Returns current policy compliance status for one or all applications.
    .PARAMETER AppGuid
        Application GUID. If omitted, checks all applications.
    .PARAMETER PolicyNonCompliantOnly
        Return only applications that did not pass their policy.
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcApplicationCompliance
        Get-VcApplicationCompliance -PolicyNonCompliantOnly
        Get-VcApplicationCompliance -AppGuid 'abc'
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single')]
        [string]$AppGuid,

        [Parameter(ParameterSetName = 'All')]
        [switch]$PolicyNonCompliantOnly,

        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $apps = @(Get-VcApplication -Guid $AppGuid -Profile $Profile)
    } else {
        $getParams = @{ Profile = $Profile }
        if ($PolicyNonCompliantOnly) { $getParams['PolicyCompliance'] = 'DID_NOT_PASS' }
        $apps = Get-VcApplications @getParams
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $i = 0

    foreach ($app in $apps) {
        $i++
        if ($apps.Count -gt 1) {
            Write-Progress -Activity 'Checking policy compliance' `
                           -Status "$($app.Name) ($i / $($apps.Count))" `
                           -PercentComplete ([int](($i / $apps.Count) * 100))
        }

        $results.Add([pscustomobject]@{
            AppName          = $app.Name
            AppGuid          = $app.Guid
            PolicyName       = $app.PolicyName
            PolicyCompliance = $app.PolicyCompliance
            LastScanDate     = $app.LastScanDate
            Passed           = ($app.PolicyCompliance -eq 'PASSED')
        })
    }

    if ($apps.Count -gt 1) {
        Write-Progress -Activity 'Checking policy compliance' -Completed
    }

    $output = $results.ToArray()
    if ($Export) {
        $output | Export-Csv -Path $Export -NoTypeInformation
        Write-Host "Compliance report exported to '$Export'."
    }

    return $output
}
