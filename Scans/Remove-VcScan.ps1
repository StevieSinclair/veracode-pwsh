function Remove-VcScan {
    <#
    .SYNOPSIS
        Deletes a specific scan (build). The scan must not be in RESULTS_READY state
        unless -Force is supplied.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER ScanId
        Scan ID to delete. Accepts pipeline input from Get-VcScans.
    .PARAMETER SandboxGuid
        When provided, targets the sandbox scan endpoint instead of the policy scan endpoint.
    .PARAMETER LegacyAppId
        Legacy numeric application ID. Used as a fallback when the REST scan endpoint is
        unavailable — falls back to the XML API deletebuild.do.
    .PARAMETER Force
        Bypasses confirmation and allows deletion of completed (RESULTS_READY) scans.
    .EXAMPLE
        Remove-VcScan -AppGuid 'abc' -ScanId '123'
        Get-VcScans -AppGuid 'abc' -StuckOnly | Remove-VcScan -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ScanId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SandboxGuid,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('LegacyId')]
        [int]$LegacyAppId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Status,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if ($Force) { $ConfirmPreference = 'None' }

        # Guard: completed scans should not be deleted without explicit -Force
        if ($Status -eq 'RESULTS_READY' -and -not $Force) {
            Write-Warning "Scan $ScanId is in RESULTS_READY state (completed). Use -Force to delete a completed scan."
            return
        }

        $label = "Scan $ScanId (app: $AppGuid)"
        if (-not $PSCmdlet.ShouldProcess($label, 'Delete scan')) { return }

        $restPath = if ($SandboxGuid) {
            "/appsec/v1/applications/$AppGuid/sandboxes/$SandboxGuid/scans/$ScanId"
        } else {
            "/appsec/v1/applications/$AppGuid/scans/$ScanId"
        }

        try {
            Write-Verbose "Deleting scan via REST: $restPath"
            Invoke-VcApi -Method DELETE -Path $restPath -Profile $Profile | Out-Null
            Write-Verbose "Scan $ScanId deleted."
        } catch {
            # If the REST endpoint returns 404/405/501, fall back to XML deletebuild.do
            if ($_ -match 'HTTP (404|405|501)' -and $LegacyAppId) {
                Write-Verbose "REST delete unavailable (HTTP $($Matches[1])). Falling back to XML API deletebuild.do..."
                $xmlParams = @{ app_id = $LegacyAppId }
                if ($SandboxGuid) { $xmlParams['sandbox_id'] = $SandboxGuid }
                Invoke-VcXmlApi -Path '/api/5.0/deletebuild.do' -Params $xmlParams -Method POST -Profile $Profile | Out-Null
                Write-Verbose "Scan deleted via XML API deletebuild.do."
            } else {
                throw
            }
        }
    }
}
