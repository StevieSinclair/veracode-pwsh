function Stop-VcDastScan {
    <#
    .SYNOPSIS
        Stops (cancels) a running DAST scan. The analysis configuration is preserved;
        only the active scan run is terminated.
    .PARAMETER AnalysisId
        The DAST analysis ID. Accepts pipeline input from Get-VcDastScans.
    .PARAMETER Force
        Skip confirmation prompt.
    .EXAMPLE
        Stop-VcDastScan -AnalysisId 'abc-123'
        Get-VcDastScans -StuckOnly | Stop-VcDastScan -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$AnalysisId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [switch]$Force,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        if ($Force) { $ConfirmPreference = 'None' }

        $label = if ($Name) { "'$Name' ($AnalysisId)" } else { $AnalysisId }
        if (-not $PSCmdlet.ShouldProcess($label, 'Stop DAST scan')) { return }

        Write-Verbose "Stopping DAST scan $label..."
        Invoke-VcApi -Method DELETE -Path "/was/configservice/v1/analyses/$AnalysisId/scans" -Profile $Profile | Out-Null
        Write-Host "DAST scan $label stopped."
    }
}
