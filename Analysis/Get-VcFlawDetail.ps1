function Get-VcFlawDetail {
    <#
    .SYNOPSIS
        Retrieves deep flaw context for a specific finding: source file, line, call chain,
        or attack vector/URL for dynamic findings.
    .PARAMETER AppGuid
        Application GUID.
    .PARAMETER IssueId
        Finding issue ID (from Get-VcFindings).
    .PARAMETER SandboxGuid
        If the finding is from a sandbox scan.
    .EXAMPLE
        Get-VcFlawDetail -AppGuid 'abc' -IssueId 101
        Get-VcFindings -AppGuid 'abc' | Where-Object Severity -ge 4 | Select-Object -First 1 |
            ForEach-Object { Get-VcFlawDetail -AppGuid $_.AppGuid -IssueId $_.IssueId }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppGuid,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$IssueId,

        [string]$SandboxGuid,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        # First fetch the finding summary to know scan type
        $query = @{}
        if ($SandboxGuid) { $query['context'] = $SandboxGuid }

        $findingPath = "/appsec/v2/applications/$AppGuid/findings/$IssueId"

        $finding = $null
        try {
            $finding = Invoke-VcApi -Method GET -Path $findingPath -Query $query -Profile $Profile
        } catch {
            Write-Warning "Could not fetch finding $IssueId`: $_"
            return
        }

        # Attempt to get detailed flaw info (static or dynamic)
        $detail = $null
        $detailType = if ($finding.scan_type -eq 'DYNAMIC') { 'dynamic_flaw_info' } else { 'static_flaw_info' }

        try {
            $detail = Invoke-VcApi -Method GET -Path "$findingPath/$detailType" -Query $query -Profile $Profile
        } catch {
            Write-Verbose "No $detailType available for finding $IssueId (may not be supported for this scan type)."
        }

        $result = [pscustomobject]@{
            IssueId         = $IssueId
            AppGuid         = $AppGuid
            ScanType        = $finding.scan_type
            Severity        = $finding.severity
            SeverityLabel   = $script:VcSeverityLabels[[int]$finding.severity]
            CweId           = $finding.cwe_id
            CweName         = $finding.finding_details?.cwe?.name
            FileName        = $finding.finding_details?.file_name
            LineNumber      = $finding.finding_details?.file_line_number
            AttackVector    = $finding.finding_details?.attack_vector
            FlawStatus      = $finding.finding_status?.status
            MitigationStatus = $finding.finding_status?.mitigation_review_status
            # Static detail
            FunctionName    = $detail?.function_name
            QualifiedFunctionName = $detail?.qualified_function_name
            CallStack       = $detail?.call_stack
            # Dynamic detail
            Url             = $detail?.url
            HttpMethod      = $detail?.http_method
            AttackPayload   = $detail?.attack_payload
            _DetailRaw      = $detail
        }

        Write-Host ""
        Write-Host "  ── Finding $IssueId ──────────────────────────────────────────" -ForegroundColor DarkCyan
        Write-Host "  Severity : $($result.SeverityLabel) ($($result.Severity))" -ForegroundColor $(if ($result.Severity -ge 4) { 'Red' } elseif ($result.Severity -eq 3) { 'Yellow' } else { 'White' })
        Write-Host "  CWE      : $($result.CweId) — $($result.CweName)"
        Write-Host "  Status   : $($result.FlawStatus)  Mitigation: $($result.MitigationStatus)"

        if ($result.ScanType -eq 'DYNAMIC') {
            Write-Host "  URL      : $($result.Url)"
            Write-Host "  Method   : $($result.HttpMethod)"
            if ($result.AttackVector) { Write-Host "  Vector   : $($result.AttackVector)" }
        } else {
            Write-Host "  File     : $($result.FileName):$($result.LineNumber)"
            if ($result.FunctionName) { Write-Host "  Function : $($result.FunctionName)" }
            if ($result.QualifiedFunctionName) { Write-Host "  FQ Name  : $($result.QualifiedFunctionName)" }
            if ($result.CallStack) {
                Write-Host ""
                Write-Host "  Call Stack:" -ForegroundColor DarkCyan
                $result.CallStack | ForEach-Object {
                    Write-Host "    → $($_.function_name)  [$($_.file_path):$($_.line_number)]" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""

        return $result
    }
}
