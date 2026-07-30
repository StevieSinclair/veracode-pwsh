function Get-VcDastFindings {
    <#
    .SYNOPSIS
        Lists DAST (Dynamic Analysis) findings for an application, enriched with
        URL, HTTP method, and attack vector context.
    .PARAMETER AppGuid
        Application GUID. Accepts pipeline input from Get-VcApplications.
    .PARAMETER MinSeverity
        Return only findings with severity >= this value (0-5).
    .PARAMETER Url
        Wildcard filter applied client-side against the finding URL.
    .PARAMETER FlawStatus
        OPEN (default) or CLOSED.
    .EXAMPLE
        Get-VcDastFindings -AppGuid 'abc'
        Get-VcDastFindings -AppGuid 'abc' -MinSeverity 4
        Get-VcDastFindings -AppGuid 'abc' -Url '*/admin/*'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Guid')]
        [string]$AppGuid,

        [ValidateRange(-1,5)]
        [int]$MinSeverity = -1,

        [string]$Url,

        [ValidateSet('OPEN','CLOSED')]
        [string]$FlawStatus = 'OPEN',

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        $query = @{ scan_type = 'DYNAMIC'; finding_status = $FlawStatus }
        if ($MinSeverity -ge 0) { $query['severity_gte'] = $MinSeverity }

        $raw      = Invoke-VcPagedApi -Path "/appsec/v2/applications/$AppGuid/findings" `
                                      -EmbeddedKey 'findings' -Query $query -Profile $Profile
        $findings = @($raw | ForEach-Object { ConvertTo-VcDastFinding $_ $AppGuid })

        if ($Url) {
            $findings = @($findings | Where-Object { $_.Url -like $Url })
        }

        return $findings
    }
}

function ConvertTo-VcDastFinding {
    param($Raw, [string]$AppGuid)

    $d = $Raw.finding_details
    $s = $Raw.finding_status

    [pscustomobject]@{
        IssueId          = $Raw.issue_id
        AppGuid          = $AppGuid
        ScanType         = 'DYNAMIC'
        Severity         = $Raw.severity
        SeverityLabel    = $script:VcSeverityLabels[[int]$Raw.severity]
        CweId            = $Raw.cwe_id
        CweName          = if ($d) { $d.cwe?.name }           else { $null }
        Category         = if ($d) { $d.finding_category?.name } else { $null }
        CategoryId       = if ($d) { $d.finding_category?.id }   else { $null }
        # DAST-specific context
        Url              = if ($d) { $d.url }          else { $null }
        HttpMethod       = if ($d) { $d.http_method }  else { $null }
        AttackVector     = if ($d) { $d.attack_vector } else { $null }
        AttackPayload    = if ($d) { $d.attack_payload } else { $null }
        Path             = if ($d -and $d.url) {
                               try { ([Uri]$d.url).AbsolutePath } catch { $d.url }
                           } else { $null }
        # Status
        FlawStatus       = if ($s) { $s.status }                   else { $null }
        MitigationStatus = if ($s) { $s.mitigation_review_status } else { $null }
        FirstFoundDate   = if ($s) { $s.first_found_date }         else { $null }
        LastSeenDate     = if ($s) { $s.last_seen_date }           else { $null }
        DaysOpen         = if ($s -and $s.first_found_date) {
                               [int]([DateTimeOffset]::UtcNow -
                               [DateTimeOffset]::Parse($s.first_found_date)).TotalDays
                           } else { $null }
        Annotations      = $Raw.annotations
        _Raw             = $Raw
    }
}
