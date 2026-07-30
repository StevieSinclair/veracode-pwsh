function Get-VcAuditLog {
    <#
    .SYNOPSIS
        Retrieves the organisation audit log (identity API).
    .PARAMETER StartDate
        Return events on or after this date. Default: 30 days ago.
    .PARAMETER EndDate
        Return events on or before this date. Default: now.
    .PARAMETER UserEmail
        Filter events by the actor's email address.
    .PARAMETER EventType
        Filter by event type (e.g. LOGIN, LOGOUT, USER_CREATED, POLICY_UPDATED).
    .PARAMETER Export
        Path to write results as a CSV file.
    .EXAMPLE
        Get-VcAuditLog
        Get-VcAuditLog -StartDate (Get-Date).AddDays(-7)
        Get-VcAuditLog -UserEmail 'alice@acme.com' -Export .\audit.csv
    #>
    [CmdletBinding()]
    param(
        [DateTime]$StartDate = ([DateTime]::UtcNow.AddDays(-30)),
        [DateTime]$EndDate   = [DateTime]::UtcNow,

        [string]$UserEmail,
        [string]$EventType,
        [string]$Export,

        [string]$Profile = $script:VcCurrentProfile
    )

    $query = @{
        start_date = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        end_date   = $EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($UserEmail) { $query['user_email'] = $UserEmail }
    if ($EventType) { $query['event_type'] = $EventType }

    Write-Verbose "Fetching audit log from $($query['start_date']) to $($query['end_date'])..."

    $raw = Invoke-VcPagedApi -Path '/api/authn/v2/audit_logs' -EmbeddedKey 'audit_logs' -Query $query -Profile $Profile

    $entries = $raw | ForEach-Object {
        [pscustomobject]@{
            EventId        = $_.id
            EventDate      = $_.event_timestamp
            EventType      = $_.event_type
            ActorEmail     = $_.actor_email
            ActorName      = $_.actor_name
            TargetEmail    = $_.target_user_email
            TargetName     = $_.target_user_name
            Description    = $_.description
            IpAddress      = $_.ip_address
            _Raw           = $_
        }
    }

    if ($Export) {
        $entries | Select-Object -ExcludeProperty _Raw |
            Export-Csv -Path $Export -NoTypeInformation
        Write-Host "Audit log exported to '$Export' ($($entries.Count) entries)."
    }

    return $entries
}
