function Set-VcUserRoles {
    <#
    .SYNOPSIS
        Adds or removes specific roles from one or more users without replacing the full role list.
    .PARAMETER UserId
        One or more user IDs. Accepts pipeline input from Get-VcUsers.
    .PARAMETER AddRoles
        Role names to add (any not already assigned).
    .PARAMETER RemoveRoles
        Role names to remove (silently ignored if the user does not hold them).
    .EXAMPLE
        Set-VcUserRoles -UserId 'abc','def' -AddRoles 'MitigationApprover'
        Get-VcUsers -Role 'Reviewer' | Set-VcUserRoles -AddRoles 'SecurityLead' -RemoveRoles 'Reviewer'
        Set-VcUserRoles -UserId 'abc' -RemoveRoles 'Administrator' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string[]]$UserId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Email,

        [string[]]$AddRoles,
        [string[]]$RemoveRoles,

        [string]$Profile = $script:VcCurrentProfile
    )

    process {
        foreach ($id in $UserId) {
            Write-Verbose "Fetching roles for user $id..."
            $current   = Invoke-VcApi -Path "/api/authn/v2/users/$id" -Profile $Profile
            $existing = @($current.roles | ForEach-Object { $_.role_name })

            # Pure array merge — no .NET collection constructors to avoid overload-binder issues.
            $toKeep   = if ($RemoveRoles) { @($existing | Where-Object { $_ -notin $RemoveRoles }) } else { $existing }
            $toAdd    = if ($AddRoles)    { @($AddRoles | Where-Object { $_ -notin $existing })    } else { @() }
            $newRoles = @($toKeep) + @($toAdd)

            $label = if ($Email) { "$Email ($id)" } else { $id }
            if (-not $PSCmdlet.ShouldProcess($label, "Update roles: +[$($AddRoles -join ',')] -[$($RemoveRoles -join ',')]")) { continue }

            Set-VcUser -UserId $id -Email $Email -Roles $newRoles -Profile $Profile -Confirm:$false | Out-Null
            Write-Verbose "Roles updated for $label. New set: $($newRoles -join ', ')"
        }
    }
}
