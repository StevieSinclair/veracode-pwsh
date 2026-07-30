#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Scans/Get-VcScans.ps1')
    . (Join-Path $ModuleRoot 'Scans/Remove-VcScan.ps1')
    . (Join-Path $ModuleRoot 'Scans/Repair-VcStuckScan.ps1')
    . (Join-Path $ModuleRoot 'Scans/Resume-VcScan.ps1')

    $script:NowUtc = [DateTimeOffset]::UtcNow

    # A scan submitted 6 hours ago in a stuck state
    $script:StuckScanRaw = [pscustomobject]@{
        scan_id        = 'scan-stuck-1'
        scan_status    = 'SCAN_IN_PROGRESS'
        scan_type      = 'STATIC'
        submitted_date = $script:NowUtc.AddHours(-6).ToString('o')
        modules_count  = 3
    }

    # A completed scan
    $script:DoneScanRaw = [pscustomobject]@{
        scan_id        = 'scan-done-1'
        scan_status    = 'RESULTS_READY'
        scan_type      = 'STATIC'
        submitted_date = $script:NowUtc.AddHours(-2).ToString('o')
        modules_count  = 3
    }

    # A fresh scan submitted 1 hour ago (not stuck)
    $script:FreshScanRaw = [pscustomobject]@{
        scan_id        = 'scan-fresh-1'
        scan_status    = 'SCAN_IN_PROGRESS'
        scan_type      = 'STATIC'
        submitted_date = $script:NowUtc.AddHours(-1).ToString('o')
        modules_count  = 2
    }
}

Describe 'Get-VcScanAgeHours' {
    It 'returns a positive age for a past date' {
        $age = Get-VcScanAgeHours ($script:NowUtc.AddHours(-5).ToString('o'))
        $age | Should -BeGreaterThan 4.9
        $age | Should -BeLessThan 5.1
    }
    It 'returns -1 for null or empty input' {
        Get-VcScanAgeHours $null  | Should -Be -1
        Get-VcScanAgeHours ''     | Should -Be -1
    }
    It 'returns -1 for an unparseable string' {
        Get-VcScanAgeHours 'not-a-date' | Should -Be -1
    }
}

Describe 'ConvertTo-VcScan' {
    It 'marks a long-running SCAN_IN_PROGRESS as stuck' {
        $scan = ConvertTo-VcScan $script:StuckScanRaw 'app-1' $null
        $scan.IsStuck   | Should -Be $true
        $scan.Status    | Should -Be 'SCAN_IN_PROGRESS'
        $scan.AgeHours  | Should -BeGreaterThan 5
    }
    It 'does not mark RESULTS_READY as stuck' {
        $scan = ConvertTo-VcScan $script:DoneScanRaw 'app-1' $null
        $scan.IsStuck | Should -Be $false
        $scan.Status  | Should -Be 'RESULTS_READY'
    }
    It 'carries AppGuid and SandboxGuid through' {
        $scan = ConvertTo-VcScan $script:StuckScanRaw 'app-1' 'sb-1'
        $scan.AppGuid     | Should -Be 'app-1'
        $scan.SandboxGuid | Should -Be 'sb-1'
    }
}

Describe 'Get-VcScans' {
    It 'filters with -StuckOnly' {
        Mock Invoke-VcPagedApi {
            @($script:StuckScanRaw, $script:DoneScanRaw, $script:FreshScanRaw)
        }
        $stuck = Get-VcScans -AppGuid 'app-1' -StuckOnly
        # StuckScanRaw (6h, SCAN_IN_PROGRESS) and FreshScanRaw (1h, SCAN_IN_PROGRESS)
        # Both are in stuck states, so both should appear — IsStuck is true for any stuck-state scan
        $stuck | ForEach-Object { $_.IsStuck | Should -Be $true }
    }

    It 'filters with -OlderThanHours' {
        Mock Invoke-VcPagedApi {
            @($script:StuckScanRaw, $script:DoneScanRaw, $script:FreshScanRaw)
        }
        # StuckScanRaw=6h, DoneScanRaw=2h, FreshScanRaw=1h — only the 6h scan qualifies
        $old = Get-VcScans -AppGuid 'app-1' -OlderThanHours 4
        $old.Count | Should -Be 1
        $old[0].ScanId | Should -Be 'scan-stuck-1'
    }

    It 'uses sandbox path when SandboxGuid is supplied' {
        Mock Invoke-VcPagedApi { @() } -ParameterFilter {
            $Path -like '*/sandboxes/sb-1/scans'
        }
        Get-VcScans -AppGuid 'app-1' -SandboxGuid 'sb-1'
        Should -Invoke Invoke-VcPagedApi -Times 1
    }
}

Describe 'Remove-VcScan' {
    It 'sends DELETE to the correct REST path' {
        Mock Invoke-VcApi { $null }
        Remove-VcScan -AppGuid 'app-1' -ScanId 'scan-1' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Method -eq 'DELETE' -and $Path -eq '/appsec/v1/applications/app-1/scans/scan-1'
        }
    }

    It 'uses sandbox path when SandboxGuid is provided' {
        Mock Invoke-VcApi { $null }
        Remove-VcScan -AppGuid 'app-1' -ScanId 'scan-1' -SandboxGuid 'sb-1' -Force
        Should -Invoke Invoke-VcApi -Times 1 -ParameterFilter {
            $Path -like '*/sandboxes/sb-1/scans/scan-1'
        }
    }

    It 'blocks deletion of RESULTS_READY without -Force' {
        Mock Invoke-VcApi { $null }
        Remove-VcScan -AppGuid 'app-1' -ScanId 'scan-1' -Status 'RESULTS_READY' -Confirm:$false
        Should -Invoke Invoke-VcApi -Times 0
    }

    It 'allows deletion of RESULTS_READY with -Force' {
        Mock Invoke-VcApi { $null }
        Remove-VcScan -AppGuid 'app-1' -ScanId 'scan-1' -Status 'RESULTS_READY' -Force
        Should -Invoke Invoke-VcApi -Times 1
    }

    It 'does nothing with -WhatIf' {
        Mock Invoke-VcApi { $null }
        Remove-VcScan -AppGuid 'app-1' -ScanId 'scan-1' -Force -WhatIf
        Should -Invoke Invoke-VcApi -Times 0
    }
}

Describe 'Repair-VcStuckScan (single app)' {
    It 'deletes stuck scans and reports count' {
        Mock Get-VcScans {
            @(
                (ConvertTo-VcScan $script:StuckScanRaw 'app-1' $null)
            )
        }
        Mock Remove-VcScan { $null }

        Repair-VcStuckScan -AppGuid 'app-1' -ThresholdHours 4 -Force
        Should -Invoke Remove-VcScan -Times 1
    }

    It 'does not delete scans below the threshold' {
        Mock Get-VcScans {
            @(
                (ConvertTo-VcScan $script:FreshScanRaw 'app-1' $null)  # only 1h old
            )
        }
        Mock Remove-VcScan { $null }

        Repair-VcStuckScan -AppGuid 'app-1' -ThresholdHours 4 -Force
        Should -Invoke Remove-VcScan -Times 0
    }
}

Describe 'Resume-VcScan' {
    It 'deletes the most recent scan' {
        Mock Get-VcScans {
            @(
                (ConvertTo-VcScan $script:StuckScanRaw 'app-1' $null),
                (ConvertTo-VcScan $script:FreshScanRaw 'app-1' $null)
            )
        }
        Mock Remove-VcScan { $null }

        Resume-VcScan -AppGuid 'app-1' -Confirm:$false
        # Latest by SubmittedDate is FreshScanRaw (submitted 1h ago, most recent)
        Should -Invoke Remove-VcScan -Times 1 -ParameterFilter {
            $ScanId -eq 'scan-fresh-1'
        }
    }

    It 'blocks deletion of RESULTS_READY without -Force' {
        Mock Get-VcScans { @((ConvertTo-VcScan $script:DoneScanRaw 'app-1' $null)) }
        Mock Remove-VcScan { $null }

        Resume-VcScan -AppGuid 'app-1' -Confirm:$false
        Should -Invoke Remove-VcScan -Times 0
    }
}
