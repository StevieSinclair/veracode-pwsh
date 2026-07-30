#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Applications/New-VcApplication.ps1')
    . (Join-Path $ModuleRoot 'Applications/Copy-VcApplication.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Get-VcSandboxes.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Remove-VcSandbox.ps1')
    . (Join-Path $ModuleRoot 'Sandboxes/Remove-VcOldSandboxes.ps1')
    . (Join-Path $ModuleRoot 'Scans/Get-VcScans.ps1')
    . (Join-Path $ModuleRoot 'Scans/Watch-VcScan.ps1')

    $script:SampleApp = [pscustomobject]@{
        Guid                 = 'app-1'
        Name                 = 'MyApp'
        BusinessCriticality  = 'HIGH'
        PolicyGuid           = 'pol-1'
        PolicyName           = 'PCI Policy'
        PolicyCompliance     = 'PASSED'
        Description          = 'A test application'
        BusinessUnitGuid     = 'bu-1'
        TeamGuids            = @('team-1')
        LastScanDate         = [DateTime]::UtcNow.AddDays(-5).ToString('o')
    }

    $nowStr = [DateTimeOffset]::UtcNow.ToString('o')
    $oldStr = [DateTimeOffset]::UtcNow.AddDays(-100).ToString('o')

    $script:FreshSandbox = [pscustomobject]@{
        SandboxGuid      = 'sb-fresh'
        Name             = 'dev-sandbox'
        SandboxType      = 'DEVELOPMENT'
        LastModifiedDate = $nowStr
        AutoRecreate     = $false
    }

    $script:OldSandbox = [pscustomobject]@{
        SandboxGuid      = 'sb-old'
        Name             = 'old-sandbox'
        SandboxType      = 'DEVELOPMENT'
        LastModifiedDate = $oldStr
        AutoRecreate     = $false
    }

    $script:SampleScan = [pscustomobject]@{
        ScanId        = 'scan-1'
        AppGuid       = 'app-1'
        SandboxGuid   = $null
        Status        = 'SCAN_IN_PROGRESS'
        ScanType      = 'STATIC'
        SubmittedDate = [DateTimeOffset]::UtcNow.AddHours(-1).ToString('o')
        AgeHours      = 1
        IsStuck       = $false
    }

    $script:DoneScan = [pscustomobject]@{
        ScanId        = 'scan-done'
        AppGuid       = 'app-1'
        SandboxGuid   = $null
        Status        = 'RESULTS_READY'
        ScanType      = 'STATIC'
        SubmittedDate = [DateTimeOffset]::UtcNow.AddHours(-2).ToString('o')
        AgeHours      = 2
        IsStuck       = $false
    }
}

Describe 'Copy-VcApplication' {
    It 'creates a new app with the source app settings' {
        Mock Get-VcApplication { $script:SampleApp }
        Mock New-VcApplication {
            [pscustomobject]@{ Guid = 'app-new'; Name = $Name }
        }

        $result = Copy-VcApplication -SourceGuid 'app-1' -NewName 'MyApp-v2' -Confirm:$false
        $result.Name | Should -Be 'MyApp-v2'

        Should -Invoke New-VcApplication -Times 1 -ParameterFilter {
            $Name -eq 'MyApp-v2' -and $BusinessCriticality -eq 'HIGH'
        }
    }

    It 'allows overriding the policy' {
        Mock Get-VcApplication { $script:SampleApp }
        Mock New-VcApplication { [pscustomobject]@{ Guid = 'app-new'; Name = $Name } }

        Copy-VcApplication -SourceGuid 'app-1' -NewName 'MyApp-nopol' -PolicyGuid '' -Confirm:$false

        Should -Invoke New-VcApplication -Times 1
    }

    It 'does nothing with -WhatIf' {
        Mock Get-VcApplication { $script:SampleApp }
        Mock New-VcApplication { }

        Copy-VcApplication -SourceGuid 'app-1' -NewName 'X' -WhatIf
        Should -Invoke New-VcApplication -Times 0
    }
}

Describe 'Remove-VcOldSandboxes' {
    It 'deletes only sandboxes older than the threshold' {
        Mock Get-VcSandboxes   { @($script:FreshSandbox, $script:OldSandbox) }
        Mock Get-VcScans       { @() }   # no scans — safe to delete
        Mock Remove-VcSandbox  { }

        Remove-VcOldSandboxes -AppGuid 'app-1' -OlderThanDays 60 -Force

        Should -Invoke Remove-VcSandbox -Times 1 -ParameterFilter {
            $SandboxGuid -eq 'sb-old'
        }
        Should -Invoke Remove-VcSandbox -Times 0 -ParameterFilter {
            $SandboxGuid -eq 'sb-fresh'
        }
    }

    It 'skips sandboxes with RESULTS_READY scans when KeepResultsReady is set' {
        Mock Get-VcSandboxes { @($script:OldSandbox) }
        Mock Get-VcScans     { @($script:DoneScan) }
        Mock Remove-VcSandbox { }

        Remove-VcOldSandboxes -AppGuid 'app-1' -OlderThanDays 60 -KeepResultsReady -Force

        Should -Invoke Remove-VcSandbox -Times 0
    }

    It 'reports zero deleted when no old sandboxes exist' {
        Mock Get-VcSandboxes  { @($script:FreshSandbox) }
        Mock Remove-VcSandbox { }

        Remove-VcOldSandboxes -AppGuid 'app-1' -OlderThanDays 60 -Force
        Should -Invoke Remove-VcSandbox -Times 0
    }
}

Describe 'Watch-VcScan' {
    It 'returns immediately when scan is in a terminal state' {
        Mock Get-VcScans { @($script:DoneScan) }

        $result = Watch-VcScan -AppGuid 'app-1' -IntervalSeconds 1 -TimeoutMinutes 1
        $result.Status | Should -Be 'RESULTS_READY'

        Should -Invoke Get-VcScans -Times 1
    }

    It 'accepts pipeline input from Get-VcApplications' {
        Mock Get-VcScans { @($script:DoneScan) }

        $app    = [pscustomobject]@{ Guid = 'app-1'; Name = 'MyApp' }
        $result = $app | Watch-VcScan -IntervalSeconds 1 -TimeoutMinutes 1
        $result.Status | Should -Be 'RESULTS_READY'
    }
}
