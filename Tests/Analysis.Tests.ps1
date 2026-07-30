#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $script:VcCurrentProfile = 'default'

    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')
    . (Join-Path $ModuleRoot 'Applications/Get-VcApplications.ps1')
    . (Join-Path $ModuleRoot 'Findings/Get-VcFindings.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcSeverityBreakdown.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcCweBreakdown.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcCategoryBreakdown.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcMitigationStatus.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Get-VcFlawDetail.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Compare-VcScans.ps1')
    . (Join-Path $ModuleRoot 'Analysis/Export-VcAnalysisReport.ps1')

    # Build a set of synthetic findings for all tests
    function New-TestFinding_ {
        param([int]$Id, [int]$Sev, [int]$CweId, [string]$CweName, [string]$Cat, [int]$CatId, [string]$MitStatus = 'NONE')
        [pscustomobject]@{
            IssueId          = $Id
            AppGuid          = 'app-1'
            ScanType         = 'STATIC'
            Severity         = $Sev
            SeverityLabel    = $script:VcSeverityLabels[$Sev]
            CweId            = $CweId
            CweName          = $CweName
            Category         = $Cat
            CategoryId       = $CatId
            FileName         = 'com/example/Dao.java'
            LineNumber       = $Id * 10
            AttackVector     = 'Network'
            FlawStatus       = 'OPEN'
            MitigationStatus = $MitStatus
            DaysOpen         = 20
            Annotations      = @()
            _Raw             = $null
        }
    }

    $script:Findings = @(
        (New-TestFinding_ 1 5 89  'SQL Injection'          'Injection'     18 'NONE')
        (New-TestFinding_ 2 5 89  'SQL Injection'          'Injection'     18 'PROPOSED')
        (New-TestFinding_ 3 4 79  'Cross-Site Scripting'   'XSS'            4 'NONE')
        (New-TestFinding_ 4 3 22  'Improper Input Handling' 'Input Handling' 5 'APPROVED')
        (New-TestFinding_ 5 2 311 'Missing Encryption'     'Cryptography'   7 'NONE')
        (New-TestFinding_ 6 1 209 'Information Leakage'    'Information'    9 'NONE')
    )
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcSeverityBreakdown' {
    BeforeEach { Mock Get-VcFindings { $script:Findings } }

    It 'returns one row per severity level (0-5)' {
        $rows = Get-VcSeverityBreakdown -AppGuid 'app-1'
        $rows.Count | Should -Be 6
    }

    It 'counts VeryHigh findings correctly' {
        $rows = Get-VcSeverityBreakdown -AppGuid 'app-1'
        # One row in the breakdown table for severity 5
        @($rows | Where-Object { $_.Severity -eq 5 }).Count | Should -Be 1
        # That row's Count column should reflect 2 findings at VH
        $vhRow = $rows | Where-Object { $_.Severity -eq 5 }
        $vhRow.Count | Should -Be 2
    }

    It 'computes correct percentage for a severity level' {
        $rows = Get-VcSeverityBreakdown -AppGuid 'app-1'
        $vhRow = $rows | Where-Object { $_.Severity -eq 5 }
        # 2 out of 6 findings = 33.3%
        $vhRow.PctTotal | Should -Be 33.3
    }

    It 'exports to CSV' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Get-VcSeverityBreakdown -AppGuid 'app-1' -Export $tmp
        (Import-Csv $tmp).Count | Should -Be 6
        Remove-Item $tmp -Force
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcCweBreakdown' {
    BeforeEach { Mock Get-VcFindings { $script:Findings } }

    It 'groups findings by CWE and sorts by count descending' {
        $rows = Get-VcCweBreakdown -AppGuid 'app-1'
        $rows[0].CweId | Should -Be 89   # 2 SQL Injection findings
        $rows[0].Count | Should -Be 2
    }

    It 'respects -Top parameter' {
        $rows = Get-VcCweBreakdown -AppGuid 'app-1' -Top 2
        $rows.Count | Should -Be 2
    }

    It 'computes VeryHigh and High inline severity counts' {
        $rows = Get-VcCweBreakdown -AppGuid 'app-1'
        $sqli = $rows | Where-Object { $_.CweId -eq 89 }
        $sqli.VeryHigh | Should -Be 2
        $sqli.High     | Should -Be 0
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcCategoryBreakdown' {
    BeforeEach { Mock Get-VcFindings { $script:Findings } }

    It 'groups findings by category' {
        $rows = Get-VcCategoryBreakdown -AppGuid 'app-1'
        $rows.Count | Should -BeGreaterThan 0
    }

    It 'top category is Injection with 2 findings' {
        $rows = Get-VcCategoryBreakdown -AppGuid 'app-1'
        $inj = $rows | Where-Object { $_.CategoryName -eq 'Injection' }
        $inj.Total    | Should -Be 2
        $inj.VeryHigh | Should -Be 2
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Get-VcMitigationStatus' {
    BeforeEach { Mock Get-VcFindings { $script:Findings } }

    It 'returns one row per finding' {
        $rows = Get-VcMitigationStatus -AppGuid 'app-1'
        $rows.Count | Should -Be $script:Findings.Count
    }

    It 'filters to PROPOSED only with -PendingOnly' {
        $rows = Get-VcMitigationStatus -AppGuid 'app-1' -PendingOnly
        $rows | ForEach-Object { $_.MitigationStatus | Should -Be 'PROPOSED' }
    }

    It 'does not flag proposal as stale when DaysOpen is below threshold' {
        # Our test findings have DaysOpen=20; default StaleDays=30
        $rows = Get-VcMitigationStatus -AppGuid 'app-1' -StaleDays 30
        @($rows | Where-Object { $_.IsStaleProposal }).Count | Should -Be 0
    }

    It 'flags proposal as stale when DaysOpen exceeds threshold' {
        $rows = Get-VcMitigationStatus -AppGuid 'app-1' -StaleDays 10
        # Finding #2 has PROPOSED + DaysOpen 20 which is > 10
        @($rows | Where-Object { $_.IsStaleProposal }).Count | Should -Be 1
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Compare-VcScans' {
    It 'correctly identifies NEW, FIXED, and PERSISTED findings' {
        # Baseline has issue IDs 1,2,3. Current has 2,3,4 → NEW=4, FIXED=1, PERSISTED=2,3
        $baseFindings = @(
            [pscustomobject]@{ IssueId=1; AppGuid='app-1'; ScanType='STATIC'; Severity=5; SeverityLabel='Very High'; CweId=89; CweName='SQLi'; Category='Inj'; CategoryId=1; FileName='a.java'; LineNumber=1; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=30; Annotations=@(); AttackVector=''; _Raw=$null }
            [pscustomobject]@{ IssueId=2; AppGuid='app-1'; ScanType='STATIC'; Severity=4; SeverityLabel='High';      CweId=79; CweName='XSS';  Category='XSS'; CategoryId=2; FileName='b.java'; LineNumber=2; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=20; Annotations=@(); AttackVector=''; _Raw=$null }
            [pscustomobject]@{ IssueId=3; AppGuid='app-1'; ScanType='STATIC'; Severity=3; SeverityLabel='Medium';    CweId=22; CweName='Inp';  Category='Inp'; CategoryId=3; FileName='c.java'; LineNumber=3; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=10; Annotations=@(); AttackVector=''; _Raw=$null }
        )
        $currFindings = @(
            [pscustomobject]@{ IssueId=2; AppGuid='app-1'; ScanType='STATIC'; Severity=4; SeverityLabel='High';   CweId=79; CweName='XSS'; Category='XSS'; CategoryId=2; FileName='b.java'; LineNumber=2; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=25; Annotations=@(); AttackVector=''; _Raw=$null }
            [pscustomobject]@{ IssueId=3; AppGuid='app-1'; ScanType='STATIC'; Severity=3; SeverityLabel='Medium'; CweId=22; CweName='Inp'; Category='Inp'; CategoryId=3; FileName='c.java'; LineNumber=3; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=15; Annotations=@(); AttackVector=''; _Raw=$null }
            [pscustomobject]@{ IssueId=4; AppGuid='app-1'; ScanType='STATIC'; Severity=5; SeverityLabel='Very High'; CweId=89; CweName='SQLi'; Category='Inj'; CategoryId=1; FileName='d.java'; LineNumber=4; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=1; Annotations=@(); AttackVector=''; _Raw=$null }
        )

        # Mock Invoke-VcPagedApi to return baseline vs current based on build_id
        Mock Invoke-VcPagedApi {
            if ($Query -and $Query['build_id'] -eq 'base') { return $baseFindings | ForEach-Object { $_._Raw = $_; $_ } }
            return $currFindings | ForEach-Object { $_._Raw = $_; $_ }
        }

        # Stub ConvertTo-VcFinding to pass through (already pre-shaped)
        # We need to re-define it for this scope or mock it
        Mock ConvertTo-VcFinding { param($Raw, $AppGuid) $Raw }

        $result = Compare-VcScans -AppGuid 'app-1' -BaselineBuildId 'base' -CurrentBuildId 'curr'
        $result.NewCount       | Should -Be 1   # issue 4
        $result.FixedCount     | Should -Be 1   # issue 1
        $result.PersistedCount | Should -Be 2   # issues 2,3
    }

    It 'exports a combined CSV with ChangeType column' {
        $finding = [pscustomobject]@{ IssueId=1; AppGuid='app-1'; ScanType='STATIC'; Severity=5; SeverityLabel='Very High'; CweId=89; CweName='SQLi'; Category='Inj'; CategoryId=1; FileName='a.java'; LineNumber=1; FlawStatus='OPEN'; MitigationStatus='NONE'; DaysOpen=5; Annotations=@(); AttackVector=''; _Raw=$null }
        Mock Invoke-VcPagedApi { @($finding) }
        Mock ConvertTo-VcFinding { param($Raw, $AppGuid) $Raw }

        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.csv'
        Compare-VcScans -AppGuid 'app-1' -BaselineBuildId 'b1' -CurrentBuildId 'b2' -Export $tmp
        $rows = Import-Csv $tmp
        $rows | ForEach-Object { $_.ChangeType | Should -BeIn @('NEW','FIXED','PERSISTED') }
        Remove-Item $tmp -Force
    }
}

# ────────────────────────────────────────────────────────────────────────────
Describe 'Export-VcAnalysisReport' {
    BeforeEach {
        Mock Get-VcApplication {
            [pscustomobject]@{
                Guid='app-1'; Name='MyApp'; PolicyName='PCI'; PolicyCompliance='PASSED'; LegacyId=1234
                LastScanDate='2026-07-01'; BusinessCriticality='HIGH'; PolicyGuid='pol-1'
                Description=''; BusinessUnitGuid=$null; TeamGuids=@()
            }
        }
        Mock Get-VcFindings    { $script:Findings }
        Mock Compare-VcScans   { [pscustomobject]@{ NewCount=1; FixedCount=0; PersistedCount=5; NewFindings=@(); FixedFindings=@(); PersistedFindings=@() } }
    }

    It 'writes an HTML file' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'
        Export-VcAnalysisReport -AppGuid 'app-1' -OutputPath $tmp
        $content = Get-Content $tmp -Raw
        $content | Should -Match '<!DOCTYPE html'
        $content | Should -Match 'MyApp'
        $content | Should -Match 'Severity Breakdown'
        Remove-Item $tmp -Force
    }

    It 'respects -IncludeSections to limit output' {
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'
        Export-VcAnalysisReport -AppGuid 'app-1' -OutputPath $tmp -IncludeSections @('Severity')
        $content = Get-Content $tmp -Raw
        $content | Should -Match 'Severity Breakdown'
        $content | Should -Not -Match 'CWE Heat Map'
        Remove-Item $tmp -Force
    }
}
