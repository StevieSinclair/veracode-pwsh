# Veracode PowerShell Module — Usage Guide

## Requirements

- **PowerShell 7.0+** (required; uses `??`, `?.`, `[DateTimeOffset]`)
- **Windows** — credential path resolves relative to the module root
- **Pester 6.0+** — only needed to run the test suite
- A Veracode account with API credentials (ID + Key)

---

## Installation & Import

```powershell
# From the repo root
Import-Module .\Veracode.psd1

# Verify it loaded
Get-Command -Module Veracode | Sort-Object Name
```

---

## Credentials

Credentials are read from `.veracode\credentials` relative to the **module root** (not `$HOME`). The file uses an INI format identical to the official Veracode CLI:

```ini
[default]
veracode_api_id = your-api-id
veracode_api_key = your-api-key

[staging]
veracode_api_id = staging-id
veracode_api_key = staging-key
```

### Interactive Setup Wizard

```powershell
# Creates or updates a profile interactively (API key is masked during entry)
Initialize-VcCredentials

# Specify a non-default profile
Initialize-VcCredentials -ProfileName staging
```

### Switch Active Profile

```powershell
# All subsequent commands use the staging profile
Set-VcProfile -ProfileName staging

# Pass a profile per command to override without switching globally
Get-VcApplications -Profile staging
```

---

## Applications

```powershell
# List all applications
Get-VcApplications

# Filter by name wildcard
Get-VcApplications -Name 'MyApp*'

# Filter by business unit or policy
Get-VcApplications -BusinessUnit 'Finance'
Get-VcApplications -PolicyName 'Veracode Recommended Medium'

# Get a single application by GUID
Get-VcApplication -Guid 'abc-123'

# Create an application
New-VcApplication -Name 'NewApp' -BusinessCriticality HIGH

# Modify an application
Set-VcApplication -Guid 'abc-123' -BusinessCriticality MEDIUM

# Delete an application (prompts for confirmation)
Remove-VcApplication -Guid 'abc-123'

# Clone an application (copies policy and team memberships)
Copy-VcApplication -SourceGuid 'abc-123' -NewName 'NewApp-Clone'
```

---

## Sandboxes

```powershell
# List sandboxes for an application
Get-VcSandboxes -AppGuid 'abc-123'

# Create a sandbox
New-VcSandbox -AppGuid 'abc-123' -Name 'feature/login-rework'

# Rename / modify a sandbox
Set-VcSandbox -AppGuid 'abc-123' -SandboxGuid 'sbx-456' -Name 'feature/auth-v2'

# Delete a sandbox (prompts for confirmation)
Remove-VcSandbox -AppGuid 'abc-123' -SandboxGuid 'sbx-456'

# Promote a sandbox scan to policy
Invoke-VcSandboxPromotion -AppGuid 'abc-123' -SandboxGuid 'sbx-456'

# Remove sandboxes older than 90 days (skips those with results ready)
Remove-VcOldSandboxes -AppGuid 'abc-123' -OlderThanDays 90
Remove-VcOldSandboxes -AppGuid 'abc-123' -OlderThanDays 30 -Force
```

---

## Scans

```powershell
# List scans for an application
Get-VcScans -AppGuid 'abc-123'

# Watch a scan until it completes (polls every 60 seconds by default)
Watch-VcScan -AppGuid 'abc-123'
Watch-VcScan -AppGuid 'abc-123' -PollSeconds 30 -Bell

# Detect and remove stuck scans for one app
Repair-VcStuckScan -AppGuid 'abc-123'

# Detect and remove stuck scans org-wide (shows all before acting)
Repair-VcStuckScan -All -ThresholdHours 6 -Force

# Preview without making changes
Repair-VcStuckScan -All -WhatIf

# Resume a paused scan
Resume-VcScan -AppGuid 'abc-123' -ScanId 'scn-789'

# Delete a scan (prompts for confirmation)
Remove-VcScan -AppGuid 'abc-123' -ScanId 'scn-789'
```

---

## Findings

```powershell
# All open findings for an application
Get-VcFindings -AppGuid 'abc-123'

# Filter by scan type and minimum severity
Get-VcFindings -AppGuid 'abc-123' -ScanType STATIC -MinSeverity 4

# Filter by CWE
Get-VcFindings -AppGuid 'abc-123' -CweId 89

# Include mitigation annotations
Get-VcFindings -AppGuid 'abc-123' -IncludeAnnotations

# Scope findings to a sandbox
Get-VcFindings -AppGuid 'abc-123' -SandboxGuid 'sbx-456'

# Export findings to CSV
Export-VcFindings -AppGuid 'abc-123' -OutputPath .\findings.csv
Export-VcFindings -AppGuid 'abc-123' -OutputPath .\sast-high.csv -ScanType STATIC -MinSeverity 4
```

---

## Users & Teams

```powershell
# List users
Get-VcUsers
Get-VcUsers -Email '*@example.com'

# Create a user
New-VcUser -Email 'dev@example.com' -FirstName 'Dev' -LastName 'User' -Roles 'Creator','Submitter'

# Update a user's roles
Set-VcUserRoles -UserId 'usr-001' -Roles 'Creator','Reviewer'

# Update a user's profile
Set-VcUser -UserId 'usr-001' -FirstName 'Developer'

# Deactivate a user
Remove-VcUser -UserId 'usr-001'

# Export all users to CSV
Export-VcUsers -OutputPath .\users.csv

# Team management
Get-VcTeams
New-VcTeam -Name 'Backend Team'
Set-VcTeamMembers -TeamId 'team-001' -UserIds 'usr-001','usr-002'
Remove-VcTeam -TeamId 'team-001'
```

---

## Policy

```powershell
# List all policies
Get-VcPolicies

# Filter by name or type
Get-VcPolicies -Name '*Recommended*'
Get-VcPolicies -Type CUSTOMER

# Get a single policy by GUID
Get-VcPolicy -PolicyGuid 'pol-001'

# Trigger a policy evaluation for an application
Invoke-VcPolicyEvaluation -AppGuid 'abc-123'

# Check compliance for one app or the entire org
Get-VcApplicationCompliance -AppGuid 'abc-123'
Get-VcApplicationCompliance -All
```

---

## Analysis

### Severity & CWE Breakdown

```powershell
# Severity distribution with bar chart
Get-VcSeverityBreakdown -AppGuid 'abc-123'

# Top CWEs (default 20, shows VH/H/M/L counts)
Get-VcCweBreakdown -AppGuid 'abc-123'
Get-VcCweBreakdown -AppGuid 'abc-123' -Top 10 -Export .\cwe.csv

# Category breakdown (Veracode categories)
Get-VcCategoryBreakdown -AppGuid 'abc-123'
```

### Mitigations & Modules

```powershell
# Mitigation status summary
Get-VcMitigationStatus -AppGuid 'abc-123'

# Show only pending proposals; flag proposals stale for 60+ days
Get-VcMitigationStatus -AppGuid 'abc-123' -PendingOnly -StaleDays 60

# Flaw detail (call stack for SAST, URL/method for DAST)
Get-VcFlawDetail -AppGuid 'abc-123' -IssueId 101

# Prescan module list (requires Legacy App ID from the portal)
Get-VcPrescanModules -LegacyId 123456

# Module-level finding breakdown
Get-VcModuleBreakdown -AppGuid 'abc-123'
Get-VcModuleBreakdown -AppGuid 'abc-123' -Threshold 10
```

### Scan Comparison & Trend

```powershell
# Compare latest scan against baseline (auto-resolves build IDs)
Compare-VcScans -AppGuid 'abc-123'

# Compare two specific builds; export results
Compare-VcScans -AppGuid 'abc-123' -BaselineBuildId 111 -CurrentBuildId 222 -Export .\diff.csv

# Finding count sparkline across last 10 builds
Get-VcFindingTrend -AppGuid 'abc-123'
Get-VcFindingTrend -AppGuid 'abc-123' -LastNBuilds 20 -Export .\trend.csv
```

### Full HTML Analysis Report

```powershell
# Generate a self-contained dark-themed HTML report
Export-VcAnalysisReport -AppGuid 'abc-123' -OutputPath .\report.html

# Include specific sections only
Export-VcAnalysisReport -AppGuid 'abc-123' -OutputPath .\lite.html `
    -IncludeSections Severity,CWE,Diff
```

---

## Application Maturity Scoring

Scores each application across 5 dimensions (0–3 each), adjusted by finding severity (+2/0/−2), producing a Level 1–5 maturity rating:

| Level | Label      | Score Range |
|-------|-----------|-------------|
| 1     | Initial    | ≤ 2         |
| 2     | Developing | 3–5         |
| 3     | Established| 6–8         |
| 4     | Advanced   | 9–10        |
| 5     | Optimized  | 11–13       |

The 5 dimensions are: **Scan Cadence**, **Scan Coverage** (SAST/SCA/DAST presence), **Finding Resolution**, **Mitigation Quality**, **Policy Compliance**.

```powershell
# Score a single application and display improvement guidance
Get-VcApplicationMaturity -AppGuid 'abc-123'

# Score all applications in the org
Get-VcApplicationMaturity -All

# Export scores to CSV
Get-VcApplicationMaturity -All -Export .\maturity.csv

# Display a formatted bar-chart maturity report
Show-VcMaturityReport -AppGuid 'abc-123'
```

---

## SCA (Software Composition Analysis)

```powershell
# All open SCA findings
Get-VcScaFindings -AppGuid 'abc-123'

# Filter by CVSS score or license risk
Get-VcScaFindings -AppGuid 'abc-123' -MinCvss 7.0
Get-VcScaFindings -AppGuid 'abc-123' -LicenseRisk HIGH

# Library-level summary (aggregates all CVEs per library version)
Get-VcScaLibrarySummary -AppGuid 'abc-123'
Get-VcScaLibrarySummary -AppGuid 'abc-123' -Export .\libraries.csv

# Prioritized upgrade recommendations (libraries with known fix versions)
Get-VcScaUpgrades -AppGuid 'abc-123'

# License risk breakdown
Get-VcScaLicenses -AppGuid 'abc-123'
Get-VcScaLicenses -AppGuid 'abc-123' -RiskLevel HIGH

# Org-wide blast radius: which vulnerable libraries affect multiple apps
Get-VcScaExposure
Get-VcScaExposure -MinCvss 7.0 -MinAppCount 3 -Export .\exposure.csv
```

---

## DAST (Dynamic Analysis)

### Managing Scans

```powershell
# List all DAST analyses
Get-VcDastScans

# Filter by status or application
Get-VcDastScans -Status RUNNING
Get-VcDastScans -AppGuid 'abc-123'

# List stuck analyses (active state, older than threshold)
Get-VcDastScans -StuckOnly
Get-VcDastScans -StuckOnly -ThresholdHours 12

# Get full config for a single analysis
Get-VcDastScan -AnalysisId 'ana-001'

# Trigger an existing analysis immediately (sets schedule start = now)
Start-VcDastScan -AnalysisId 'ana-001'

# Stop a running analysis (preserves configuration)
Stop-VcDastScan -AnalysisId 'ana-001'
Stop-VcDastScan -AnalysisId 'ana-001' -Force

# Stop all stuck analyses (shows list before acting)
Repair-VcDastScan -All
Repair-VcDastScan -All -ThresholdHours 12 -Force
Repair-VcDastScan -AnalysisId 'ana-001' -Force

# Pipeline: find stuck scans and stop them
Get-VcDastScans -StuckOnly | Stop-VcDastScan -Force
```

### DAST Findings

```powershell
# List DAST findings for an application
Get-VcDastFindings -AppGuid 'abc-123'

# Filter by severity or URL pattern
Get-VcDastFindings -AppGuid 'abc-123' -MinSeverity 4
Get-VcDastFindings -AppGuid 'abc-123' -Url '*/admin/*'

# Comprehensive DAST analysis: severity, CWE, endpoint heat map, attack vectors
Get-VcDastAnalysis -AppGuid 'abc-123'
Get-VcDastAnalysis -AppGuid 'abc-123' -Top 20 -Export .\dast-analysis.csv
```

### DAST + SAST Cross-Comparison

```powershell
# Find CWEs confirmed by both SAST and DAST (highest remediation priority)
Compare-VcDastSast -AppGuid 'abc-123'
Compare-VcDastSast -AppGuid 'abc-123' -Export .\overlap.csv

# Org-wide: pipe applications into the comparison
Get-VcApplications | Compare-VcDastSast -Export .\org-overlap.csv
```

---

## Admin

### Audit Log

```powershell
# Last 24 hours of audit events
Get-VcAuditLog

# Filter by date range, user, or event type
Get-VcAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
Get-VcAuditLog -UserEmail 'admin@example.com'
Get-VcAuditLog -EventType 'user.login'

# Export to CSV
Get-VcAuditLog -StartDate (Get-Date).AddDays(-30) -Export .\audit.csv
```

### Org-Wide Report

```powershell
# Generate a CSV snapshot of apps, compliance, findings, and scan health
Export-VcReport -OutputPath .\org-report.csv

# Generate a self-contained dark-themed HTML report
Export-VcReport -OutputPath .\org-report.html -Format HTML
```

---

## Interactive TUI Dashboard

```powershell
Show-VcDashboard
```

The TUI provides keyboard-driven menus for all major areas:

| Key | Section               |
|-----|-----------------------|
| `a` | Applications          |
| `x` | Sandboxes             |
| `s` | Scans                 |
| `u` | Users                 |
| `t` | Teams                 |
| `f` | Findings              |
| `p` | Policy                |
| `d` | Admin                 |
| `n` | Analysis              |
| `q` | Quick Actions         |
| `Q` | Quit                  |

Tables are paged — press `n`/`p` to navigate pages, `b` to go back to the menu.

---

## Pipeline & Composition Examples

```powershell
# Get all apps failing policy and check their maturity
Get-VcApplicationCompliance -All |
    Where-Object { -not $_.Passed } |
    ForEach-Object { Get-VcApplicationMaturity -AppGuid $_.AppGuid }

# Stop all stuck DAST scans without confirmation
Get-VcDastScans -StuckOnly -ThresholdHours 6 | Stop-VcDastScan -Force

# Export Very High findings for all apps to one CSV
Get-VcApplications | ForEach-Object {
    Get-VcFindings -AppGuid $_.Guid -MinSeverity 5
} | Export-Csv .\all-critical.csv -NoTypeInformation

# Show upgrade priority for every app and export
Get-VcApplications | ForEach-Object {
    Get-VcScaUpgrades -AppGuid $_.Guid
} | Sort-Object Priority, MaxCvss -Descending |
    Export-Csv .\all-upgrades.csv -NoTypeInformation

# Find libs with critical CVEs that appear in 3+ apps
Get-VcScaExposure -MinCvss 9.0 -MinAppCount 3
```

---

## Running Tests

```powershell
# Run all tests from the repo root
Invoke-Pester .\Tests\ -Output Detailed

# Run a specific domain
Invoke-Pester .\Tests\DAST.Tests.ps1 -Output Detailed
Invoke-Pester .\Tests\SCA.Tests.ps1  -Output Detailed

# Available test files:
#   Tests/Core.Tests.ps1
#   Tests/Applications.Tests.ps1
#   Tests/Scans.Tests.ps1
#   Tests/Users.Tests.ps1
#   Tests/Teams.Tests.ps1
#   Tests/Findings.Tests.ps1
#   Tests/Policy.Tests.ps1
#   Tests/Admin.Tests.ps1
#   Tests/Maturity.Tests.ps1
#   Tests/Analysis.Tests.ps1
#   Tests/SCA.Tests.ps1
#   Tests/DAST.Tests.ps1
#   Tests/QOL.Tests.ps1
```

---

## Credential Environment Variables

The following environment variables override credentials file values when set:

| Variable                | Purpose             |
|-------------------------|---------------------|
| `VERACODE_API_ID`       | API ID              |
| `VERACODE_API_KEY`      | API Key (secret)    |

This is useful in CI/CD pipelines — set the variables in the pipeline environment and the module picks them up automatically without a credentials file.
