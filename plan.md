# Veracode PowerShell Management Suite — Plan

## Overview

A modular PowerShell suite for managing Veracode at scale. All scripts are built on a shared
authentication/HTTP core and follow PowerShell verb-noun naming conventions. The suite covers:
applications, sandboxes, scans (including stuck-scan recovery), users, teams, findings, policies,
and an interactive TUI dashboard.

---

## Architecture

```
veracode/
├── Veracode.psd1                  # Module manifest (auto-imports all sub-modules)
├── Veracode.psm1                  # Module root loader
│
├── Core/
│   ├── Auth.ps1                   # HMAC-SHA256 signing (REST) + credential store
│   ├── ApiClient.ps1              # Invoke-VcApi wrapper (REST + XML API)
│   └── Config.ps1                 # Read/write ~/.veracode/credentials
│
├── Applications/
│   ├── Get-VcApplications.ps1
│   ├── New-VcApplication.ps1
│   ├── Set-VcApplication.ps1
│   └── Remove-VcApplication.ps1
│
├── Sandboxes/
│   ├── Get-VcSandboxes.ps1
│   ├── New-VcSandbox.ps1
│   ├── Set-VcSandbox.ps1
│   ├── Remove-VcSandbox.ps1
│   └── Invoke-VcSandboxPromotion.ps1
│
├── Scans/
│   ├── Get-VcScans.ps1
│   ├── Remove-VcScan.ps1
│   ├── Repair-VcStuckScan.ps1     # Detect + delete stuck scan, unblock pipeline
│   └── Resume-VcScan.ps1         # Delete blocking scan so a new one can proceed
│
├── Users/
│   ├── Get-VcUsers.ps1
│   ├── New-VcUser.ps1
│   ├── Set-VcUser.ps1
│   ├── Remove-VcUser.ps1
│   └── Set-VcUserRoles.ps1
│
├── Teams/
│   ├── Get-VcTeams.ps1
│   ├── New-VcTeam.ps1
│   ├── Set-VcTeamMembers.ps1
│   └── Remove-VcTeam.ps1
│
├── Findings/
│   ├── Get-VcFindings.ps1
│   └── Export-VcFindings.ps1
│
├── Policy/
│   ├── Get-VcPolicies.ps1
│   └── Invoke-VcPolicyEvaluation.ps1
│
├── Admin/
│   ├── Get-VcAuditLog.ps1
│   └── Export-VcReport.ps1
│
├── Analysis/
│   ├── Get-VcSeverityBreakdown.ps1
│   ├── Get-VcCweBreakdown.ps1
│   ├── Get-VcCategoryBreakdown.ps1
│   ├── Get-VcModuleBreakdown.ps1
│   ├── Get-VcPrescanModules.ps1
│   ├── Compare-VcScans.ps1        # Scan-to-scan diff (new/fixed/persisted)
│   ├── Get-VcFindingTrend.ps1     # Historical build trend
│   ├── Get-VcMitigationStatus.ps1
│   ├── Get-VcFlawDetail.ps1       # Deep flaw context (code/call chain)
│   └── Export-VcAnalysisReport.ps1 # Self-contained HTML report
│
├── SCA/
│   ├── Get-VcScaFindings.ps1
│   ├── Get-VcScaLibrarySummary.ps1
│   ├── Get-VcScaUpgrades.ps1      # Actionable upgrade checklist
│   ├── Get-VcScaLicenses.ps1      # License risk report
│   └── Get-VcScaExposure.ps1      # Org-wide blast-radius analysis
│
├── DAST/
│   ├── Get-VcDastScans.ps1
│   ├── Get-VcDastScan.ps1
│   ├── Start-VcDastScan.ps1
│   ├── Stop-VcDastScan.ps1
│   ├── Get-VcDastFindings.ps1
│   ├── Get-VcDastAnalysis.ps1     # URL heat map, attack vector dist.
│   ├── Compare-VcDastSast.ps1     # CWE overlap between DAST + SAST
│   └── Repair-VcDastScan.ps1      # Stuck DAST scan recovery
│
└── Dashboard/
    └── Show-VcDashboard.ps1       # Interactive TUI (menu-driven)
```

---

## Module Design Principles

1. **Single auth layer** — all API calls go through `Invoke-VcApi`; HMAC signing lives only in
   `Auth.ps1`. No script manages HTTP directly.

2. **Credential file** — `.veracode\credentials` in the module root (INI format, same schema
   as the Veracode CLI). Keeps credentials alongside the scripts on Windows without touching
   the user profile. Config.ps1 reads the `[default]` profile or a named profile via
   `-Profile`. Environment variables `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` override
   the file (useful for CI/CD).

3. **Pipeline-friendly output** — all Get-* functions return typed PSCustomObjects so results
   can be piped, filtered with `Where-Object`, and exported with `Export-Csv`/`ConvertTo-Json`.

4. **WhatIf/Confirm on destructive ops** — Remove-*, Repair-*, Resume-* all support `-WhatIf`
   and `-Confirm` via `ShouldProcess`.

5. **Pagination handled internally** — callers receive a flat array; page-walking happens inside
   each Get-* function.

6. **TUI uses no external dependencies** — the dashboard is built on `Write-Host` with ANSI
   colour codes and `Read-Host` for input; no third-party TUI library required.

---

## Authentication

- **REST API** (`api.veracode.com`) — HMAC-SHA256 signing per Veracode spec:
  `Authorization: VERACODE-HMAC-SHA-256 id=<API_ID>,ts=<timestamp>,nonce=<random_hex>,sig=<hmac>`
- **XML Upload API** (`analysiscenter.veracode.com`) — same HMAC signing, used only for
  build/prescan operations not yet in the REST surface.
- Credentials stored in `.veracode\credentials` (module root) as:
  ```ini
  [default]
  veracode_api_key_id = <id>
  veracode_api_key_secret = <secret>
  ```

---

## Scope: Feature Areas

### 1. Application Management
- List all apps with compliance status, last scan date, business unit
- Filter by policy compliance (PASSED / DID_NOT_PASS / NOT_ASSESSED), business unit, scan type
- Create, update, delete individual or bulk apps
- Bulk CSV import for creating many apps at once

### 2. Sandbox Management
- List sandboxes per app showing scan status
- Create / rename / delete sandboxes
- Promote a sandbox scan to policy scan

### 3. Scan Management & Stuck-Scan Recovery
- List scans per app/sandbox with status, age, module count
- Identify stuck scans (states: `INCOMPLETE`, `PRESCAN_SUBMITTED`, `SUBMITTED_TO_ENGINE`,
  `RESULTS_READY` for > threshold time)
- Delete the latest (blocking) scan with confirmation
- Resume flow: delete stuck/blocking scan → print next steps
- Bulk scan-status report across all apps

### 4. User Management
- List users with roles, teams, login status, last login date
- Create users individually or from CSV (bulk onboarding)
- Update roles and team assignments
- Deactivate / delete users (bulk by team or role filter)
- Export user roster to CSV

### 5. Team Management
- List teams with member counts
- Create / delete teams
- Add or remove members (by email or user ID)
- Move members between teams

### 6. Findings & Results
- List findings for an app (or sandbox) filtered by severity, scan type, CWE, flaw status
- Include mitigation annotations
- Export findings to CSV or JSON
- Cross-app summary: how many open High/Very High findings per app

### 10. Scan Results Analysis  *(new)*
In-depth analysis of what a completed scan produced, beyond raw finding lists:

- **Severity breakdown** — findings grouped and counted by severity level (0–5) with
  percentage of total; displayed as a text bar chart in the TUI
- **CWE heat map** — top N CWEs by count; shows CWE ID, name, count, and % of total findings
- **Category breakdown** — findings grouped by Veracode category (e.g., SQL Injection,
  XSS, Cryptography) using the `category_id` field
- **Module-level analysis** — which uploaded modules contribute the most findings; useful
  for identifying high-risk components
- **Scan-to-scan diff** — compare two builds of the same app: NEW findings (introduced),
  FIXED findings (closed), PERSISTED findings (unchanged). Uses `GET /appsec/v2/applications/
  {guid}/findings` with `build_id` param on both scans and computes the delta.
- **Historical trend** — fetches the build list (XML API `getbuildlist.do`) and pulls finding
  counts per severity for each past build, printing a mini trend table
- **Mitigation status report** — findings broken down by mitigation state:
  `NONE`, `PROPOSED`, `APPROVED`, `REJECTED`, `ACCEPTED`; highlights long-pending proposals
- **SCA (open-source) analysis** — filters to `scan_type=SCA`, groups by library name and
  version, shows CVE IDs and CVSS scores
- **Detailed flaw context** — for a specific finding, fetches `static_flaw_info` (code file,
  line number, surrounding code snippet context, call chain) or `dynamic_flaw_info`
- **Prescan module report** — fetches `getprescanresults.do` to show which modules were
  identified, their size, and whether they were selected for scanning
- **HTML report generation** — self-contained HTML file with all analysis sections, colour-
  coded severity tables, and a trend sparkline using ASCII art or inline SVG

### 7. Policy Management
- List policies
- Evaluate any app against any policy (ad-hoc compliance check)
- Show pass/fail reason detail

### 8. Admin & Audit
- Fetch audit log (if available via API)
- Generate HTML/CSV report: app compliance snapshot, scan health, user activity summary

### 9. TUI Dashboard
- Main menu with numbered options for each domain
- Application overview: table of all apps with compliance colour-coded
- Scan queue viewer: all in-flight scans across the org, sortable by age
- Stuck-scan finder: highlight scans older than N hours in a suspect state
- User quick-manage: search by email, view/edit roles inline
- Quick-action panel: fix stuck scan, promote sandbox, delete latest scan
- **Scan Analysis sub-menu**: select an app → select a build → view any analysis section
  inline (severity chart, CWE heat map, diff vs previous, mitigation tracker)

---

## TUI Layout (ASCII sketch)

```
╔══════════════════════════════════════════════════════╗
║          VERACODE MANAGEMENT CONSOLE                 ║
╠══════════════════════════════════════════════════════╣
║  [1] Applications    [2] Sandboxes    [3] Scans      ║
║  [4] Users           [5] Teams        [6] Findings   ║
║  [7] Policy          [8] Admin        [9] Analysis   ║
║  [Q] Quit                                            ║
╠══════════════════════════════════════════════════════╣
║  Profile: default    Org: Acme Corp   UTC 2026-07-30 ║
╚══════════════════════════════════════════════════════╝
```

Each submenu presents a table of items and a context-sensitive action menu (view, create,
edit, delete, promote, fix, export).

---

### 11. SCA Analysis
- List SCA findings filtered by CVSS score or license risk
- Library summary: group by library+version with all associated CVEs and fix availability
- Upgrade recommendations: actionable checklist of libraries with known safe versions
- License risk report: libraries grouped by license risk level (High / Medium / Low)
- Org-wide exposure: identify libraries present across multiple apps (blast-radius)
- SCA sub-menu in TUI

### 12. DAST (Dynamic Analysis)
- List DAST analyses (scans) with status, target URL, schedule
- Get scan details (auth config, crawl settings, allowed hosts)
- Start / stop DAST scans; stuck-scan recovery mirrors SAST flow
- DAST findings filtered by severity, URL pattern, CWE
- DAST analysis: URL/endpoint heat map, attack vector distribution, severity breakdown
- DAST vs SAST CWE overlap — findings confirmed by both = higher remediation priority
- DAST sub-menu in TUI

---

## Out of Scope (for now)
- Pipeline scan (CLI-based) orchestration
- Custom SAST rule editing
- SCA agent/container scan configuration (only reading results, not configuring agents)
