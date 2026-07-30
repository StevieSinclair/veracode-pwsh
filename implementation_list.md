# Veracode PowerShell Suite — Implementation List

Each item below is a self-contained implementation unit. Work through them in order; later items
depend on the Core layer being complete.

---

## Phase 0 — Scaffolding

### 0.1 Module Manifest & Loader
**File:** `Veracode.psd1`, `Veracode.psm1`
- [ ] Create `Veracode.psd1` with `ModuleVersion`, `Author`, `FunctionsToExport = '*'`
- [ ] Create `Veracode.psm1` that dot-sources every `*.ps1` under subdirectories in load order
      (Core first, then domain modules, then Dashboard)
- [ ] Add `$ErrorActionPreference = 'Stop'` at module root

### 0.2 Directory Structure
- [ ] Create folders: `Core/`, `Applications/`, `Sandboxes/`, `Scans/`, `Users/`, `Teams/`,
      `Findings/`, `Policy/`, `Admin/`, `Dashboard/`

---

## Phase 1 — Core Layer

### 1.1 Credential & Config  (`Core/Config.ps1`)
**Functions:** `Get-VcCredential`, `Set-VcCredential`
- [ ] Read `.veracode\credentials` relative to module root (INI parser, supports multiple profiles)
- [ ] `Get-VcCredential [-Profile <string>]` — returns `@{Id=...; Secret=...}`
- [ ] `Set-VcCredential -Id <string> -Secret <string> [-Profile <string>]` — writes/updates file
- [ ] If credentials file absent, prompt interactively and offer to save
- [ ] Expose `$VcCurrentProfile` module-level variable defaulting to `'default'`

### 1.2 HMAC-SHA256 Signing  (`Core/Auth.ps1`)
**Functions:** `New-VcAuthHeader`
- [ ] Implement Veracode HMAC-SHA256 signing spec:
  - Generate 16-byte random nonce (hex string)
  - Build signing string: `id={id}\nhost={host}\nurl={url_path_and_query}\nveracode_request_timestamp={ts}`
  - Derive signing key: `HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(secret_bytes, nonce), ts), "vcode_request_version_1")`
  - Compute signature: `HMAC-SHA256(signing_key, signing_string)`
- [ ] Return Authorization header string: `VERACODE-HMAC-SHA-256 id=...,ts=...,nonce=...,sig=...`
- [ ] Unit-test with a known API ID/key/nonce/ts → expected sig (from Veracode docs example)

### 1.3 HTTP Client  (`Core/ApiClient.ps1`)
**Functions:** `Invoke-VcApi`, `Invoke-VcXmlApi`
- [ ] `Invoke-VcApi -Method <GET|POST|PUT|DELETE> -Path <string> [-Body <hashtable>] [-Query <hashtable>]`
  - Builds full URL: `https://api.veracode.com` + Path + query string
  - Calls `New-VcAuthHeader` to sign the request
  - Sends via `Invoke-RestMethod`
  - Handles HTTP 429 (rate limit) with exponential back-off (3 retries)
  - Throws descriptive error on non-2xx
  - Returns parsed JSON body
- [ ] `Invoke-VcXmlApi -Path <string> [-Params <hashtable>]` — same pattern for XML API base URL,
      returns `[xml]` object
- [ ] Internal helper `ConvertTo-QueryString` for hashtable → `?key=val&key2=val2`

---

## Phase 2 — Application Management

### 2.1 List Applications  (`Applications/Get-VcApplications.ps1`)
**Function:** `Get-VcApplications`
- [ ] Parameters: `-Name <string>` (wildcard filter), `-PolicyCompliance <string>`,
      `-BusinessUnit <string>`, `-ScanType <string>`, `-All` (default)
- [ ] Pages through `GET /appsec/v1/applications` collecting all pages
- [ ] Returns objects with: `Guid`, `Name`, `LegacyId`, `BusinessUnit`, `PolicyName`,
      `PolicyCompliance`, `LastCompletedScanDate`, `Teams`
- [ ] `-Name` supports `*` wildcard (client-side filter after full fetch)

### 2.2 Get Single Application
- [ ] `Get-VcApplication -Guid <string>` — `GET /appsec/v1/applications/{guid}`
- [ ] Also accept `-LegacyId <int>` (fetches via `?legacy_id=`)

### 2.3 Create Application  (`Applications/New-VcApplication.ps1`)
**Function:** `New-VcApplication`
- [ ] Parameters: `-Name <string>` (required), `-BusinessCriticality <string>` (required,
      `VERY_HIGH|HIGH|MEDIUM|LOW|VERY_LOW`), `-PolicyGuid <string>`, `-Teams <string[]>`,
      `-BusinessUnit <string>`, `-Description <string>`
- [ ] `POST /appsec/v1/applications`
- [ ] Supports `-WhatIf`
- [ ] Prints created app GUID on success

### 2.4 Update Application  (`Applications/Set-VcApplication.ps1`)
**Function:** `Set-VcApplication`
- [ ] Parameters: `-Guid <string>` (required), `-Name`, `-PolicyGuid`, `-Teams`, `-Description`
- [ ] `PUT /appsec/v1/applications/{guid}`
- [ ] Accepts pipeline input from `Get-VcApplications`

### 2.5 Delete Application  (`Applications/Remove-VcApplication.ps1`)
**Function:** `Remove-VcApplication`
- [ ] Parameters: `-Guid <string>`, pipeline input
- [ ] `DELETE /appsec/v1/applications/{guid}`
- [ ] Requires `-Confirm` or explicit `-Force`; supports `-WhatIf`
- [ ] Bulk: `Get-VcApplications -Name "test-*" | Remove-VcApplication -WhatIf`

### 2.6 Bulk CSV Import
**Function:** `Import-VcApplications`
- [ ] `-CsvPath <string>` — CSV with columns `Name,BusinessCriticality,PolicyGuid,Teams`
- [ ] Calls `New-VcApplication` for each row
- [ ] Outputs success/fail summary table

---

## Phase 3 — Sandbox Management

### 3.1 List Sandboxes  (`Sandboxes/Get-VcSandboxes.ps1`)
**Function:** `Get-VcSandboxes`
- [ ] Parameters: `-AppGuid <string>` (required)
- [ ] `GET /appsec/v1/applications/{app_guid}/sandboxes`
- [ ] Returns: `SandboxGuid`, `Name`, `SandboxType`, `LastModifiedDate`, `AutoRecreate`

### 3.2 Create Sandbox  (`Sandboxes/New-VcSandbox.ps1`)
**Function:** `New-VcSandbox`
- [ ] Parameters: `-AppGuid <string>`, `-Name <string>`, `-AutoRecreate <bool>`
- [ ] `POST /appsec/v1/applications/{app_guid}/sandboxes`
- [ ] Supports `-WhatIf`

### 3.3 Update Sandbox  (`Sandboxes/Set-VcSandbox.ps1`)
**Function:** `Set-VcSandbox`
- [ ] Parameters: `-AppGuid`, `-SandboxGuid`, `-Name`, `-AutoRecreate`
- [ ] `PUT /appsec/v1/applications/{app_guid}/sandboxes/{sandbox_guid}`

### 3.4 Delete Sandbox  (`Sandboxes/Remove-VcSandbox.ps1`)
**Function:** `Remove-VcSandbox`
- [ ] Parameters: `-AppGuid`, `-SandboxGuid`, pipeline input
- [ ] `DELETE /appsec/v1/applications/{app_guid}/sandboxes/{sandbox_guid}`
- [ ] Requires `-Force` or confirmation prompt

### 3.5 Promote Sandbox Scan  (`Sandboxes/Invoke-VcSandboxPromotion.ps1`)
**Function:** `Invoke-VcSandboxPromotion`
- [ ] Parameters: `-AppGuid`, `-SandboxGuid`
- [ ] `POST /appsec/v1/applications/{app_guid}/sandboxes/{sandbox_guid}/promote`
- [ ] Confirms before promoting; prints result

---

## Phase 4 — Scan Management & Stuck-Scan Recovery

### 4.1 List Scans  (`Scans/Get-VcScans.ps1`)
**Function:** `Get-VcScans`
- [ ] Parameters: `-AppGuid <string>`, `-SandboxGuid <string>` (optional, for sandbox scans),
      `-Status <string>` (filter), `-OlderThanHours <int>` (filter)
- [ ] `GET /appsec/v1/applications/{app_guid}/scans` (+ sandbox variant)
- [ ] Returns: `ScanId`, `AppGuid`, `SandboxGuid`, `Status`, `SubmittedDate`, `AgeHours`,
      `ModuleCount`, `ScanType`
- [ ] Calculates `AgeHours` from `SubmittedDate` to now

### 4.2 Delete a Scan  (`Scans/Remove-VcScan.ps1`)
**Function:** `Remove-VcScan`
- [ ] Parameters: `-AppGuid`, `-ScanId`, pipeline input from `Get-VcScans`
- [ ] `DELETE /appsec/v1/applications/{app_guid}/scans/{scan_id}`
- [ ] Supports `-WhatIf` and `-Confirm`
- [ ] For sandbox scans: accept `-SandboxGuid` and use sandbox scan endpoint

### 4.3 Stuck-Scan Detection & Repair  (`Scans/Repair-VcStuckScan.ps1`)
**Function:** `Repair-VcStuckScan`
- [ ] Parameters: `-AppGuid <string>` (or `-All` for org-wide scan), `-ThresholdHours <int>`
      (default 4), `-WhatIf`, `-Force`
- [ ] Stuck states: `INCOMPLETE`, `PRESCAN_SUBMITTED`, `SUBMITTED_TO_ENGINE`,
      `SCAN_IN_PROGRESS` when `AgeHours > ThresholdHours`
- [ ] Algorithm:
  1. `Get-VcScans` for app (or all apps if `-All`)
  2. Filter to stuck scans by state + age
  3. Display table of stuck scans with app name, scan ID, state, age
  4. Prompt confirmation (or auto-proceed with `-Force`)
  5. Call `Remove-VcScan` for each
  6. Report how many deleted vs failed
- [ ] `-All` mode: pages through all apps, collects stuck scans, shows consolidated report

### 4.4 Resume / Unblock a Scan  (`Scans/Resume-VcScan.ps1`)
**Function:** `Resume-VcScan`
- [ ] Thin wrapper: identifies the latest scan for an app (or sandbox), deletes it with
      confirmation, prints message "Pipeline unblocked — submit a new scan now."
- [ ] Parameters: `-AppGuid`, `-SandboxGuid` (optional), `-Latest` (default: delete latest only)
- [ ] Safety: refuses to delete if scan status is `RESULTS_READY` (completed) unless `-Force`

### 4.5 Org-Wide Scan Health Report
**Function:** `Get-VcScanHealth`
- [ ] Pages all apps → fetches current scan for each → builds summary table:
  `AppName | Status | AgeHours | Stuck?`
- [ ] Color codes in TUI: green=ok, yellow=slow, red=stuck
- [ ] `-Export <path>` writes CSV

---

## Phase 5 — User Management

### 5.1 List Users  (`Users/Get-VcUsers.ps1`)
**Function:** `Get-VcUsers`
- [ ] Parameters: `-Email <string>` (wildcard), `-Role <string>`, `-TeamGuid <string>`,
      `-Inactive` (filter to disabled accounts)
- [ ] `GET /api/authn/v2/users` with pagination
- [ ] Returns: `UserId`, `Email`, `FirstName`, `LastName`, `Roles`, `Teams`, `LoginEnabled`,
      `LastLoginDate`

### 5.2 Create User  (`Users/New-VcUser.ps1`)
**Function:** `New-VcUser`
- [ ] Parameters: `-Email`, `-FirstName`, `-LastName`, `-Roles <string[]>`, `-Teams <string[]>`,
      `-Type <human|service>` (default `human`)
- [ ] `POST /api/authn/v2/users`
- [ ] Supports `-WhatIf`

### 5.3 Update User  (`Users/Set-VcUser.ps1`)
**Function:** `Set-VcUser`
- [ ] Parameters: `-UserId`, pipeline input; updatable: `-Roles`, `-Teams`, `-LoginEnabled`
- [ ] `PUT /api/authn/v2/users/{user_id}`

### 5.4 Delete / Deactivate User  (`Users/Remove-VcUser.ps1`)
**Function:** `Remove-VcUser`
- [ ] Parameters: `-UserId`, `-Deactivate` (set `login_enabled=false` instead of delete)
- [ ] `DELETE /api/authn/v2/users/{user_id}` or PUT with `login_enabled=false`
- [ ] Supports `-WhatIf`, `-Force`

### 5.5 Bulk Role Assignment  (`Users/Set-VcUserRoles.ps1`)
**Function:** `Set-VcUserRoles`
- [ ] Parameters: `-UserId <string[]>` or pipeline, `-AddRoles <string[]>`, `-RemoveRoles <string[]>`
- [ ] Fetches current roles, merges delta, calls `Set-VcUser`
- [ ] Supports `-WhatIf`

### 5.6 Bulk CSV Import
**Function:** `Import-VcUsers`
- [ ] `-CsvPath` with columns `Email,FirstName,LastName,Roles,Teams`
- [ ] Calls `New-VcUser` per row; summary on completion

### 5.7 Export User Roster
**Function:** `Export-VcUsers`
- [ ] `-OutputPath <string>` — writes `Get-VcUsers` results to CSV

---

## Phase 6 — Team Management

### 6.1 List Teams  (`Teams/Get-VcTeams.ps1`)
**Function:** `Get-VcTeams`
- [ ] `GET /api/authn/v2/teams` with pagination
- [ ] Returns: `TeamId`, `TeamName`, `MemberCount`, `BusinessUnit`

### 6.2 Create Team  (`Teams/New-VcTeam.ps1`)
**Function:** `New-VcTeam`
- [ ] Parameters: `-Name`, `-BusinessUnit`
- [ ] `POST /api/authn/v2/teams`

### 6.3 Manage Team Members  (`Teams/Set-VcTeamMembers.ps1`)
**Function:** `Set-VcTeamMembers`
- [ ] Parameters: `-TeamId`, `-AddUsers <string[]>` (email or user ID), `-RemoveUsers <string[]>`
- [ ] Fetches team, resolves user IDs, PUTs updated member list

### 6.4 Delete Team  (`Teams/Remove-VcTeam.ps1`)
**Function:** `Remove-VcTeam`
- [ ] `DELETE /api/authn/v2/teams/{team_id}`; `-Force` required

---

## Phase 7 — Findings & Results

### 7.1 Get Findings  (`Findings/Get-VcFindings.ps1`)
**Function:** `Get-VcFindings`
- [ ] Parameters: `-AppGuid`, `-SandboxGuid`, `-ScanType <STATIC|DYNAMIC|MANUAL|SCA>`,
      `-Severity <int>` (0–5 minimum), `-CweId <int>`, `-FlawStatus <string>`,
      `-IncludeAnnotations`
- [ ] `GET /appsec/v2/applications/{app_guid}/findings` with filters
- [ ] Returns: `IssueId`, `Title`, `Severity`, `CweId`, `ScanType`, `FlawStatus`,
      `FileName`, `LineNumber`, `MitigationStatus`

### 7.2 Export Findings  (`Findings/Export-VcFindings.ps1`)
**Function:** `Export-VcFindings`
- [ ] `-AppGuid` (or `-All` across org), `-OutputPath`, `-Format <CSV|JSON>`
- [ ] Streams results page by page to avoid memory pressure on large finding sets

### 7.3 Org-Wide Findings Summary
**Function:** `Get-VcFindingsSummary`
- [ ] Iterates all apps, fetches count of open findings by severity
- [ ] Outputs table: `AppName | VeryHigh | High | Medium | Low | VeryLow`
- [ ] `-PolicyNonCompliantOnly` filters to apps that are DID_NOT_PASS

---

## Phase 8 — Policy Management

### 8.1 List Policies  (`Policy/Get-VcPolicies.ps1`)
**Function:** `Get-VcPolicies`
- [ ] `GET /appsec/v1/policies`
- [ ] Returns: `PolicyGuid`, `Name`, `Description`, `ScanFrequencyDays`, `FindingRules`

### 8.2 Evaluate App Against Policy  (`Policy/Invoke-VcPolicyEvaluation.ps1`)
**Function:** `Invoke-VcPolicyEvaluation`
- [ ] Parameters: `-AppGuid`, `-PolicyGuid`
- [ ] `POST /appsec/v1/applications/{app_guid}/policy-evaluations`
- [ ] Returns pass/fail with reason detail (scan frequency, past-due findings)

---

## Phase 9 — Admin & Reporting

### 9.1 Org Compliance Snapshot  (`Admin/Export-VcReport.ps1`)
**Function:** `Export-VcReport`
- [ ] Combines: all apps + compliance status + open finding counts + scan health
- [ ] `-OutputPath` — generates CSV or simple HTML table report
- [ ] Sections: App Compliance, Scan Health, User Activity summary

### 9.2 Bulk Scan Status Report
**Function:** `Get-VcScanReport`
- [ ] All apps in org → latest scan state → export table
- [ ] Highlights stuck or overdue scans in red (HTML) / "STUCK" label (CSV)

---

## Phase 10 — Interactive TUI Dashboard

### 10.1 Main Menu  (`Dashboard/Show-VcDashboard.ps1`)
**Function:** `Show-VcDashboard`
- [ ] Render header bar: profile name, org name (from first app fetch), UTC date
- [ ] Numbered menu items: Applications, Sandboxes, Scans, Users, Teams, Findings, Policy, Admin, Quit
- [ ] Loop: read key → dispatch to sub-menu function → clear screen → re-render
- [ ] Catch errors and show inline without crashing the TUI

### 10.2 Application Sub-Menu
- [ ] Show table of all apps (paginated view, 20 per screen, N/P to navigate)
- [ ] Columns: `#`, `Name`, `Compliance`, `Last Scan`, `BU`
- [ ] Compliance colour: green=PASSED, red=DID_NOT_PASS, grey=NOT_ASSESSED
- [ ] Actions: `[V]iew`, `[C]reate`, `[E]dit`, `[D]elete`, `[B]ack`
- [ ] View drills into app → lists sandboxes inline

### 10.3 Scan Queue / Health Sub-Menu
- [ ] Live table: all in-flight scans across the org (calls `Get-VcScanHealth`)
- [ ] Highlight stuck scans (age > threshold) in red
- [ ] Actions: `[F]ix stuck` (calls `Repair-VcStuckScan` on selected), `[R]esume/delete latest`,
      `[P]romote sandbox scan`, `[B]ack`
- [ ] `[R]efresh` re-fetches without leaving sub-menu

### 10.4 User Management Sub-Menu
- [ ] Search by email prompt at entry
- [ ] Table of matching users with roles and teams
- [ ] Actions: `[C]reate`, `[E]dit roles/teams`, `[D]eactivate`, `[X]Delete`, `[B]ack`
- [ ] Edit roles: display checkbox-style list of available roles, toggle with number keys

### 10.5 Quick-Action Panel
- [ ] Accessible from main menu as `[Q]uick Actions`
- [ ] One-liner ops:
  - Fix all stuck scans older than N hours (prompts for N)
  - Export all findings for an app to CSV (prompts for app name)
  - Promote sandbox scan (prompts for app + sandbox)
  - Add/remove user from team (prompts for email + team name)

---

## Phase 11 — Quality-of-Life Scripts

### 11.1 Watch Scan Progress
**Function:** `Watch-VcScan`
- [ ] Parameters: `-AppGuid`, `-SandboxGuid`, `-IntervalSeconds <int>` (default 30)
- [ ] Polls scan status and prints a progress line every interval
- [ ] Exits when status reaches `RESULTS_READY` or a terminal error state
- [ ] Plays console bell on completion (optional `-Bell`)

### 11.2 Clone Application Settings
**Function:** `Copy-VcApplication`
- [ ] Parameters: `-SourceGuid`, `-NewName`
- [ ] Fetches source app profile, creates new app with same policy/teams/BU/criticality

### 11.3 Batch Sandbox Cleanup
**Function:** `Remove-VcOldSandboxes`
- [ ] Parameters: `-AppGuid`, `-OlderThanDays <int>`, `-WhatIf`
- [ ] Deletes sandboxes whose `LastModifiedDate` is older than threshold
- [ ] Skips sandboxes whose latest scan is `RESULTS_READY` (preserve completed results)

### 11.4 Credential Setup Wizard
**Function:** `Initialize-VcCredentials`
- [ ] Interactive prompts for API ID and secret (masked input)
- [ ] Validates by making a test API call (`GET /appsec/v1/applications?size=1`)
- [ ] Writes to `.veracode\credentials` in the module root

### 11.5 Open Findings Age Report
**Function:** `Get-VcFindingAge`
- [ ] For an app, shows each open finding with how many days it has been open
- [ ] Highlights findings approaching SLA deadline based on policy grace period

---

## Phase 12 — Scan Results Analysis  (`Analysis/`)

All analysis functions operate on a completed scan (build). They accept `-AppGuid` + `-BuildId`
(or default to the latest completed build when `-BuildId` is omitted). The XML API
(`detailedreport.do`, `getbuildlist.do`, `getprescanresults.do`) is used for data that is not
yet exposed in the REST surface; the REST findings endpoint is used for everything else.

### 12.1 Severity Breakdown  (`Analysis/Get-VcSeverityBreakdown.ps1`)
**Function:** `Get-VcSeverityBreakdown`
- [ ] Parameters: `-AppGuid`, `-BuildId` (optional), `-SandboxGuid` (optional)
- [ ] Fetches all findings; groups by `severity` (0=Informational … 5=Very High)
- [ ] Outputs table: `Severity | Label | Count | % of Total`
- [ ] In TUI: renders horizontal bar chart using block characters (`█`) scaled to terminal width
- [ ] `-Export <path>` writes CSV

### 12.2 CWE Heat Map  (`Analysis/Get-VcCweBreakdown.ps1`)
**Function:** `Get-VcCweBreakdown`
- [ ] Parameters: `-AppGuid`, `-BuildId`, `-Top <int>` (default 20)
- [ ] Groups findings by `cwe_id`; looks up CWE name from a local bundled `cwemap.json`
      (CWE ID → name, maintained in `Data/cwemap.json`)
- [ ] Outputs table: `Rank | CWE ID | Name | Count | Severity Distribution`
- [ ] Severity distribution shown as colour-coded mini-bar (VH/H/M/L/VL/Info counts inline)
- [ ] `-Export <path>` writes CSV

### 12.3 Category Breakdown  (`Analysis/Get-VcCategoryBreakdown.ps1`)
**Function:** `Get-VcCategoryBreakdown`
- [ ] Groups findings by Veracode `finding_category_id` / `finding_category_name`
- [ ] Outputs: `Category | Count | VH | H | M | L | VL` count columns
- [ ] Useful for identifying which vulnerability classes dominate the scan

### 12.4 Module-Level Analysis  (`Analysis/Get-VcModuleBreakdown.ps1`)
**Function:** `Get-VcModuleBreakdown`
- [ ] Uses XML `detailedreport.do` (returns per-module finding counts in the report XML)
- [ ] Alternatively correlates `files.source_file.file` paths to module names if REST only
- [ ] Outputs: `Module | Total Findings | VH | H | M`
- [ ] Highlights modules exceeding a threshold (`-Threshold <int>`, default 10 High+VH)

### 12.5 Prescan Module Report  (`Analysis/Get-VcPrescanModules.ps1`)
**Function:** `Get-VcPrescanModules`
- [ ] XML API: `GET /api/5.0/getprescanresults.do?build_id={build_id}`
- [ ] Parses `prescanresults` XML; outputs: `Module | Platform | Size | Selected | WarnCount`
- [ ] Flags modules that were not selected for scan (common source of missed coverage)
- [ ] `-BuildId` defaults to latest build for the app

### 12.6 Scan-to-Scan Diff  (`Analysis/Compare-VcScans.ps1`)
**Function:** `Compare-VcScans`
- [ ] Parameters: `-AppGuid`, `-BaselineBuildId <string>`, `-CurrentBuildId <string>`
      (if `-CurrentBuildId` omitted: latest build; if `-BaselineBuildId` omitted: second-latest)
- [ ] Fetches findings for both builds; matches on `issue_id` (stable across builds)
- [ ] Produces three lists:
  - **NEW** — `issue_id` present in current but not baseline
  - **FIXED** — `issue_id` present in baseline but not current
  - **PERSISTED** — present in both (compares severity/flaw_status for changes)
- [ ] Outputs summary: `+{new} new  -{fixed} fixed  ={persisted} unchanged`
- [ ] `-Verbose` lists each finding in each category
- [ ] `-Export <path>` writes three CSV sheets (or one with a `ChangeType` column)

### 12.7 Historical Trend  (`Analysis/Get-VcFindingTrend.ps1`)
**Function:** `Get-VcFindingTrend`
- [ ] Parameters: `-AppGuid`, `-LastNBuilds <int>` (default 10), `-Severity <string>` (optional)
- [ ] XML API `getbuildlist.do` to list builds (build IDs + dates)
- [ ] For each build: fetch finding counts by severity (use `summaryreport.do` or findings API)
- [ ] Outputs table: `Build# | Date | VH | H | M | L | VL | Total`
- [ ] In TUI: ASCII sparkline trend for Very High + High counts across builds

### 12.8 Mitigation Status Report  (`Analysis/Get-VcMitigationStatus.ps1`)
**Function:** `Get-VcMitigationStatus`
- [ ] Parameters: `-AppGuid`, `-BuildId`, `-PendingOnly` (show only PROPOSED/unanswered)
- [ ] Uses `GET /appsec/v2/applications/{guid}/findings?include_annot=TRUE`
- [ ] Groups by `mitigation_status`: `NONE | PROPOSED | APPROVED | REJECTED | ACCEPTED`
- [ ] For PROPOSED: shows days since proposal (flag if > 30 days with no action)
- [ ] Outputs table + optional export

### 12.9 Detailed Flaw Context  (`Analysis/Get-VcFlawDetail.ps1`)
**Function:** `Get-VcFlawDetail`
- [ ] Parameters: `-AppGuid`, `-IssueId <string>`, `-SandboxGuid` (optional)
- [ ] `GET /appsec/v2/applications/{guid}/findings/{issue_id}/static_flaw_info`
      or `dynamic_flaw_info` depending on scan type
- [ ] Returns and displays: file path, line number, CWE, description, call chain / attack vector
- [ ] Pretty-prints code context block when `source_file` and `line_number` are available
- [ ] Drillable from the TUI findings table with `[D]etail` action

### 12.10 HTML Report Generator  (`Analysis/Export-VcAnalysisReport.ps1`)
**Function:** `Export-VcAnalysisReport`
- [ ] Parameters: `-AppGuid`, `-BuildId`, `-OutputPath <string>`, `-IncludeSections <string[]>`
      (default: all sections)
- [ ] Runs: severity breakdown, CWE heat map, category breakdown, module breakdown,
      mitigation status, scan diff vs previous build
- [ ] Generates a self-contained HTML file:
  - Header with app name, build ID, scan date, policy compliance status
  - Severity table with colour-coded rows (red=VH, orange=H, yellow=M)
  - CWE top-20 table
  - Category breakdown table
  - Module hotspot table
  - Scan diff summary (new/fixed/persisted counts)
  - Mitigation pipeline table
  - ASCII trend table embedded as `<pre>` block
- [ ] No external JS/CSS dependencies; all styles inlined

---

## Phase 13 — SCA (Software Composition Analysis)  (`SCA/`)

SCA findings are retrieved via the same findings endpoint with `scan_type=SCA`. Additional
metadata (CVE IDs, library names, CVSS scores, license) comes from the findings payload.

### 13.1 List SCA Findings  (`SCA/Get-VcScaFindings.ps1`)
**Function:** `Get-VcScaFindings`
- [ ] Parameters: `-AppGuid`, `-BuildId`, `-MinCvss <float>`, `-LicenseRisk <string>`
- [ ] `GET /appsec/v2/applications/{guid}/findings?scan_type=SCA`
- [ ] Returns: `Library`, `Version`, `CVE`, `CvssScore`, `Severity`, `FixedInVersion`,
      `LicenseRisk`, `FlawStatus`
- [ ] `-MinCvss` filters to findings with CVSS ≥ threshold (e.g., `7.0` for High+)

### 13.2 SCA Library Summary  (`SCA/Get-VcScaLibrarySummary.ps1`)
**Function:** `Get-VcScaLibrarySummary`
- [ ] Groups SCA findings by library name + version
- [ ] For each library: list all associated CVEs, max CVSS, count of findings, fix available?
- [ ] Outputs: `Library | Version | CVE Count | Max CVSS | Highest Severity | Fix Available`
- [ ] Flags libraries with known fix (when `fixed_in_version` is populated)

### 13.3 SCA Upgrade Recommendations  (`SCA/Get-VcScaUpgrades.ps1`)
**Function:** `Get-VcScaUpgrades`
- [ ] Filters SCA findings where `fixed_in_version` is non-null
- [ ] Groups by library; outputs: `Library | Current Version | Safe Version | CVEs Resolved`
- [ ] Acts as an actionable upgrade checklist
- [ ] `-Export <path>` writes CSV

### 13.4 SCA License Risk Report  (`SCA/Get-VcScaLicenses.ps1`)
**Function:** `Get-VcScaLicenses`
- [ ] Extracts `license_risk` field from SCA findings
- [ ] Groups by risk level: `HIGH | MEDIUM | LOW | UNRECOGNIZED`
- [ ] Outputs: `Library | Version | License | Risk Level`
- [ ] Useful for legal/compliance review alongside security findings

### 13.5 Org-Wide SCA Exposure  (`SCA/Get-VcScaExposure.ps1`)
**Function:** `Get-VcScaExposure`
- [ ] Iterates all apps (or a filtered subset) fetching SCA findings for each
- [ ] Identifies libraries appearing across multiple apps (blast-radius analysis)
- [ ] Outputs: `Library | Version | App Count | Apps | Max CVSS | CVEs`
- [ ] Highlights libraries present in 3+ apps with CVSS ≥ 7.0 as critical exposure
- [ ] `-Export <path>` writes CSV

### 13.6 SCA Analysis in TUI
- [ ] Add `[S]CA` action to the Findings sub-menu
- [ ] Sub-menu: Library Summary → Upgrade Recommendations → License Risk → Org Exposure
- [ ] Library detail: drill into a library to see all CVEs and affected apps

---

## Phase 14 — DAST (Dynamic Analysis)  (`DAST/`)

DAST scans have their own scan lifecycle and finding types. Key differences from SAST:
findings include `attack_vector`, `url`, `http_method`, and response context rather than
source file/line. DAST scan management uses the Dynamic Analysis REST API.

### 14.1 List DAST Scans  (`DAST/Get-VcDastScans.ps1`)
**Function:** `Get-VcDastScans`
- [ ] `GET /was/configservice/v1/analyses` — lists dynamic analyses (DAST scans)
- [ ] Returns: `AnalysisId`, `Name`, `Status`, `ScanType`, `SubmittedDate`, `CompletedDate`,
      `AppGuid`, `Url`
- [ ] Parameters: `-Status <string>`, `-AppGuid <string>`, `-All`

### 14.2 Get DAST Scan Details  (`DAST/Get-VcDastScan.ps1`)
**Function:** `Get-VcDastScan`
- [ ] `GET /was/configservice/v1/analyses/{analysis_id}`
- [ ] Returns full configuration: target URLs, scan settings, auth config reference,
      allowed hosts, crawl configuration, schedule

### 14.3 Start / Schedule DAST Scan  (`DAST/Start-VcDastScan.ps1`)
**Function:** `Start-VcDastScan`
- [ ] Parameters: `-AnalysisId <string>` (run existing config) or full config params
- [ ] `PUT /was/configservice/v1/analyses/{analysis_id}` with `start_time` set to now
- [ ] Supports `-WhatIf`

### 14.4 Stop DAST Scan  (`DAST/Stop-VcDastScan.ps1`)
**Function:** `Stop-VcDastScan`
- [ ] `DELETE /was/configservice/v1/analyses/{analysis_id}/scan`
- [ ] Requires `-Confirm` or `-Force`

### 14.5 Get DAST Findings  (`DAST/Get-VcDastFindings.ps1`)
**Function:** `Get-VcDastFindings`
- [ ] `GET /appsec/v2/applications/{app_guid}/findings?scan_type=DYNAMIC`
- [ ] Returns: `IssueId`, `Title`, `Severity`, `CweId`, `Url`, `HttpMethod`,
      `AttackVector`, `FlawStatus`, `MitigationStatus`
- [ ] Parameters: `-AppGuid`, `-MinSeverity <int>`, `-Url <string>` (wildcard filter on URL)

### 14.6 DAST Findings Analysis  (`DAST/Get-VcDastAnalysis.ps1`)
**Function:** `Get-VcDastAnalysis`
- [ ] Severity breakdown specific to DAST findings (same structure as 12.1 but DAST-only)
- [ ] CWE breakdown for DAST findings
- [ ] **URL/endpoint heat map**: groups findings by base URL path; shows which endpoints have
      the most vulnerabilities — `Endpoint | Finding Count | Highest Severity | CWEs`
- [ ] **Attack vector distribution**: groups by attack vector type (e.g., URL parameter,
      cookie, header, form field)
- [ ] Outputs combined analysis report; `-Export <path>` writes HTML or CSV

### 14.7 DAST vs SAST Overlap  (`DAST/Compare-VcDastSast.ps1`)
**Function:** `Compare-VcDastSast`
- [ ] Fetches SAST and DAST findings for the same app; matches on `cwe_id`
- [ ] Identifies CWEs confirmed by both scan types (higher confidence findings)
- [ ] Outputs: `CWE | Name | SAST Count | DAST Count | Overlap?`
- [ ] Helps prioritise remediation: overlapping findings = confirmed exploitability

### 14.8 DAST Scan Health & Stuck DAST Scans  (`DAST/Repair-VcDastScan.ps1`)
**Function:** `Repair-VcDastScan`
- [ ] Lists DAST analyses stuck in `RUNNING`/`SUBMITTED` state beyond `-ThresholdHours` (default 8)
- [ ] Calls `Stop-VcDastScan` for confirmed stuck analyses
- [ ] Mirrors the same UX as `Repair-VcStuckScan` for SAST

### 14.9 DAST Sub-Menu in TUI
- [ ] Add `[D]AST` to main TUI menu (or nest under Scans menu)
- [ ] Sub-menu: List Scans → DAST Findings → DAST Analysis → DAST vs SAST → Stop Scan

---

## Implementation Order Summary

| Phase | Priority | Prerequisite |
|-------|----------|-------------|
| 0 — Scaffolding | Critical | None |
| 1 — Core (Auth + HTTP) | Critical | Phase 0 |
| 2 — Applications | High | Phase 1 |
| 3 — Sandboxes | High | Phase 2 |
| 4 — Scans + Recovery | High | Phase 3 |
| 5 — Users | High | Phase 1 |
| 6 — Teams | Medium | Phase 5 |
| 7 — Findings | Medium | Phase 2 |
| 8 — Policy | Medium | Phase 2 |
| 9 — Admin/Reports | Medium | Phases 2,5,7 |
| 10 — TUI Dashboard | Medium | Phases 2–9 |
| 11 — QOL Scripts | Low | Phases 2–5 |
| 12 — Scan Results Analysis | High | Phases 4,7 |
| 13 — SCA Analysis | High | Phase 7 |
| 14 — DAST | Medium | Phases 4,7 |

---

## Testing Strategy

- Each Core function: inline Pester tests in `Tests/Core.Tests.ps1` using mock HTTP responses
- HMAC signing: compare output against Veracode-published test vector before any live calls
- Destructive functions: always test with `-WhatIf` first; live tests against a sandbox app
- TUI: manual smoke-test; no automated tests for interactive prompts
