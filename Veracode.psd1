@{
    ModuleVersion     = '0.1.0'
    GUID              = 'a3f2c8d1-7e45-4b09-9f62-1a0d3e5c8b7f'
    Author            = 'Veracode Admin Tooling'
    Description       = 'PowerShell management suite for Veracode — applications, scans, users, findings, SCA, DAST, and TUI dashboard.'
    PowerShellVersion = '7.0'
    RootModule        = 'Veracode.psm1'
    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('Veracode', 'AppSec', 'SAST', 'DAST', 'SCA', 'Security')
        }
    }
}
