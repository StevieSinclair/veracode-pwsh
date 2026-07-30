#Requires -Modules Pester

BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $ModuleRoot 'Core/Config.ps1')
    . (Join-Path $ModuleRoot 'Core/Auth.ps1')
    . (Join-Path $ModuleRoot 'Core/ApiClient.ps1')

    # Module-level variable required by Get-VcCredential default
    $script:VcCurrentProfile = 'default'
}

Describe 'ConvertFrom-HexString' {
    It 'decodes known hex to bytes' {
        $bytes = ConvertFrom-HexString 'deadbeef'
        $bytes | Should -Be @(0xde, 0xad, 0xbe, 0xef)
    }
    It 'is case-insensitive' {
        $lower = ConvertFrom-HexString 'ff00'
        $upper = ConvertFrom-HexString 'FF00'
        $lower | Should -Be $upper
    }
    It 'throws on odd-length input' {
        { ConvertFrom-HexString 'abc' } | Should -Throw
    }
}

Describe 'New-VcAuthHeader' {
    It 'returns a header string matching the expected format' {
        $header = New-VcAuthHeader `
            -ApiId     'testid' `
            -ApiSecret ('00' * 32) `
            -HostName  'api.veracode.com' `
            -UrlPath   '/appsec/v1/applications'

        $header | Should -Match '^VERACODE-HMAC-SHA-256 id=testid,ts=\d+,nonce=[0-9a-f]{32},sig=[0-9a-f]{64}$'
    }

    It 'produces a different signature on each call (nonce randomness)' {
        $h1 = New-VcAuthHeader -ApiId 'id' -ApiSecret ('aa' * 32) -Host 'api.veracode.com' -UrlPath '/test'
        $h2 = New-VcAuthHeader -ApiId 'id' -ApiSecret ('aa' * 32) -Host 'api.veracode.com' -UrlPath '/test'
        $h1 | Should -Not -Be $h2
    }
}

Describe 'ConvertTo-QueryString' {
    It 'encodes a simple hashtable' {
        $qs = ConvertTo-QueryString @{ page = 0; size = 50 }
        # Order not guaranteed in hashtable — check both keys present
        $qs | Should -Match 'page=0'
        $qs | Should -Match 'size=50'
    }
    It 'URL-encodes special characters' {
        $qs = ConvertTo-QueryString @{ name = 'my app' }
        $qs | Should -Be 'name=my%20app'
    }
    It 'omits null values' {
        $qs = ConvertTo-QueryString @{ a = 'x'; b = $null }
        $qs | Should -Not -Match 'b='
    }
}

Describe 'ConvertFrom-VcIni' {
    It 'parses a two-section INI file' {
        $tmp = [System.IO.Path]::GetTempFileName()
        @'
[default]
veracode_api_key_id = abc
veracode_api_key_secret = def

[staging]
veracode_api_key_id = ghi
veracode_api_key_secret = jkl
'@ | Set-Content $tmp

        $parsed = ConvertFrom-VcIni -Path $tmp
        $parsed['default']['veracode_api_key_id']     | Should -Be 'abc'
        $parsed['staging']['veracode_api_key_secret']  | Should -Be 'jkl'
        Remove-Item $tmp
    }
}

Describe 'Get-VcCredential' {
    It 'reads from environment variables when set' {
        $env:VERACODE_API_KEY_ID     = 'envid'
        $env:VERACODE_API_KEY_SECRET = 'envsecret'
        $cred = Get-VcCredential
        $cred.Id     | Should -Be 'envid'
        $cred.Secret | Should -Be 'envsecret'
        $cred.Source | Should -Be 'environment'
        Remove-Item Env:VERACODE_API_KEY_ID
        Remove-Item Env:VERACODE_API_KEY_SECRET
    }

    It 'throws when credentials file is absent and no env vars' {
        Remove-Item Env:VERACODE_API_KEY_ID     -ErrorAction SilentlyContinue
        Remove-Item Env:VERACODE_API_KEY_SECRET -ErrorAction SilentlyContinue
        $saved = $script:CredentialsPath
        $script:CredentialsPath = Join-Path ([System.IO.Path]::GetTempPath()) 'vc_nonexistent_credentials'
        { Get-VcCredential } | Should -Throw
        $script:CredentialsPath = $saved
    }
}
