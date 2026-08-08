# Implements Veracode HMAC-SHA256 request signing.
# Spec: https://docs.veracode.com/r/c_enabling_hmac

function New-VcAuthHeader {
    <#
    .SYNOPSIS
        Builds the VERACODE-HMAC-SHA-256 Authorization header for a given request.
    .PARAMETER ApiId
        The Veracode API ID (veracode_api_key_id from credentials).
    .PARAMETER ApiSecret
        The Veracode API secret (veracode_api_key_secret from credentials), hex-encoded.
    .PARAMETER Host
        The target hostname without scheme (e.g. 'api.veracode.com').
    .PARAMETER UrlPath
        The request path including query string (e.g. '/appsec/v1/applications?page=0').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ApiId,
        [Parameter(Mandatory)] [string]$ApiSecret,
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [string]$UrlPath
    )

    # 16 random bytes for the nonce
    $nonceBytes = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
    $nonceHex = [BitConverter]::ToString($nonceBytes).Replace('-', '').ToLower()

    # Timestamp in milliseconds since Unix epoch
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()

    # String to sign
    $signingData = "id=$ApiId`nhost=$HostName`nurl=$UrlPath`nveracode_request_timestamp=$timestamp"

    # Decode the hex secret into bytes
    $secretBytes = ConvertFrom-HexString $ApiSecret

    # Key derivation: secret → nonce → timestamp → wrap constant
    $kNonce = Invoke-HmacSha256 -KeyBytes $secretBytes  -DataBytes $nonceBytes
    $kTime  = Invoke-HmacSha256 -KeyBytes $kNonce       -DataString $timestamp
    $kWrap  = Invoke-HmacSha256 -KeyBytes $kTime        -DataString 'vcode_request_version_1'
    $sig    = Invoke-HmacSha256 -KeyBytes $kWrap        -DataString $signingData

    $sigHex = [BitConverter]::ToString($sig).Replace('-', '').ToLower()

    return "VERACODE-HMAC-SHA-256 id=$ApiId,ts=$timestamp,nonce=$nonceHex,sig=$sigHex"
}

# Computes HMAC-SHA256; accepts data as either a byte array or a UTF-8 string.
function Invoke-HmacSha256 {
    param(
        [byte[]]$KeyBytes,
        [byte[]]$DataBytes,
        [string]$DataString
    )
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($KeyBytes)
    if ($DataBytes) {
        return $hmac.ComputeHash($DataBytes)
    }
    return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($DataString))
}

# Decodes a lowercase or uppercase hex string to a byte array.
function ConvertFrom-HexString {
    param([string]$Hex)
    $Hex = $Hex.ToLower()
    if ($Hex.Length % 2 -ne 0) { throw "Hex string has odd length: '$Hex'" }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $bytes
}
