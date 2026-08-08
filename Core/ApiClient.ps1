# HTTP client for Veracode REST and XML APIs.
# All API calls must go through Invoke-VcApi or Invoke-VcXmlApi — never call Invoke-RestMethod directly.

$script:RestBaseUrl = 'https://api.veracode.com'
$script:XmlBaseUrl  = 'https://analysiscenter.veracode.com'
$script:RestHost    = 'api.veracode.com'
$script:XmlHost     = 'analysiscenter.veracode.com'

function Invoke-VcApi {
    <#
    .SYNOPSIS
        Sends a signed REST API request to Veracode and returns the parsed JSON body.
    .PARAMETER Method
        HTTP method: GET, POST, PUT, DELETE.
    .PARAMETER Path
        API path, e.g. '/appsec/v1/applications'.
    .PARAMETER Query
        Hashtable of query-string parameters appended to the URL.
    .PARAMETER Body
        Hashtable serialised to JSON and sent as the request body.
    .PARAMETER Profile
        Credentials profile to use (defaults to the active session profile).
    .EXAMPLE
        Invoke-VcApi -Path '/appsec/v1/applications' -Query @{ size = 50; page = 0 }
        Invoke-VcApi -Method POST -Path '/appsec/v1/applications' -Body @{ profile = @{ name = 'MyApp'; business_criticality = 'HIGH' } }
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('GET','POST','PUT','DELETE','PATCH')]
        [string]$Method = 'GET',

        [Parameter(Mandatory)]
        [string]$Path,

        [hashtable]$Query,
        [object]$Body,

        [string]$Profile = $script:VcCurrentProfile
    )

    $cred    = Get-VcCredential -Profile $Profile
    $qs      = if ($Query) { '?' + (ConvertTo-QueryString $Query) } else { '' }
    $urlPath = $Path + $qs
    $fullUrl = $script:RestBaseUrl + $urlPath

    $authHeader = New-VcAuthHeader -ApiId $cred.Id -ApiSecret $cred.Secret `
                                   -HostName $script:RestHost -UrlPath $urlPath

    $params = @{
        Method      = $Method
        Uri         = $fullUrl
        Headers     = @{
            Authorization = $authHeader
            Accept        = 'application/json'
        }
        ErrorAction = 'Stop'
    }

    if ($Body) {
        $params['Body']        = ($Body | ConvertTo-Json -Depth 10 -Compress)
        $params['ContentType'] = 'application/json'
    }

    return Invoke-VcWithRetry -Params $params
}

function Invoke-VcPagedApi {
    <#
    .SYNOPSIS
        Pages through all results of a REST endpoint that uses HAL pagination.
        Returns a flat array of all items from the embedded collection.
    .PARAMETER EmbeddedKey
        The key inside '_embedded' that holds the item array (e.g. 'applications', 'users').
    .EXAMPLE
        $apps = Invoke-VcPagedApi -Path '/appsec/v1/applications' -EmbeddedKey 'applications'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$EmbeddedKey,
        [hashtable]$Query,
        [int]$PageSize = 500,
        [string]$Profile = $script:VcCurrentProfile
    )

    $allItems  = [System.Collections.Generic.List[object]]::new()
    $page      = 0
    $baseQuery = if ($Query) { $Query.Clone() } else { @{} }
    $baseQuery['size'] = $PageSize

    do {
        $baseQuery['page'] = $page
        $response = Invoke-VcApi -Path $Path -Query $baseQuery -Profile $Profile

        $items = $response._embedded.$EmbeddedKey
        if ($items) { $allItems.AddRange([object[]]$items) }

        # Guard: if the API returns no pagination metadata treat it as a single page.
        $totalPages = if ($null -ne $response.page.total_pages) { [int]$response.page.total_pages } else { 1 }
        $page++
    } while ($page -lt $totalPages)

    return $allItems.ToArray()
}

function Invoke-VcXmlApi {
    <#
    .SYNOPSIS
        Sends a signed request to the Veracode XML (Upload) API and returns an [xml] object.
    .PARAMETER Path
        API path, e.g. '/api/5.0/getbuildlist.do'.
    .PARAMETER Params
        Hashtable of query parameters.
    .PARAMETER Method
        HTTP method (default GET).
    .EXAMPLE
        $xml = Invoke-VcXmlApi -Path '/api/5.0/getbuildlist.do' -Params @{ app_id = 12345 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [hashtable]$Params,
        [ValidateSet('GET','POST')] [string]$Method = 'GET',
        [string]$Profile = $script:VcCurrentProfile
    )

    $cred    = Get-VcCredential -Profile $Profile
    $qs      = if ($Params) { '?' + (ConvertTo-QueryString $Params) } else { '' }
    $urlPath = $Path + $qs
    $fullUrl = $script:XmlBaseUrl + $urlPath

    $authHeader = New-VcAuthHeader -ApiId $cred.Id -ApiSecret $cred.Secret `
                                   -HostName $script:XmlHost -UrlPath $urlPath

    # Invoke-WebRequest is used here so we get the raw response string, which we parse
    # explicitly as [xml]. This avoids ambiguity in how Invoke-RestMethod handles XML
    # across different PowerShell versions.
    $requestParams = @{
        Method      = $Method
        Uri         = $fullUrl
        Headers     = @{
            Authorization = $authHeader
        }
        ErrorAction = 'Stop'
    }

    $rawContent = Invoke-VcWithRetry -Params $requestParams -AsString
    return [xml]$rawContent
}

# Internal: executes an HTTP request with exponential back-off on 429 and transient 5xx.
# -AsString uses Invoke-WebRequest and returns the raw response body as a string.
# Without -AsString uses Invoke-RestMethod and returns the parsed object.
function Invoke-VcWithRetry {
    param(
        [hashtable]$Params,
        [switch]$AsString
    )

    $maxRetries = 3
    $baseDelay  = 2   # seconds; doubled each retry

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            if ($AsString) {
                $resp = Invoke-WebRequest -UseBasicParsing @Params
                return $resp.Content
            }
            return Invoke-RestMethod @Params
        }
        catch {
            $status = $null
            $body   = $null

            # Handle HTTP errors — .Response exists on both PS5.1 (WebException) and PS7 (HttpRequestException).
            if ($_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
                try {
                    # PS5.1: Response is System.Net.HttpWebResponse — use GetResponseStream()
                    # PS7:   Response is System.Net.Http.HttpResponseMessage — use Content.ReadAsStringAsync()
                    $respObj = $_.Exception.Response
                    if ($respObj -is [System.Net.HttpWebResponse]) {
                        $stream = $respObj.GetResponseStream()
                        $reader = [System.IO.StreamReader]::new($stream)
                        $body   = $reader.ReadToEnd()
                        $reader.Dispose()
                    } elseif ($respObj.Content) {
                        $body = $respObj.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                } catch {}
            }

            $retryable = $status -eq 429 -or ($status -ge 500 -and $status -le 599)
            if ($retryable -and $attempt -lt $maxRetries) {
                $wait = $baseDelay * [Math]::Pow(2, $attempt - 1)
                Write-Verbose "HTTP $status — retrying in ${wait}s (attempt $attempt of $maxRetries)"
                Start-Sleep -Seconds $wait
                continue
            }

            $msg = "Veracode API error: HTTP $status on $($Params.Method) $($Params.Uri)"
            if ($body) { $msg += "`nResponse: $body" }
            throw $msg
        }
    }
}

# Converts a hashtable to a URL query string: key=value&key2=value2.
# Null values are omitted; all keys and values are percent-encoded.
function ConvertTo-QueryString {
    param([hashtable]$Params)
    $parts = foreach ($k in $Params.Keys) {
        $v = $Params[$k]
        if ($null -ne $v) {
            "$([Uri]::EscapeDataString($k))=$([Uri]::EscapeDataString($v.ToString()))"
        }
    }
    return $parts -join '&'
}
