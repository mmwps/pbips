function Convert_BytesToUrlSafeB64 ($bytes) { [System.Convert]::ToBase64String($bytes).TrimEnd('=') -replace '\+','-' -replace '/','_' }
function Convert_UrlSafeB64ToBytes ($b64) {
    $padding = ( 4 - $b64.Length % 4 ) % 4
    $b64 = $b64 + ("=" * $padding)

    $bytes = [System.Convert]::FromBase64String($b64)
    
    $bytes
}

function Decode_B64($b64) {
    $bytes = Convert_UrlSafeB64ToBytes $b64
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)

    $text
}

function Encode_B64($text) {

   $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
   $b64 = Convert_BytesToUrlSafeB64 $bytes

   $b64
}

function Crack_ApiKeyToken($token) {
    $b64Payload = ( $token      -split ' '  )[1]
    $b64Claims  = ( $b64Payload -split '\.' )[1]

    $claims = Decode_B64($b64Claims)

    ConvertFrom-Json $claims
}

function Get_Signature ($key, $text){
    try {
        $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($key)
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($text)

        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $keyBytes

        $hash = $hmac.ComputeHash($textBytes)
        $b64Hash = Convert_BytesToUrlSafeB64 $hash

        $b64Hash
    }
    finally {
        if ($hmac) { $hmac.Dispose() }
    }
}

function Create_ApiKeyHeaders ([string] $apiKey, [string] $workspaceCollectionName, [string] $workspaceId = $null, [System.Collections.Hashtable] $claims = @{})
{
    $token = Get-ApiKeyToken $apiKey $workspaceCollectionName $workspaceId $claims
    @{ 'Authorization' = $token }
}

function Create_AadHeaders ([System.Management.Automation.PSCredential] $creds)
{
    @{ 'Authorization' = "Bearer: " }

    throw "Not Implemented"
}

function Create_CommonState (
    [string] $env,
    [string] $ver,
    [System.Management.Automation.PSCredential] $creds,
    [string] $apiKey,
    [string] $workspaceCollectionName,
    [string] $token,
    [string] $workspaceId = $null,
    [System.Collections.Hashtable] $claims = $null
) {
    ## Configuration Based?
    $base = if ($env -eq "PROD") { "https://api.powerbi.com" } else { "https://dxtapi.powerbi.com" }

    $uri = ""
    $headers = @{}

    if ($creds -or $token -like 'Bearer: *') {
        $uri = "$base/$ver/myorg"

        $headers = 
            if ($token) { @{ 'Authorization' = $token } }
            else { Create_AadHeaders $creds }
    }
    else {
        if ($token) {
            $t = Crack_ApiKeyToken $token
            
            $workspaceCollectionName = $t.wcn
            $workspaceId = $t.wid
        }

        $uri = "$base/$ver/collections/$workspaceCollectionName";
        if ($workspaceId) { $uri += "/workspaces/$workspaceId" }

        $headers =
            if ($token) { @{ 'Authorization' = $token } }
            else { Create_ApiKeyHeaders $apiKey $workspaceCollectionName $workspaceId $claims }
    }
    
    Write-Verbose "COMMON HEADERS: "
    $headers.GetEnumerator() |% { Write-Verbose "`t$($_.name) = $($_.Value)" }

    $uri ; $headers
}

function Execute_Request {
    try {
        Invoke-RestMethod @Args
    }
    catch {
        $resp = $_.Exception.Response
        
        $code = [int] $resp.StatusCode
        $desc = $resp.StatusDescription
        
        $rid = $resp.Headers["RequestId"]
        $aid = $resp.Headers["ActivityId"]
        
        throw "$code`: $desc`nRequest ID: $rid`nActivity ID: $aid"
    }
}

function Get-AadToken {
param(
    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials   
)
    throw "Not Implemented"
}

function Get-ApiKeyToken {
param(
    [Parameter(Mandatory=$true)]
    [string] $ApiKey,
    
    [Parameter(Mandatory=$true)]
    [string] $WorkspaceCollectionName,

    [Parameter()]
    [string] $WorkspaceId = $null,

    [Parameter()]
    [System.Collections.Hashtable] $Claims = $null,

    [Parameter()]
    [int] $BeforeBuffer = -1,

    [Parameter()]
    [int] $AfterBuffer = 1
)

    $now = ([DateTime]::UtcNow - ([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime())
    $nbf = $now.Add([TimeSpan]::FromMinutes($BeforeBuffer))
    $exp = $now.Add([TimeSpan]::FromMinutes($AfterBuffer))

    $body = @{
        'type' = 'dev';
        'ver' = '0.1.0';
        'iss' = 'PowerBISDK'; # 'PowerShellBI'; # Should this be PowerBISDK
        'aud' = 'https://analysis.windows.net/powerbi/api';
        'wcn' = $WorkspaceCollectionName;
        'exp' = [int]$exp.TotalSeconds;
        'nbf' = [int]$now.TotalSeconds;
    }

    if ($WorkspaceId) { $body.Add('wid', $WorkspaceId) }

    if ($Claims) { $Claims.GetEnumerator() |% { $body.Add($_.Name, $_.Value) } }

    $jsonHeader = '{"typ":"JWT","alg":"HS256"}'
    $jsonBody = ConvertTo-Json -Compress $body
    
    $b64Header = Encode_B64 $jsonHeader
    $b64Body   = Encode_B64 $jsonBody

    $signedString = "$b64Header.$b64Body"
    $signature = Get_Signature $ApiKey $signedString

    $payload = "$signedString.$signature"

    $token = "AppToken $payload"
    
    $token
}

function Get-Dashboards {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Position=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token $WorkspaceId
    Execute_Request -Method Get -Uri "$endpoint/dashboards" -Headers $headers
}

function Get-Tiles {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Position=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token,

    [Parameter(Mandatory=$true)]
    [Guid] $DashboardId,

    [Parameter(Mandatory=$false)]
    [Guid] $TileId
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token $WorkspaceId

    $uri = "$endpoint/dashboards/$DashboardId/tiles"
    if ($TileId) { $uri += "/$TitleId" }

    Execute_Request -Method Get -Uri $uri -Headers $headers
}

function Get-Reports {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Position=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token $WorkspaceId
    Execute_Request -Method Get -Uri "$endpoint/reports" -Headers $headers
}

function Get-Datasets {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Position=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token $WorkspaceId
    Execute_Request -Method Get -Uri "$endpoint/datasets" -Headers $headers
}

function Get-Tables {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Position=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0, Mandatory=$true)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token,

    [Parameter()]
    [string] $DatasetId
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token $WorkspaceId
    Execute_Request -Method Get -Uri "$endpoint/datasets/$DatasetId/tables" -Headers $headers
}

function Get-Workspaces {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,

    [Parameter(ParameterSetName='Token', Position=0, Mandatory=$true)]
    [string] $Token
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $Token
    Execute_Request -Method Get -Uri $endpoint -Headers $headers
}

# Update-Table

# Add rows? Clear rows?

# Get-Groups

Export-ModuleMember -Function Get-ApiKeyToken, Get-Reports, Get-Datasets #, New-Dataset #, Get-Workspaces