function B64_ToUrlSafe ($b64) { $b64.TrimEnd('=') -replace '\+','-' -replace '/','_' }

function Encode_B64($text) {

   $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
   $b64 = [System.Convert]::ToBase64String($bytes)

   B64_ToUrlSafe $b64
}

function Get_Signature ($key, $text){
    try {
        $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($key)
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($text)

        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $keyBytes

        $hash = $hmac.ComputeHash($textBytes)
        $b64Hash = [System.Convert]::ToBase64String($hash)

        B64_ToUrlSafe $b64Hash
    }
    finally {
        if ($hmac -ne $null) { $hmac.Dispose() }
    }
}

function Create_CommonHeaders()
{
    #$requestId  = [Guid]::NewGuid().ToString()
    #$activityId = [Guid]::NewGuid().ToString()

    #Write-Verbose ("RID: $requestId`nAID: $activityId`n")

    @{
    #    'RequestId'  = $requestId;
    #    'ActivityId' = $activityId;
    }
}

function Create_ApiKeyHeaders ([string] $apiKey, [string] $workspaceCollectionName, [string] $workspaceId = $null, [System.Collections.Hashtable] $claims = @{})
{
    $now = ([DateTime]::UtcNow - ([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime())
    $nbf = $now.Add([TimeSpan]::FromMinutes(-10))
    $exp = $now.Add([TimeSpan]::FromMinutes(10))

    $body = @{
        'type' = 'dev';
        'ver' = '0.1.0';
        'iss' = 'PowerBISDK'; # 'PowerShellBI'; # Should this be PowerBISDK
        'aud' = 'https://analysis.windows.net/powerbi/api';
        'wcn' = $workspaceCollectionName;
        'exp' = [int]$exp.TotalSeconds;
        'nbf' = [int]$now.TotalSeconds;
    }

    if ($workspaceId -ne $null) { $body.Add('wid', $workspaceId) }

    $claims.GetEnumerator() |% { $body.Add($_.Name, $_.Value) }

    $jsonHeader = '{"typ":"JWT","alg":"HS256"}'
    $jsonBody = ConvertTo-Json -Compress $body
    
    $b64Header = Encode_B64 $jsonHeader
    $b64Body   = Encode_B64 $jsonBody

    $signedString = "$b64Header.$b64Body"
    $signature = Get_Signature $apiKey $signedString

    $payload = "$signedString.$signature"

    $headers = Create_CommonHeaders
    $headers.Add('Authorization', "AppToken $payload")

    $headers
}

function Create_AadHeaders ([System.Management.Automation.PSCredential] $creds)
{
    @{ 'Authorization' = "Bearer: " }

    throw "Not Implemented"
}

function Create_CommonState ([string] $env, [string] $ver, [System.Management.Automation.PSCredential] $creds, [string] $apiKey, [string] $workspaceCollectionName, [string] $workspaceId, [System.Collections.Hashtable] $claims = @{})
{
    # TODO: Configuration Based
    $base = if ($env -eq "PROD") { "https://api.powerbi.com" } else { "https://dxtapi.powerbi.com" }

    $uri = ""
    $headers = @{}

    if ($creds -ne $null) {
        $uri = "$base/$ver/myorg"
        $headers = Create_AadHeaders $creds }
    else {
        $uri = "$base/$ver/collections/$workspaceCollectionName";
        if ($workspaceId -ne $null) { $uri += "/workspaces/$workspaceId" }
        
        $headers = Create_ApiKeyHeaders $apiKey $workspaceCollectionName $workspaceId $claims
    }
    
    Write-Verbose "COMMON HEADERS: "
    $headers.GetEnumerator() |% { Write-Verbose "`t$($_.name) = $($_.Value)" }

    $uri ; $headers
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

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $WorkspaceId
    Invoke-RestMethod -Method Get -Uri "$endpoint/dashboards" -Headers $headers
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

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(Mandatory=$true)]
    [Guid] $DashboardId,

    [Parameter(Mandatory=$false)]
    [Guid] $TileId
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $WorkspaceId

    $uri = "$endpoint/dashboards/$DashboardId/tiles"
    if ($TileId) { $uri += "/$TitleId" }

    Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
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

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $WorkspaceId
    Invoke-RestMethod -Method Get -Uri "$endpoint/reports" -Headers $headers
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

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName $WorkspaceId
    Invoke-RestMethod -Method Get -Uri "$endpoint/datasets" -Headers $headers
}

# New-Dataset

function Get-Workspaces {
param(
    [Parameter(Mandatory=$false)]
    [string] $Environment = 'PROD',

    [Parameter(Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName
)

    ($endpoint, $headers) = Create_CommonState $Environment 'beta' $Credentials $ApiKey $WorkspaceCollectionName
    Invoke-RestMethod -Method Get -Uri $endpoint -Headers $headers
}

# Get-Tables

# Update-Table

# Add rows? Clear rows?

# Get-Groups

Export-ModuleMember -Function Get-Reports, Get-Datasets #, Get-Workspaces