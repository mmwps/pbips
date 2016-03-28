function Encode_B64($text) {

   $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
   $b64 = [System.Convert]::ToBase64String($bytes)

   $b64
}

function Get_Signature ($key, $text){
    try {
        $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($key)
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($text)

        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $keyBytes

        $hash = $hmac.ComputeHash($textBytes)
        $b64Hash = [System.Convert]::ToBase64String($hash)

        $b64Hash
    }
    finally {
        if ($hmac -ne $null) { $hmac.Dispose() }
    }
}

function Create_CommonHeaders()
{
    $requestId = [Guid]::NewGuid().ToString()
    $activityId = [Guid]::NewGuid().ToString()

    Write-Verbose ("RID: $requestId`nAID: $activityId`n")

    @{
        'RequestId'  = $requestId;
        'ActivityId' = $activityId;
    }
}

function Create_ApiKeyHeaders ([string] $apiKey, [string] $workspaceCollectionName, [System.Collections.Hashtable] $claims = @{})
{
    $now = [DateTime]::UtcNow

    $exp = $now
    $exp.AddMinutes(10)

    $body = @{
        'ver' = '1.0.0';
        'type' = 'dev';
        'iss' = 'PowerShellBI'; # Should this be PowerBISDK
        'aud' = 'https://analysis.windows.net/powerbi/api';
        'wcn' = $workspaceCollectionName;
      # 'exp' = $exp.GetTicks();
      # 'nbf' = $now.GetTicks();
    }

    $claims.GetEnumerator() |% { $body.Add($_.Name, $_.Value) }

    $jsonHeader = '{ "typ": "JWT", "alg": "H265" }'
    $jsonBody = ConvertTo-Json $body
    
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

function Create_CommonState ([System.Management.Automation.PSCredential] $creds, [string] $apiKey, [string] $workspaceCollectionName, [System.Collections.Hashtable] $claims = @{})
{
    if ($creds) { "https://api.powerbi.com/beta/myorg" ; Create_AadHeaders $creds                                     }
    else        { "https://api.powerbi.com/v1/myorg"   ; Create_ApiKeyHeaders $apiKey WorkspaceCollectionName $claims }
}

function Get-Dashboards {
param(
    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Postion=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($endpoint, $headers) = Create_CommonState $Credentials $ApiKey $WorkspaceCollectionName @{ 'wid' = $WorkspaceId }
    Invoke-RestMethod -Method Get -Uri "$endpoint/dashboards" -Headers $headers
}

function Get-Tiles {
param(
    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Postion=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials,

    [Parameter(Mandatory=$true)]
    [Guid] $DashboardId,

    [Parameter(Mandatory=$false)]
    [Guid] $TileId
)

    ($endpoint, $headers) = Create_CommonState $Credentials $ApiKey $WorkspaceCollectionName @{ 'wid' = $WorkspaceId }

    $uri = "$endpoint/dashboards/$DashboardId/tiles"
    if ($TileId) { $uri += "/$TitleId" }

    Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
}

function Get-Reports {
param(
    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Postion=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($ver, $headers) = Create_CommonState $Credentials $ApiKey $WorkspaceCollectionName @{ 'wid' = $WorkspaceId }
    Invoke-RestMethod -Method Get -Uri "$endpoint/reports" -Headers $headers
}


# Get-Datasets
function Get-Datasets {
param(
    [Parameter(ParameterSetName='ApiKey', Position=0, Mandatory=$true)]
    [string] $ApiKey,

    [Parameter(ParameterSetName='ApiKey', Position=1, Mandatory=$true)]
    [string] $WorkspaceCollectionName,
    
    [Parameter(ParameterSetName='ApiKey', Postion=2, Mandatory=$true)]
    [string] $WorkspaceId,

    [Parameter(ParameterSetName='AAD', Position=0)]
    [System.Management.Automation.PSCredential] $Credentials
)

    ($ver, $headers) = Create_CommonState $Credentials $ApiKey $WorkspaceCollectionName @{ 'wid' = $WorkspaceId }
    Invoke-RestMethod -Method Get -Uri "$endpoint/datasets" -Headers $headers
}

# New-Dataset

# Get-Workspaces

# Get-Tables

# Get-Groups

# Get-Table

# Update-Table

# Add rows? Clear rows?

Export-ModuleMember -Function Get-Dashboards, Get-Tiles, Get-Reports, Get-Datasets, Get-Workspaces