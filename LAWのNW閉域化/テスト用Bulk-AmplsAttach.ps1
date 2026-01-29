
<# 
  AMPLS に LAW/AI をタグ条件（固定・スカラ）で一括紐付け（完全版）
  - ParentResource 非対応環境でも動作（REST 直叩き）
  - タグ条件はスカラ固定（配列の罠を排除）
  - 既存スコープドリソースと差分だけ作成
  - ARM ベース URL は環境から自動検出（AzureCloud/China/USGov 等）
  - 認証トークンは Az → 失敗時 az CLI へフォールバック、JWT 形式チェックと期限切れ自動リトライを実装
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$AmplsResourceGroup,

  [Parameter(Mandatory=$true)]
  [string]$AmplsName,

  # ドライラン: 作成せずに計画のみ
  [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

# --- タグ条件 ---
$TagKey_Function   = 'AAA'
$TagValue_Function = 'aaa'
$TagKey_Owner      = 'BBB'
$TagValue_Owner    = 'bbb'



# --- ARM API バージョン（scopedResources 用） ---
$apiVer  = '2023-06-01-preview'

# =========================================================
# 0) AMPLS リソース解決
# =========================================================
Write-Host "==== [0] AMPLS リソース解決 ====" -ForegroundColor Cyan

$ampls = Get-AzResource -ResourceGroupName $AmplsResourceGroup `
                        -ResourceType 'Microsoft.Insights/privateLinkScopes' `
                        -Name $AmplsName -ErrorAction Stop

$amplsId = $ampls.ResourceId
if ([string]::IsNullOrWhiteSpace($amplsId)) {
  throw "AMPLS の ResourceId が取得できませんでした。RG/Name/サブスクリプションを確認してください。"
}

# =========================================================
# ARM 環境の自動検出（AzureCloud/China/USGov 等）
# =========================================================
$ctx = Get-AzContext
if (-not $ctx) { throw "Az にログインしていません。Connect-AzAccount を先に実行してください。" }

$env = Get-AzEnvironment -Name $ctx.Environment
$script:ArmBase            = $env.ResourceManagerUrl.TrimEnd('/')   # 例: https://management.azure.com
$script:ArmResource        = "$($script:ArmBase)/"                  # 末尾 / あり（Az 用）
$script:ArmResourceNoSlash = $script:ArmBase                        # 末尾 / なし（CLI 用）

Write-Host "[DEBUG] Environment: $($env.Name)  ARM: $script:ArmBase" -ForegroundColor DarkGray

# =========================================================
# JWT ユーティリティ（正規表現は使わない／Base64URL 対応）
# =========================================================
function Test-JwtLike {
  param([string]$Token)
  if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
  $parts = $Token.Split('.')
  return ($parts.Count -eq 3 -and $parts[0].Length -gt 0 -and $parts[1].Length -gt 0 -and $parts[2].Length -gt 0)
}
function Get-JwtPayloadJson {
  param([string]$Token)
  $p = $Token.Split('.')[1]
  # Base64URL → Base64
  $p = $p.Replace('-', '+').Replace('_', '/')
  switch ($p.Length % 4) { 2 { $p += '=='} ; 3 { $p += '=' } ; 1 { $p += '===' } ; default {} }
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

# =========================================================
# トークン取得（優先: az CLI → 次点: Az.Accounts）
#  - aud は参照ログのみ（厳密チェックで破棄しない）
#  - CLI は v2（scope）→ v1（resource）→ Az（/ と無しの両方）でフォールバック
# =========================================================
function Get-ArmAccessToken {
  # 1) CLI（v2: scope/.default）
  try {
    $cliJson = az account get-access-token --scope "$($script:ArmResourceNoSlash)/.default" -o json 2>$null
    if ($cliJson) {
      $obj = $cliJson | ConvertFrom-Json
      $t   = $obj.accessToken
      if (Test-JwtLike $t) {
        try { $aud = (Get-JwtPayloadJson $t).aud ; Write-Host "[DEBUG] CLI(scope) aud=$aud" -ForegroundColor DarkGray } catch {}
        return $t
      }
    }
    Write-Host "[DEBUG] CLI(scope) token 取得失敗/形式不正 → CLI(resource) へ" -ForegroundColor DarkYellow
  } catch {
    Write-Host "[DEBUG] CLI(scope) 例外: $($_.Exception.Message) → CLI(resource) へ" -ForegroundColor DarkYellow
  }

  # 2) CLI（v1: resource）
  try {
    $cliJson = az account get-access-token --resource $script:ArmResourceNoSlash -o json 2>$null
    if ($cliJson) {
      $obj = $cliJson | ConvertFrom-Json
      $t   = $obj.accessToken
      if (Test-JwtLike $t) {
        try { $aud = (Get-JwtPayloadJson $t).aud ; Write-Host "[DEBUG] CLI(resource) aud=$aud" -ForegroundColor DarkGray } catch {}
        return $t
      }
    }
    Write-Host "[DEBUG] CLI(resource) token 取得失敗/形式不正 → Az.Accounts へ" -ForegroundColor DarkYellow
  } catch {
    Write-Host "[DEBUG] CLI(resource) 例外: $($_.Exception.Message) → Az.Accounts へ" -ForegroundColor DarkYellow
  }

  # 3) Az.Accounts（ResourceUrl: with /）
  try {
    $tok = Get-AzAccessToken -ResourceUrl $script:ArmResource
    $t   = if ($tok.PSObject.Properties.Name -contains 'Token') { $tok.Token } elseif ($tok.PSObject.Properties.Name -contains 'AccessToken') { $tok.AccessToken } else { $null }
    if (Test-JwtLike $t) {
      try { $aud = (Get-JwtPayloadJson $t).aud ; Write-Host "[DEBUG] Az(ResourceUrl=/) aud=$aud" -ForegroundColor DarkGray } catch {}
      return $t
    }
    Write-Host "[DEBUG] Az(ResourceUrl=/) token 取得失敗/形式不正 → Az(ResourceUrl=NoSlash) へ" -ForegroundColor DarkYellow
  } catch {
    Write-Host "[DEBUG] Az(ResourceUrl=/) 例外: $($_.Exception.Message) → Az(ResourceUrl=NoSlash) へ" -ForegroundColor DarkYellow
  }

  # 4) Az.Accounts（ResourceUrl: no slash）
  try {
    $tok = Get-AzAccessToken -ResourceUrl $script:ArmResourceNoSlash
    $t   = if ($tok.PSObject.Properties.Name -contains 'Token') { $tok.Token } elseif ($tok.PSObject.Properties.Name -contains 'AccessToken') { $tok.AccessToken } else { $null }
    if (Test-JwtLike $t) {
      try { $aud = (Get-JwtPayloadJson $t).aud ; Write-Host "[DEBUG] Az(ResourceUrl=NoSlash) aud=$aud" -ForegroundColor DarkGray } catch {}
      return $t
    }
  } catch {
    Write-Host "[DEBUG] Az(ResourceUrl=NoSlash) 例外: $($_.Exception.Message)" -ForegroundColor DarkYellow
  }

  throw "アクセストークン取得に失敗しました。Cloud Shell の再起動や Connect-AzAccount の再実行もご検討ください。"
}

# 初回トークン
$script:ArmToken = Get-ArmAccessToken

function New-ArmHeaders {
  param([switch]$WithContent)
  $h = @{ "Authorization" = "Bearer $($script:ArmToken)"; "Accept" = "application/json" }
  if ($WithContent) { $h["Content-Type"] = "application/json" }
  return $h
}

# =========================================================
# REST ヘルパ（Invoke-RestMethod 版）※ 認証失敗時はトークン再取得で 1 リトライ
# =========================================================
function Invoke-ArmGet {
  param([string]$ResourceId, [string]$ApiVersion)
  if (-not $ResourceId.StartsWith('/')) { throw "ResourceId must start with '/': '$ResourceId'" }
  $uri = "{0}{1}?api-version={2}" -f $script:ArmBase, $ResourceId, $ApiVersion
  try {
    return Invoke-RestMethod -Method GET -Uri $uri -Headers (New-ArmHeaders)
  } catch {
    $msg = $_.ErrorDetails.Message
    if ($msg -match 'InvalidAuthenticationToken|ExpiredAuthenticationToken|AuthenticationFailed') {
      Write-Host "[DEBUG] GET: token refresh & retry" -ForegroundColor DarkYellow
      $script:ArmToken = Get-ArmAccessToken
      return Invoke-RestMethod -Method GET -Uri $uri -Headers (New-ArmHeaders)
    }
    throw
  }
}

function Invoke-ArmPut {
  param([string]$ResourceId, [string]$ApiVersion, [hashtable]$Body)
  if (-not $ResourceId.StartsWith('/')) { throw "ResourceId must start with '/': '$ResourceId'" }
  $uri  = "{0}{1}?api-version={2}" -f $script:ArmBase, $ResourceId, $ApiVersion
  $json = ($Body | ConvertTo-Json -Depth 10 -Compress)
  try {
    return Invoke-RestMethod -Method PUT -Uri $uri -Headers (New-ArmHeaders -WithContent) -Body $json
  } catch {
    $msg = $_.ErrorDetails.Message
    if ($msg -match 'InvalidAuthenticationToken|ExpiredAuthenticationToken|AuthenticationFailed') {
      Write-Host "[DEBUG] PUT: token refresh & retry" -ForegroundColor DarkYellow
      $script:ArmToken = Get-ArmAccessToken
      return Invoke-RestMethod -Method PUT -Uri $uri -Headers (New-ArmHeaders -WithContent) -Body $json
    }
    throw
  }
}

# =========================================================
# 1) 既存 scopedResources 一覧（重複回避用）
# =========================================================
Write-Host "==== [1] 既存 scopedResources 一覧（REST/GET） ====" -ForegroundColor Cyan
$childrenListId = "$amplsId/scopedResources"
$existing = Invoke-ArmGet -ResourceId $childrenListId -ApiVersion $apiVer

$existingLinkedIds = @{}
foreach ($item in ($existing.value | ForEach-Object { $_ })) {
  $linked = $item.properties.linkedResourceId
  if (![string]::IsNullOrWhiteSpace($linked)) { $existingLinkedIds[$linked] = $true }
}
Write-Host ("既存登録数: {0}" -f $existingLinkedIds.Keys.Count)

# =========================================================
# 2) LAW/AI を取得 → タグ（スカラ）で厳密抽出
# =========================================================
Write-Host "==== [2] LAW/AI を取得 → タグ（スカラ）で厳密抽出 ====" -ForegroundColor Cyan
$allTargets = @()
$allTargets += Get-AzResource -ResourceType 'Microsoft.OperationalInsights/workspaces'
$allTargets += Get-AzResource -ResourceType 'Microsoft.Insights/components'

$filtered = $allTargets | Where-Object {
  $tags = $_.Tags
  if (-not $tags) { return $false }
  $hasFunc  = ($tags.ContainsKey($TagKey_Function) -and [string]$tags[$TagKey_Function] -eq $TagValue_Function)
  $hasOwner = ($tags.ContainsKey($TagKey_Owner)    -and [string]$tags[$TagKey_Owner]    -eq $TagValue_Owner)
  return ($hasFunc -and $hasOwner)
}

if (-not $filtered) {
  Write-Host "タグ条件（$TagKey_Function=$TagValue_Function AND $TagKey_Owner=$TagValue_Owner）に一致する LAW/AI がありません。" -ForegroundColor Yellow
  return
}
Write-Host ("タグ一致の候補数: {0}" -f $filtered.Count)

# =========================================================
# 3) 差分（未登録のみ）抽出
# =========================================================
Write-Host "==== [3] 差分（未登録のみ）抽出 ====" -ForegroundColor Cyan
$toCreate = @()
foreach ($res in $filtered) {
  if (-not $existingLinkedIds.ContainsKey($res.ResourceId)) {
    $toCreate += $res
  }
}
Write-Host ("新規に紐付ける対象数: {0}" -f $toCreate.Count)
if ($toCreate.Count -eq 0) {
  Write-Host "追加対象はありません（すでに全て AMPLS に登録済み）。" -ForegroundColor Green
  return
}

# =========================================================
# 4) 作成（REST/PUT）
# =========================================================
function New-ScopedChildName {
  param([string]$Type, [string]$Name, [string]$Id)
  $abbr = switch -Wildcard ($Type) {
    'Microsoft.OperationalInsights/workspaces' { 'law'; break }
    'Microsoft.Insights/components'           { 'ai' ; break }
    default { 'res' }
  }
  # 安全な短ハッシュ（Id から SHA1 先頭6桁）
  $hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Id))) -Algorithm SHA1).Hash.Substring(0,6).ToLower()
  return "{0}-{1}-{2}" -f $abbr, $Name, $hash
}

Write-Host "==== [4] 作成（REST/PUT） ====" -ForegroundColor Cyan
$i = 0
foreach ($res in $toCreate) {
  $i++
  $childName = New-ScopedChildName -Type $res.ResourceType -Name $res.Name -Id $res.ResourceId
  $childId   = "$amplsId/scopedResources/$childName"
  Write-Host ("({0}/{1}) 追加: {2}  ←  {3}" -f $i, $toCreate.Count, $childName, $res.ResourceId)

  if ($WhatIf.IsPresent) { continue }

  try {
    $body = @{
      properties = @{
        kind             = 'Resource'          # LAW/AI は Resource
        linkedResourceId = $res.ResourceId
      }
    }
    $null = Invoke-ArmPut -ResourceId $childId -ApiVersion $apiVer -Body $body
  }
  catch {
    Write-Warning ("  失敗: {0}" -f $_.Exception.Message)
  }
}

# =========================================================
# 5) 登録結果
# =========================================================
Write-Host "==== [5] 登録結果 ====" -ForegroundColor Cyan
$after = Invoke-ArmGet -ResourceId $childrenListId -ApiVersion $apiVer
$after.value | Select-Object `
  @{n='name'; e={$_.name}},
  @{n='linkedResourceId'; e={$_.properties.linkedResourceId}} |
  Sort-Object name | Format-Table -AutoSize

Write-Host "完了。" -ForegroundColor Green
