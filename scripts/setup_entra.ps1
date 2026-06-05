<#
  setup_entra.ps1 - provision the Entra app registrations AEGIS needs to run
  genuinely-live inter-agent identity (real RS256 tokens, not dev-mock).

  What it creates:
    * 1 "resource" app  (aegis-agents)  - the audience every agent token targets.
        - identifier URI  api://aegis-agents
        - requestedAccessTokenVersion = 2  (so iss = .../v2.0, which AEGIS expects)
        - a service principal (required for token issuance)
    * 4 "client" apps   (one per swarm identity) each with:
        - a client secret (1-year)
        - a service principal

  At the end it prints the three lines you paste into .env. Run it ONCE.

  Prereqter: Azure CLI installed (`az version`). If not:
      winget install Microsoft.AzureCLI    # then restart the terminal

  Usage:
      pwsh ./scripts/setup_entra.ps1
  or in Windows PowerShell:
      powershell -ExecutionPolicy Bypass -File .\scripts\setup_entra.ps1
#>

param(
  [string]$Tenant   = "2f52c65f-0f8a-4fcf-b54f-856d78bffc78",
  [string]$Audience = "api://aegis-agents"
)

$ErrorActionPreference = "Stop"

function Require-Az {
  if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI not found on PATH. Install it first:`n  winget install --id Microsoft.AzureCLI --exact`nthen CLOSE and reopen the terminal (so PATH refreshes) and re-run this script."
  }
}

Require-Az

# 0. Make sure we're signed into the right tenant.
az account show 1>$null 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Signing in to tenant $Tenant ..." -ForegroundColor Cyan
  az login --tenant $Tenant | Out-Null
}

# 1. Resource (audience) app -------------------------------------------------
Write-Host "`n[1/3] Creating resource app 'aegis-agents' (audience = $Audience) ..." -ForegroundColor Cyan
$resourceAppId = az ad app create --display-name "aegis-agents" --query appId -o tsv
az ad app update --id $resourceAppId --identifier-uris $Audience | Out-Null
# v2.0 access tokens -> issuer is https://login.microsoftonline.com/<tid>/v2.0
az ad app update --id $resourceAppId --set api.requestedAccessTokenVersion=2 | Out-Null
# the resource needs a service principal to be a valid token audience
az ad sp create --id $resourceAppId 1>$null 2>$null
Write-Host "      resource appId = $resourceAppId"

# 2. Four client apps (one per swarm identity) -------------------------------
Write-Host "`n[2/3] Creating the four agent client apps + secrets ..." -ForegroundColor Cyan
$agents = [ordered]@{
  "victim.orchestrator"  = "aegis-agent-orchestrator"
  "victim.email_triage"  = "aegis-agent-email-triage"
  "victim.summarizer"    = "aegis-agent-summarizer"
  "victim.tool_executor" = "aegis-agent-tool-executor"
}

$creds = [ordered]@{}
$firstClientId = $null
foreach ($agentId in $agents.Keys) {
  $display = $agents[$agentId]
  $appId  = az ad app create --display-name $display --query appId -o tsv
  az ad sp create --id $appId 1>$null 2>$null
  $secret = az ad app credential reset --id $appId --append --display-name "aegis-demo" --years 1 --query password -o tsv
  $creds[$agentId] = [ordered]@{ client_id = $appId; client_secret = $secret }
  if (-not $firstClientId) { $firstClientId = $appId }
  Write-Host "      $agentId -> $appId"
}

# 3. Emit the .env lines -----------------------------------------------------
$json = ($creds | ConvertTo-Json -Compress -Depth 5)

Write-Host "`n[3/3] DONE. Paste these THREE lines into .env (replace the existing keys):" -ForegroundColor Green
Write-Host "----------------------------------------------------------------------"
Write-Host "ENTRA_CLIENT_ID=$firstClientId"
Write-Host "ENTRA_AGENT_AUDIENCE=$resourceAppId"
Write-Host "ENTRA_AGENT_CREDENTIALS=$json"
Write-Host "----------------------------------------------------------------------"
Write-Host "`nNote: token issuance can take ~30-60s to propagate after creation." -ForegroundColor Yellow
Write-Host "Keep ENTRA_ISSUER / ENTRA_JWKS_URI as they already are (tenant v2.0)." -ForegroundColor Yellow
