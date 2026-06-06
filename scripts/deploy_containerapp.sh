#!/usr/bin/env bash
# ============================================================================
# AEGIS — deploy the already-pushed image to Azure Container Apps.
# Reads secret values straight from .env so there is no copy-paste drift.
# Secrets go into Container Apps secret store; env vars reference them.
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

RG=aegis-rg
ENVNAME=aegis-env
APP=aegis-soc
ACR=aegisacr41458
IMAGE="${ACR}.azurecr.io/aegis:0.1.0"

# --- load .env (KEY=VALUE, ignore comments/blank). Values may contain '=',
# '~', quotes, braces — so split only on the FIRST '='. ----------------------
declare -A E
while IFS= read -r line; do
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${line// }" ]] && continue
  [[ "$line" != *"="* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  key="$(echo -n "$key" | tr -d '[:space:]')"
  E["$key"]="$val"
done < .env

# --- production-only overrides ----------------------------------------------
PROD_JWT="$1"   # passed in: fresh 32-byte hex generated outside this script

ACR_USER=$(az acr credential show -n "$ACR" --query username -o tsv)
ACR_PWD=$(az acr credential show -n "$ACR" --query "passwords[0].value" -o tsv)

echo "=== Deploying $APP from $IMAGE ==="

# Secrets: anything sensitive. Container Apps secret names must be lowercase
# alphanumeric/dash.
az containerapp create \
  -g "$RG" -n "$APP" \
  --environment "$ENVNAME" \
  --image "$IMAGE" \
  --target-port 8088 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 2 \
  --cpu 1.0 --memory 2.0Gi \
  --registry-server "${ACR}.azurecr.io" \
  --registry-username "$ACR_USER" \
  --registry-password "$ACR_PWD" \
  --secrets \
    azure-openai-key="${E[AZURE_OPENAI_API_KEY]}" \
    content-safety-key="${E[AZURE_CONTENT_SAFETY_KEY]}" \
    appinsights-conn="${E[APPLICATIONINSIGHTS_CONNECTION_STRING]}" \
    foundry-conn="${E[AZURE_AI_FOUNDRY_CONNECTION_STRING]}" \
    entra-creds="${E[ENTRA_AGENT_CREDENTIALS]}" \
    jwt-secret="${PROD_JWT}" \
    demo-password="${E[AEGIS_DEMO_PASSWORD]}" \
  --env-vars \
    AEGIS_ENV=production \
    AEGIS_LOG_LEVEL=INFO \
    AEGIS_API_HOST=0.0.0.0 \
    AEGIS_API_PORT=8088 \
    WEBSITES_PORT=8088 \
    AZURE_SUBSCRIPTION_ID="${E[AZURE_SUBSCRIPTION_ID]}" \
    AZURE_TENANT_ID="${E[AZURE_TENANT_ID]}" \
    AZURE_RESOURCE_GROUP="${E[AZURE_RESOURCE_GROUP]}" \
    AZURE_OPENAI_ENDPOINT="${E[AZURE_OPENAI_ENDPOINT]}" \
    AZURE_OPENAI_API_KEY=secretref:azure-openai-key \
    AZURE_OPENAI_DEPLOYMENT="${E[AZURE_OPENAI_DEPLOYMENT]}" \
    AZURE_OPENAI_API_VERSION="${E[AZURE_OPENAI_API_VERSION]}" \
    OPENAI_MODEL="${E[OPENAI_MODEL]}" \
    AZURE_AI_FOUNDRY_PROJECT_ENDPOINT="${E[AZURE_AI_FOUNDRY_PROJECT_ENDPOINT]}" \
    AZURE_AI_FOUNDRY_CONNECTION_STRING=secretref:foundry-conn \
    AZURE_CONTENT_SAFETY_ENDPOINT="${E[AZURE_CONTENT_SAFETY_ENDPOINT]}" \
    AZURE_CONTENT_SAFETY_KEY=secretref:content-safety-key \
    ENTRA_TENANT_ID="${E[ENTRA_TENANT_ID]}" \
    ENTRA_CLIENT_ID="${E[ENTRA_CLIENT_ID]}" \
    ENTRA_AGENT_AUDIENCE="${E[ENTRA_AGENT_AUDIENCE]}" \
    ENTRA_JWKS_URI="${E[ENTRA_JWKS_URI]}" \
    ENTRA_ISSUER="${E[ENTRA_ISSUER]}" \
    ENTRA_AGENT_CREDENTIALS=secretref:entra-creds \
    AEGIS_FORCE_ENTRA_MOCK="${E[AEGIS_FORCE_ENTRA_MOCK]}" \
    DEFENDER_ALERTS_RESOURCE_ID="${E[DEFENDER_ALERTS_RESOURCE_ID]}" \
    APPLICATIONINSIGHTS_CONNECTION_STRING=secretref:appinsights-conn \
    AEGIS_DEMO_USERNAME="${E[AEGIS_DEMO_USERNAME]}" \
    AEGIS_DEMO_PASSWORD=secretref:demo-password \
    AEGIS_JWT_SECRET=secretref:jwt-secret \
    AEGIS_ENABLE_DEFENDER_INGEST="${E[AEGIS_ENABLE_DEFENDER_INGEST]}" \
    AEGIS_ENABLE_AZURE_MONITOR="${E[AEGIS_ENABLE_AZURE_MONITOR]}" \
    AEGIS_ENABLE_FOUNDRY_TRACING="${E[AEGIS_ENABLE_FOUNDRY_TRACING]}" \
    AEGIS_FORCE_OFFLINE_MOCK="${E[AEGIS_FORCE_OFFLINE_MOCK]}" \
  --query "properties.configuration.ingress.fqdn" -o tsv

echo "=== done ==="
