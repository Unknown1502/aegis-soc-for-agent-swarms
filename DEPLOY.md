# AEGIS Deployment Guide

This document explains how to ship AEGIS to a public live URL so judges (and
your future PR description) can hit a single link and exercise the full
demo. Two recommended targets, in order of how fast you'll be live:

1. **Azure App Service (Container)** — single Linux app, ~10 min, free F1
   tier works. **Recommended.**
2. **Azure Container Apps** — slightly more setup, scales to zero, costs $0
   when idle.

Both use the same Docker image (`Dockerfile` in repo root).

---

## Option 1 — Azure App Service for Containers (recommended)

### 1. Build the image locally and push to Azure Container Registry

```powershell
# from the repo root
$ACR_NAME = "aegisacr"           # globally unique; lowercase
$RG = "aegis-rg"
$IMAGE = "${ACR_NAME}.azurecr.io/aegis:0.1.0"

az acr create -n $ACR_NAME -g $RG --sku Basic --admin-enabled true
az acr login -n $ACR_NAME

docker build -t $IMAGE .
docker push $IMAGE
```

Skip the local Docker steps and let ACR build for you (saves the ~700 MB
local build):

```powershell
az acr build --registry $ACR_NAME --image aegis:0.1.0 .
```

### 2. Create the App Service plan + Web App

```powershell
$PLAN = "aegis-plan"
$APP  = "aegis-prajwal"          # globally unique; becomes <APP>.azurewebsites.net

az appservice plan create -g $RG -n $PLAN --is-linux --sku B1
az webapp create -g $RG -p $PLAN -n $APP \
    --deployment-container-image-name $IMAGE
```

For free tier substitute `--sku F1` (App Service plan F1 is free, but
limited to 60 minutes/day CPU — fine for a demo, not for a sustained URL).
B1 (~$13/month) gives you always-on and is well worth it for the
30-day-live-URL hackathon rule.

### 3. Wire up Azure credentials so the container can pull

```powershell
$ACR_PWD = (az acr credential show -n $ACR_NAME --query "passwords[0].value" -o tsv)
az webapp config container set -g $RG -n $APP `
    --docker-custom-image-name $IMAGE `
    --docker-registry-server-url "https://${ACR_NAME}.azurecr.io" `
    --docker-registry-server-user $ACR_NAME `
    --docker-registry-server-password $ACR_PWD
```

### 4. Configure the runtime environment variables

The Web App reads exactly the same env vars as your local `.env`. Set them
once via the CLI (faster than the portal):

```powershell
az webapp config appsettings set -g $RG -n $APP --settings `
    WEBSITES_PORT=8088 `
    AEGIS_ENV=production `
    AEGIS_API_HOST=0.0.0.0 `
    AEGIS_API_PORT=8088 `
    AEGIS_DEMO_USERNAME=demo `
    AEGIS_DEMO_PASSWORD="<pick-something-stronger>" `
    AEGIS_JWT_SECRET="<random-32-bytes>" `
    AZURE_TENANT_ID="$env:AZURE_TENANT_ID" `
    AZURE_SUBSCRIPTION_ID="$env:AZURE_SUBSCRIPTION_ID" `
    AZURE_RESOURCE_GROUP=aegis-rg `
    AZURE_OPENAI_ENDPOINT="$env:AZURE_OPENAI_ENDPOINT" `
    AZURE_OPENAI_API_KEY="$env:AZURE_OPENAI_API_KEY" `
    AZURE_OPENAI_DEPLOYMENT=aegis-llm `
    AZURE_OPENAI_API_VERSION=2024-10-21 `
    AZURE_CONTENT_SAFETY_ENDPOINT="$env:AZURE_CONTENT_SAFETY_ENDPOINT" `
    AZURE_CONTENT_SAFETY_KEY="$env:AZURE_CONTENT_SAFETY_KEY" `
    APPLICATIONINSIGHTS_CONNECTION_STRING="$env:APPLICATIONINSIGHTS_CONNECTION_STRING" `
    AZURE_AI_FOUNDRY_CONNECTION_STRING="$env:AZURE_AI_FOUNDRY_CONNECTION_STRING" `
    AEGIS_ENABLE_AZURE_MONITOR=true `
    AEGIS_ENABLE_FOUNDRY_TRACING=true
```

Replace the `$env:...` references with the values from your local `.env`.
**Never commit `.env`** — App Service settings are the production source of
truth.

### 5. Force WebSocket support + always-on

```powershell
az webapp config set -g $RG -n $APP --web-sockets-enabled true --always-on true
```

### 6. Restart and verify

```powershell
az webapp restart -g $RG -n $APP

# Wait ~30 sec for cold start, then:
curl https://${APP}.azurewebsites.net/api/status
```

You should see the integration report with the same LIVE badges your local
`aegis status` produced.

Open the public URL:

```
https://aegis-prajwal.azurewebsites.net/
```

Login with the demo credentials you set, click **EchoLeak chain (hero)**,
and the verdict flip should be visible inside ~10 seconds.

### 7. Put the URL in your README, PR, and resume

```markdown
**Live demo:** https://aegis-prajwal.azurewebsites.net
**Login:** demo / <demo-password>
```

The hackathon rules require the URL stay up for at least 30 days post
submission. App Service B1 stays up indefinitely; no action needed.

---

## Option 2 — Azure Container Apps (scale-to-zero)

```powershell
az containerapp env create -g $RG -n aegis-env --location eastus
az containerapp create -g $RG -n aegis `
    --environment aegis-env `
    --image $IMAGE `
    --target-port 8088 `
    --ingress external `
    --min-replicas 0 --max-replicas 2 `
    --registry-server "${ACR_NAME}.azurecr.io" `
    --registry-username $ACR_NAME `
    --registry-password $ACR_PWD `
    --secrets "azure-openai-key=$env:AZURE_OPENAI_API_KEY" `
              "content-safety-key=$env:AZURE_CONTENT_SAFETY_KEY" `
              "jwt-secret=$env:AEGIS_JWT_SECRET" `
              "demo-password=<your-pw>" `
    --env-vars "AEGIS_ENV=production" `
              "AZURE_OPENAI_ENDPOINT=$env:AZURE_OPENAI_ENDPOINT" `
              "AZURE_OPENAI_API_KEY=secretref:azure-openai-key" `
              "AZURE_OPENAI_DEPLOYMENT=aegis-llm" `
              "AZURE_CONTENT_SAFETY_ENDPOINT=$env:AZURE_CONTENT_SAFETY_ENDPOINT" `
              "AZURE_CONTENT_SAFETY_KEY=secretref:content-safety-key" `
              "APPLICATIONINSIGHTS_CONNECTION_STRING=$env:APPLICATIONINSIGHTS_CONNECTION_STRING" `
              "AZURE_AI_FOUNDRY_CONNECTION_STRING=$env:AZURE_AI_FOUNDRY_CONNECTION_STRING" `
              "AEGIS_ENABLE_AZURE_MONITOR=true" `
              "AEGIS_ENABLE_FOUNDRY_TRACING=true" `
              "AEGIS_JWT_SECRET=secretref:jwt-secret" `
              "AEGIS_DEMO_PASSWORD=secretref:demo-password"
```

Container Apps gives you a free-tier-friendly URL of the form
`https://aegis.<region>.azurecontainerapps.io`. Cold start adds ~5 s the
first request after idle.

---

## Sanity checks for the live deployment

Run these against the public URL after deploy. All should return what the
local run returned:

```bash
# 1. Integration report
curl https://<your-url>/api/status | jq '.integration_report'

# 2. Login + token
TOKEN=$(curl -s -X POST https://<your-url>/api/auth/login \
    -H "content-type: application/json" \
    -d '{"username":"demo","password":"<pw>"}' | jq -r .token)

# 3. Trigger the headline attack
curl -s -X POST https://<your-url>/api/attacks/echoleak \
    -H "authorization: bearer $TOKEN" | jq '.result.sent, .result.refusal.message'
# expected: false  +  refusal message starts with "AEGIS: action blocked AND originating agent quarantined"

# 4. Verify audit chain
curl -s -X POST https://<your-url>/api/audit/verify \
    -H "authorization: bearer $TOKEN" | jq
# expected: {"ok": true, "message": "OK (N entries verified)"}

# 5. Read live metrics
curl -s https://<your-url>/api/metrics \
    -H "authorization: bearer $TOKEN" | jq '.counters'
```

---

## Cost summary (whole hackathon)

| Component | Free-tier-fits | Demo cost | Note |
|---|---|---|---|
| App Service plan B1 | no | ~$13/mo | Buy 1 month; cancel after |
| ACR Basic | no | ~$0.17/day | Negligible |
| Content Safety F0 | yes | $0 | 5K calls/mo free |
| Application Insights | yes | $0 | 5 GB/mo free |
| Azure OpenAI gpt-4.1-mini | no (PAYG) | $1–5 total | <100K tokens for whole demo + eval |
| **Total** | — | **~$15** | Within $200 free credit easily |

If you want it absolutely $0: pick App Service F1 (free) — limited to 60
min CPU/day, sufficient for demo day but not for sustained 30-day uptime.
The B1 SKU is the cheap "always-on" choice.

---

## Teardown when you're done

```powershell
az group delete -n aegis-rg --yes --no-wait
```

One command deletes every Azure resource AEGIS uses. Billing stops within
the hour.
