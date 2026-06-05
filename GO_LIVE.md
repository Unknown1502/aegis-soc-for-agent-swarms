# AEGIS — Taking Entra + Defender genuinely LIVE

Both code paths are built and verified. They stay in safe mock/disabled mode
until you add the credentials below. After each, run `aegis doctor` to verify.

---

## Defender for Cloud (5 min, lowest risk)

1. Install Azure CLI if needed: `winget install Microsoft.AzureCLI` (reopen terminal).
2. `az login --tenant 2f52c65f-0f8a-4fcf-b54f-856d78bffc78`
3. `az account set --subscription ea7eeab2-9427-41be-b367-a88246184544`
4. Check access: `az security alert list --query "length(@)"`
   - prints a number (even 0) → good, skip step 5.
   - authorization error → step 5.
5. Grant Security Reader (only if needed):
   ```powershell
   $me = az ad signed-in-user show --query id -o tsv
   az role assignment create --assignee $me --role "Security Reader" --scope /subscriptions/ea7eeab2-9427-41be-b367-a88246184544
   ```
6. In `.env`, set: `AEGIS_ENABLE_DEFENDER_INGEST=true`  ← the only edit.
7. Verify: `aegis doctor` → Defender section should say "auth OK".

Auth uses your `az login` session automatically (DefaultAzureCredential).
If 0 alerts: that's honest/real — the subscription has no AI-workload alerts;
the demo's corroboration still uses the clearly-tagged seeded alert.

---

## Entra Agent ID (~15 min)

1. Provision the 4 app registrations + audience app:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\setup_entra.ps1
   ```
2. The script prints 3 lines. Paste them into `.env`, replacing the existing
   `ENTRA_CLIENT_ID`, `ENTRA_AGENT_AUDIENCE`, and blank `ENTRA_AGENT_CREDENTIALS`:
   ```
   ENTRA_CLIENT_ID=<printed>
   ENTRA_AGENT_AUDIENCE=<printed GUID>
   ENTRA_AGENT_CREDENTIALS=<printed JSON, single line>
   ```
   Leave `ENTRA_ISSUER`, `ENTRA_JWKS_URI`, `ENTRA_TENANT_ID` unchanged.
3. Wait ~60s for Azure to propagate the new apps/secrets.
4. Verify: `aegis doctor`
   - All agents "valid" → Entra is genuinely live. Run the demo.
   - Any "invalid" with an aud/iss mismatch → `doctor` prints the exact
     `ENTRA_AGENT_AUDIENCE=` / `ENTRA_ISSUER=` value to set. Apply it, re-run.

### Emergency revert (demo safety)
If real-token verification misbehaves at the venue, set in `.env`:
```
AEGIS_FORCE_ENTRA_MOCK=true
```
This forces dev-mock identity instantly — the swarm goes back to the known-good
state. Both the verifier and token issuer flip together off the `has_entra_live`
gate, so there is never a half-live state that self-quarantines the swarm.

---

## How it works (for Q&A)

- **Verifier** ([entra_agent_id.py](aegis/sensors/entra_agent_id.py)): real
  PyJWKClient JWKS fetch + PyJWT RS256 validation (aud/iss/exp/replay). Always
  was real — only token *issuance* was mocked.
- **Issuer** (`EntraTokenIssuer`): MSAL client-credentials, one app reg per
  agent, tokens cached/refreshed by MSAL. Each agent's app id (`azp`) maps back
  to its canonical agent id so the verifier's identity check passes.
- **Defender** ([defender.py](aegis/sensors/defender.py)): `_pull_live()` calls
  the `Microsoft.Security/alerts` REST API with a DefaultAzureCredential bearer
  token; read-only, fails safe to empty.
