GDPR Guardian Agent (Python)
GDPR Guardian is a trust-by-design AI agent, built with Portia, that automates and secures the entire GDPR Data Subject Access Request (DSAR) lifecycle with human-in-the-loop orchestration.

Quick start

1) Create venv and install

```bash
python -m venv .venv
. .venv/Scripts/activate  # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2) Run server

```bash
python -m src.server.app
```

3) Open http://localhost:3000, submit a DSAR, review proposals, approve, then download the ZIP.

Notes
- Policy: see `policy/policy.yaml`.
- Demo data: `data/`.
- Code: `src/agent`, `src/server`, `src/tools`.
- Portia SDK: we include `portia-sdk-python`. Verify via GET `/health` → `portia_sdk_installed: true`.

Portia usage (important)

- LLM summarization: `src/agent/llm.py` uses Portia with Gemini (`GOOGLE_API_KEY`) to generate a review summary shown on the run page.
- PlanRun and Clarifications: When `PORTIA_API_KEY` is configured, the app creates a live, stateful PlanRun in Portia Cloud and manages human approval via Portia Clarifications. The resulting objects are displayed in the UI's audit section. Without Cloud, it generates a pre-expressed PlanRun JSON and local Clarification for the demo.
- Guardrails: when finalization is blocked, we record a GuardrailEvent via Portia for audit.
- Enable by setting `GOOGLE_API_KEY` (see "Gemini setup" below) and confirm via `/health`.

Gmail (optional)

- Install extra deps (already in `requirements.txt`): `google-api-python-client`, `google-auth`, `google-auth-oauthlib`.
- Set env vars:
  - `GMAIL_TOKEN_PATH` → path to OAuth token JSON (pre-authorized, non-interactive).
  - `GMAIL_LABEL_ID` (optional) → filter by label.
  - `GMAIL_QUERY` (optional) → Gmail search query (e.g., `from:support@example.com`).
- If configured, live Gmail messages are listed as `gmail_live` artifacts alongside demo JSON data.

Generate Gmail token (scope)

1) In Google Cloud Console, enable the Gmail API and create an OAuth 2.0 Client ID (Desktop). Download it as `credentials.json` to the project root.
2) Generate a user token with readonly scope and save it as `token.json`:
   - PowerShell (without activating venv):
     ```powershell
     .\venv312\Scripts\google-oauthlib-tool.exe --client-secrets .\credentials.json --scopes https://www.googleapis.com/auth/gmail.readonly --save --credentials .\token.json
     ```
   - If your venv is activated:
     ```powershell
     google-oauthlib-tool --client-secrets credentials.json --scopes https://www.googleapis.com/auth/gmail.readonly --save --credentials token.json
     ```
3) Either set `GMAIL_TOKEN_PATH` to the token file or simply place `token.json` in the project root. The app will auto-detect it.
4) Optional: set `GMAIL_LABEL_ID` or `GMAIL_QUERY` to scope fetched messages for the demo.

Gemini setup (Portia SDK)

```bash
# .env file in project root
GOOGLE_API_KEY=your_key_here
```
or set in shell (Windows PowerShell):
```powershell
$env:GOOGLE_API_KEY="your_key_here"
```
Then restart the server. The run page will display an LLM summary generated via Portia using Gemini.


Identity verification (ID upload)

- Upload a government ID image with the DSAR form. The agent computes a heuristic confidence:
  - Filename contains "alice" → confidence 0.95 (auto-verified)
  - Filename contains "id", "license", or "passport" → 0.60 (paused for human review)
  - Missing/invalid file → 0.10 (paused)
- Policy threshold: `identity.min_confidence_for_auto_approval` in `policy/policy.yaml` (defaults to 0.85).
- If below threshold, the run pauses with an Identity Clarification in the UI.

Legal basis and retention policies (erasure)

- Legal hold is seeded from `data/crm_profile.json` (`legal_hold: true|false`).
- Retention is policy-driven via `policy/policy.yaml` → `retention_policies`:
  - `financial_transaction_days: 2555`
  - `active_service_days: 180`
- Sample transactions are in `data/transaction_history.json`. Recent transactions or active subscription windows will block erasure with clear reasons.


Demo runbook (2 minutes)

1) Start DSAR: open `http://localhost:3000`, enter `alice@example.com`, choose Access or Erasure, and upload an ID image.
2) Identity: show Identity section (auto-verified at 0.95 for `alice-*.jpg`; paused at 0.60 for `id.jpg`).
3) Findings: show PII chips, proposals, and the Portia LLM summary.
4) Portia audit: expand PlanRun, Clarification, Decision, and Guardrail JSON.
5) Guardrail: toggle Legal hold ON → attempt approval → blocked; OFF → proceed.
6) Approve: select proposals (or justify override), approve → ZIP link appears.
7) Download: open ZIP, show `artifacts.json`, `audit_log.json`, `policy.json`, and `checksum.txt`.
8) Erasure path: with `legal_hold: true` (in CRM) → blocked; set to false → may still block due to retention (recent `transaction_history.json` per `retention_policies`).


Publishing to GitHub

- Create your local `.env` from `env.example` and never commit real secrets.
- Ensure `token.json` and `credentials.json` are ignored (already in `.gitignore`).
- Verify `out/` and `*.zip` are ignored to avoid uploading DSAR artifacts.
- If you plan to demo Gmail, do not commit any OAuth tokens; use `GMAIL_TOKEN_PATH` locally.
- Optional: add branch protection and required reviews.

