# PhishScope Gmail Add-on

A Google Workspace Add-on that analyzes the currently open Gmail message with
the PhishScope backend (full header-aware rule engine + calibrated hybrid SVM)
and shows the verdict in Gmail's sidebar — on web **and** the Gmail mobile apps.

## How it works

1. User opens a message → contextual trigger fires (`onGmailMessageOpen`).
2. The add-on fetches that one message in raw RFC822 form via the Gmail REST
   API, using the per-message access token Gmail hands the trigger. The scope
   (`gmail.addons.current.message.readonly`) only reaches the *open* message —
   never the rest of the inbox.
3. The raw message is POSTed to the backend's `/analyze/raw` endpoint
   (base64url passthrough, no re-encoding).
4. The backend runs the exact same pipeline as the web app / CLI and the card
   renders verdict, confidence, advice, rule evidence, and the ML token
   explanation.

## Setup (development)

1. Go to [script.google.com](https://script.google.com) → **New project**.
2. Project Settings → check **Show "appsscript.json" manifest file**.
3. Replace the default `appsscript.json` and `Code.gs` with the files in this
   directory. (Or use [clasp](https://github.com/google/clasp): `clasp create
   --type standalone`, copy files, `clasp push`.)
4. Project Settings → **Script Properties**:
   - `PHISHSCOPE_BACKEND_URL` — public HTTPS URL of the FastAPI backend.
     Apps Script runs on Google's servers, so `localhost` will NOT work; for
     development expose your local server with a tunnel (e.g. `ssh -R` tunnel,
     ngrok, or cloudflared) and use that URL.
   - `PHISHSCOPE_API_KEY` — optional; must match the backend env var of the
     same name if set.
5. **Deploy → Test deployments → Install**. Open Gmail, open any message, and
   click the PhishScope icon in the right sidebar.

## Before publishing to the Workspace Marketplace

- Add `"urlFetchWhitelist": ["https://YOUR-BACKEND-DOMAIN/"]` to
  `appsscript.json` (required for published add-ons that call external URLs).
- Replace `logoUrl` with your own hosted 128x128 icon.
- Google OAuth verification is required for the Gmail add-on scopes. These are
  "sensitive" scopes (standard verification), not "restricted" ones — the
  expensive CASA security assessment is not triggered because the add-on never
  requests whole-inbox access.
- Publish a privacy policy URL explaining that message content is sent to your
  backend for analysis and not stored.

## Backend requirements

- `POST /analyze/raw` (added in `backend/app/main.py`) reachable over HTTPS.
- Set `PHISHSCOPE_API_KEY` on the server so the public endpoint isn't open.
