# PhishScope Outlook Add-in

An Outlook add-in (web + new/classic desktop + Mac) that analyzes the open
message with the PhishScope backend and shows the verdict in a taskpane.

## How it works

Unlike the Gmail add-on (which Google hosts as Apps Script), an Outlook add-in
is a **web page you host** that Outlook loads in a sidebar iframe:

1. User clicks **Scan with PhishScope** on a message (or the pane is already
   open) → `taskpane.html` loads.
2. office.js provides the message context: `getAllInternetHeadersAsync()`
   returns the complete internet header block (SPF/DKIM/Return-Path included —
   full header-aware detection survives), and `item.body.getAsync` returns the
   rendered body. Raw MIME is not available in a read taskpane, which is why
   headers and body travel separately.
3. Both are POSTed to the backend's `/analyze/outlook`, which rebuilds the
   parsed-email structure (`parse_headers_and_body`) and runs the exact same
   pipeline as every other entry point.

## Development setup

1. **Host the taskpane over HTTPS** (Office requires HTTPS even on localhost):
   ```
   npx office-addin-dev-certs install
   npx http-server outlook-addin -S -C ~/.office-addin-dev-certs/localhost.crt -K ~/.office-addin-dev-certs/localhost.key -p 3000
   ```
2. **Run the backend with CORS enabled** for the taskpane origin:
   ```
   set PHISHSCOPE_CORS_ORIGINS=https://localhost:3000
   uvicorn app.main:app --port 8000
   ```
   Edit `BACKEND_URL` (and `API_KEY` if used) at the top of `taskpane.js`.
3. **Sideload the manifest**: Outlook on the web → Settings → Manage add-ins →
   My add-ins → Add a custom add-in → Add from file → `manifest.xml`.
   (Or visit https://aka.ms/olksideload.)
4. Open any message → **Scan with PhishScope** appears in the ribbon/overflow
   menu → the taskpane auto-scans on open.

Add placeholder icons at `assets/icon-{16,32,64,80,128}.png` (any square PNG
works for development).

## Before publishing to AppSource

- Host the taskpane + assets on a real HTTPS domain and update every
  `https://localhost:3000` URL in `manifest.xml` and `taskpane.js`.
- Generate your own GUID for `<Id>` if you fork this.
- AppSource review requires a privacy policy and support URL; state that
  message content is sent to your backend for analysis and not stored.
- `Permissions` is `ReadItem` — the add-in never sees the rest of the mailbox,
  which keeps the AppSource privacy review simple. Do not widen it.

## Keep in sync

`VERDICT_STYLES` (the per-verdict advice text) exists in both
`gmail-addon/Code.gs` and `taskpane.js` — edit both together.
