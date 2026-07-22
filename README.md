# PhishScope

**Explainable phishing detection, everywhere your email lives.**

PhishScope catches phishing emails and tells you *why* — a hybrid rule engine + calibrated machine-learning model score every message, and every verdict comes with the actual evidence (failing SPF/DKIM, domain mismatches, suspicious language) and the specific words the model keyed on. It's available as a web dashboard, a Gmail Add-on, and an Outlook add-in, all backed by one detection pipeline.

## Why hybrid detection

Most phishing classifiers are either pure keyword/rule engines (brittle, easy to evade) or pure ML text classifiers (opaque, blind to sender authenticity). PhishScope combines both — and we validated that the combination actually matters, not just in theory:

| Evaluation | Hybrid (rules + ML) | Text-only ML |
|---|---|---|
| Bulk text corpus (53k emails, 5-fold CV) | F1 0.993 | F1 0.992 |
| **Real, header-bearing email** (3,450 emails) | **F1 0.936** (89% precision) | F1 0.898 (82% precision) |

On plain text, the two approaches are nearly indistinguishable. Once real email headers (SPF, DKIM, Return-Path) enter the picture, the hybrid model's false-positive rate drops sharply — which is the whole point of combining signals. Full methodology and numbers: [`research/`](research/).

## How it works

```
email → parser → rule engine ─┐
                                ├→ decision engine → verdict + explanation
              → hybrid SVM ────┘
```

1. **Parser** (`backend/app/parser.py`) — extracts headers, body, URLs, attachments from raw `.eml`, or from headers+body delivered separately (Outlook add-ins can't expose raw MIME).
2. **Rule engine** (`features.py`, `scorer.py`) — checks SPF/DKIM/DMARC, sender/reply-to/return-path mismatches, suspicious TLDs and shorteners, credential/urgency language, trusted-domain matches.
3. **Hybrid model** (`ml_predictor.py`) — a calibrated Linear SVM over TF-IDF text features *and* the rule engine's numeric signals, so the ML score itself is informed by header-derived evidence.
4. **Decision engine** (`decision_engine.py`) — merges the rule score and calibrated ML probability into a final verdict (`phishing` / `suspicious` / `needs_review` / `benign_or_low_risk`), tuned against real labeled data rather than guessed thresholds.
5. **Explainability** (`explainer.py`) — surfaces the rule evidence that fired *and* the specific tokens (weighted by SVM coefficient × TF-IDF weight) that pushed the ML model toward or away from "phishing."

## Product surfaces

All three call the same backend pipeline — one detector, three entry points:

- **Web dashboard** — connect a Gmail account and scan your inbox on demand, or let it triage automatically. `backend/app/main.py` (`/dashboard`, `/scan/inbox`).
- **Gmail Add-on** — a sidebar card that scans the open message automatically. See [`gmail-addon/README.md`](gmail-addon/README.md).
- **Outlook add-in** — a taskpane with the same experience for Outlook. See [`outlook-addin/README.md`](outlook-addin/README.md).

Both add-ons preserve full header-aware detection: Gmail's Add-on API and Outlook's `getAllInternetHeadersAsync` both expose complete internet headers, which is why add-ins were chosen over a browser extension that could only see rendered DOM content.

### Live triage

Beyond on-demand scanning, the dashboard runs a background worker (`triage_worker.py`) that polls your inbox (every 60s by default) for new mail using Gmail's incremental history API — no full re-scan each cycle, just what actually arrived. Anything scored above `benign_or_low_risk` gets auto-labeled in Gmail (`PhishScope/Phishing`, `PhishScope/Suspicious`, `PhishScope/Needs Review`) so it's visible in your inbox without opening the dashboard, and the dashboard's "Live triage" panel shows what was just flagged in real time.

This uses polling rather than Gmail's push-notification API (Cloud Pub/Sub) deliberately — no extra GCP infrastructure to stand up, at the cost of up to a minute of latency instead of near-instant delivery. The worker is written so a push-based trigger could replace the polling loop later without touching the analysis or labeling logic.

Labeling requires the broader `gmail.modify` scope (vs. the dashboard's original read-only scope) — connections made before this feature shipped will show a "reconnect" prompt.

## Investigator agent (borderline verdicts)

The pipeline above produces a verdict in one shot. For the genuinely borderline band (`needs_review` / `suspicious`), PhishScope can go a step further and run an **LLM tool-calling agent** that investigates the message the way a SOC analyst would — autonomously deciding what to check, gathering evidence, and producing a structured evidence trail alongside a recommended verdict.

`POST /investigate` takes the same input as the analyze endpoints (raw base64 for Gmail, headers+body for Outlook), re-runs the fast verdict, and — only if the verdict is borderline (or `force: true` is set) — hands the message to the agent (`backend/app/investigator/`). The agent has a small tool belt:

- **`whois_domain_age`** — how recently the sender/link domain was registered (freshly-registered domains strongly correlate with phishing)
- **`dns_lookup`** — whether the domain resolves and publishes MX records (is it actually set up to send mail?)
- **`follow_redirects`** — where a link *actually* lands after following its redirect chain (cloaked destinations)
- **`cross_check_headers`** — does the visible body's claim ("from Microsoft") match the From / Return-Path / SPF / DKIM reality?

It returns the standard analysis dict plus an `investigation` block: the `evidence_trail`, a plain-language `agent_summary`, and a `recommended_verdict`.

**Safety posture.** This is the pipeline's first code that makes outbound network calls driven by attacker-controlled input (URLs and domains lifted from the email), so it is built deny-by-default:

- **Opt-in** — requires an `ANTHROPIC_API_KEY`; without it, `/investigate` returns a clean 503, never a stack trace. Everything else stays offline-by-default.
- **Gated** — requires the same `X-API-Key` as the other analyze endpoints (this release also closes a pre-existing gap where `/analyze/eml` was ungated).
- **SSRF-guarded** — every domain is resolved and every resolved IP is checked against a private / loopback / link-local / cloud-metadata blocklist *before* any connection, on every redirect hop; the scheme is restricted to http/https; redirects and timeouts are capped (`backend/app/investigator/net_guard.py`).
- **Bounded** — hard caps on tool calls and total wall-clock so a crafted email can't steer the agent into unbounded lookups or cost.
- **Advisory** — the agent *recommends*; it never overwrites the pipeline's verdict and never touches the mailbox. The `recommended_verdict` is computed deterministically from the evidence the agent gathered, so a well-worded phishing email can't talk the model into a benign verdict.

Configure via env: `PHISHSCOPE_INVESTIGATOR_MODEL` (default `claude-opus-4-8`; set to e.g. `claude-haiku-4-5` for a cheaper run), `PHISHSCOPE_INVESTIGATOR_MAX_TOOL_CALLS`, `PHISHSCOPE_INVESTIGATOR_TIMEOUT_SECONDS`, `PHISHSCOPE_INVESTIGATOR_MAX_REDIRECTS`.

## Quick start (backend + web dashboard)

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows; use `source venv/bin/activate` on macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then visit `http://localhost:8000/docs` for the API, or set up Gmail OAuth and visit `/dashboard` — see the setup walkthrough in [`gmail-addon/README.md`](gmail-addon/README.md) for the Google Cloud Console steps (same OAuth client works for both the dashboard and the add-on).

## Testing

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v
```

The suite covers the rule engine, the hybrid model's prediction contract, the decision engine (including regression tests for two real bugs found via evaluation — a threshold that made "phishing" verdicts nearly unreachable, and a marketing-pattern heuristic that could mask real phishing), both the Gmail and Outlook API contracts, the label-management/scope-detection logic behind live triage, and the investigator agent (the SSRF egress guard, each tool's signal, the bounded agent loop, and `/investigate` gating). Agent tests mock the LLM and all network I/O — the suite never makes a real request.

## Repository layout

```
backend/          FastAPI app: pipeline, models, dataset tooling, tests
gmail-addon/       Gmail Add-on (Apps Script)
outlook-addin/     Outlook add-in (manifest + taskpane)
research/          Evaluation methodology, benchmark results, literature comparison
docs/              Architecture notes
```

`datasets/` and `models/*.pkl` are intentionally not tracked in git (see `.gitignore`) — they contain real email data and large binaries respectively. Retrain via `backend/app/dataset_preprocessor.py` and `backend/app/train_final_hybrid_model.py`.

## License

All rights reserved — see [`LICENSE`](LICENSE). This repository is public for demonstration and evaluation purposes; it is not open source, and no permission is granted to use, copy, modify, or redistribute the code without prior written permission.
