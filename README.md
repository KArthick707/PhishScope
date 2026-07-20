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

- **Web dashboard** — connect a Gmail account (read-only OAuth) and scan your inbox on demand. `backend/app/main.py` (`/dashboard`, `/scan/inbox`).
- **Gmail Add-on** — a sidebar card that scans the open message automatically. See [`gmail-addon/README.md`](gmail-addon/README.md).
- **Outlook add-in** — a taskpane with the same experience for Outlook. See [`outlook-addin/README.md`](outlook-addin/README.md).

Both add-ons preserve full header-aware detection: Gmail's Add-on API and Outlook's `getAllInternetHeadersAsync` both expose complete internet headers, which is why add-ins were chosen over a browser extension that could only see rendered DOM content.

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

31 tests cover the rule engine, the hybrid model's prediction contract, the decision engine (including regression tests for two real bugs found via evaluation — a threshold that made "phishing" verdicts nearly unreachable, and a marketing-pattern heuristic that could mask real phishing), and both the Gmail and Outlook API contracts.

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
