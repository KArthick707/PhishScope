"""Background polling loop that triages new inbox mail as it arrives.

Chosen over Gmail push notifications (Cloud Pub/Sub) for this stage: no new
GCP infrastructure (topic, webhook endpoint, watch-renewal every 7 days), at
the cost of up to POLL_INTERVAL_SECONDS of latency instead of near-instant
delivery. Can be swapped for a push-based worker later without touching the
analysis pipeline -- this module's only job is "find new messages, analyze,
label," regardless of what triggers each cycle.
"""

import asyncio
import json
import os
import time
import traceback

from app import gmail_auth
from app import gmail_client
from app import gmail_labels
from app.parser import parse_eml_bytes
from app.pipeline import analyze_parsed_email

POLL_INTERVAL_SECONDS = int(os.environ.get("PHISHSCOPE_TRIAGE_POLL_SECONDS", "60"))

# MVP simplification matching gmail_auth.py's token storage: a single local
# gitignored state file. A hosted multi-user version needs this keyed per user
# in a real database instead.
STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".triage_state.json")

MAX_RECENT_RESULTS = 50

_recent_results: list[dict] = []
_status = {"running": False, "last_poll_at": None, "last_error": None}


def _load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_state(state: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def _record_result(gmail_id: str, analysis: dict, label_applied: str | None) -> None:
    decision = analysis.get("final_decision", {})
    email = analysis.get("email", {})
    _recent_results.insert(0, {
        "gmail_id": gmail_id,
        "subject": email.get("subject", ""),
        "from": email.get("from", ""),
        "verdict": decision.get("final_verdict"),
        "confidence": decision.get("confidence"),
        "label_applied": label_applied,
        "detected_at": time.time(),
    })
    del _recent_results[MAX_RECENT_RESULTS:]


def _run_one_cycle() -> None:
    """The blocking half of a poll cycle (Gmail API calls + analysis). Run via
    asyncio.to_thread so it never blocks the server's event loop -- the same
    reasoning FastAPI already applies to main.py's synchronous route handlers."""
    if not (gmail_auth.is_connected() and gmail_auth.has_required_scope()):
        return

    service = gmail_client.build_service()
    state = _load_state()

    if not state.get("last_history_id"):
        # First run after connecting: establish a baseline instead of
        # backfilling the whole inbox as "new" mail.
        baseline = gmail_client.get_current_history_id(service)
        _save_state({"last_history_id": baseline})
        return

    try:
        new_ids, latest_history_id = gmail_client.fetch_new_message_ids_since(
            service, state["last_history_id"]
        )
    except gmail_client.HistoryExpired:
        # Gmail only retains a rolling window of history; if we haven't
        # polled in a while it can expire. Reset to "now" rather than
        # silently missing an unknown range of mail.
        baseline = gmail_client.get_current_history_id(service)
        _save_state({"last_history_id": baseline})
        return

    for message_id in new_ids:
        try:
            raw_bytes = gmail_client.fetch_raw_message(service, message_id)
            parsed = parse_eml_bytes(raw_bytes)
            analysis = analyze_parsed_email(parsed)
            verdict = analysis["final_decision"]["final_verdict"]

            label_applied = gmail_labels.label_message_for_verdict(service, message_id, verdict)
            _record_result(message_id, analysis, label_applied)
        except Exception:
            # One bad message must not stop the rest of the batch or kill the
            # loop -- mirrors core.rule_engine's per-rule isolation elsewhere
            # in this codebase's design.
            traceback.print_exc()

    _save_state({"last_history_id": latest_history_id})


async def run_triage_loop() -> None:
    _status["running"] = True
    while True:
        try:
            await asyncio.to_thread(_run_one_cycle)
            _status["last_error"] = None
        except Exception as exc:
            _status["last_error"] = str(exc)
            traceback.print_exc()
        _status["last_poll_at"] = time.time()
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


def get_status() -> dict:
    return {
        "running": _status["running"],
        "connected": gmail_auth.is_connected() and gmail_auth.has_required_scope(),
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "last_poll_at": _status["last_poll_at"],
        "last_error": _status["last_error"],
        "recent_flags": _recent_results,
    }
