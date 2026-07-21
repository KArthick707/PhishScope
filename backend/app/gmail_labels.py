"""Gmail label management for the triage worker.

One label per non-benign verdict tier -- mirrors the dashboard's own verdict
badges, so a user scanning their label list sees the same severity language
as the dashboard. Deliberately no label for "benign_or_low_risk": tagging
every single email would just be inbox noise, defeating the point of triage.
"""

VERDICT_LABEL_NAMES = {
    "phishing": "PhishScope/Phishing",
    "suspicious": "PhishScope/Suspicious",
    "needs_review": "PhishScope/Needs Review",
}

# In-memory cache of label name -> Gmail label ID for this process. Labels
# rarely change, and re-listing them on every message would be a wasted API
# call per triage cycle.
_label_id_cache: dict[str, str] = {}


def label_name_for_verdict(verdict: str) -> str | None:
    return VERDICT_LABEL_NAMES.get(verdict)


def ensure_label(service, label_name: str) -> str:
    """Returns the Gmail label ID for label_name, creating it if it doesn't
    exist yet. Gmail label creation is idempotent-unsafe (calling create twice
    raises 409 if it already exists), so we always list first."""
    if label_name in _label_id_cache:
        return _label_id_cache[label_name]

    existing = service.users().labels().list(userId="me").execute().get("labels", [])
    for label in existing:
        if label["name"] == label_name:
            _label_id_cache[label_name] = label["id"]
            return label["id"]

    created = service.users().labels().create(
        userId="me",
        body={
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        },
    ).execute()
    _label_id_cache[label_name] = created["id"]
    return created["id"]


def apply_label(service, message_id: str, label_id: str) -> None:
    service.users().messages().modify(
        userId="me",
        id=message_id,
        body={"addLabelIds": [label_id]},
    ).execute()


def label_message_for_verdict(service, message_id: str, verdict: str) -> str | None:
    """Applies the appropriate PhishScope label for verdict, if any. Returns
    the label name applied, or None for benign verdicts (no label)."""
    label_name = label_name_for_verdict(verdict)
    if not label_name:
        return None
    label_id = ensure_label(service, label_name)
    apply_label(service, message_id, label_id)
    return label_name
