import base64

from googleapiclient.discovery import build

from app.gmail_auth import get_credentials


def build_service():
    return build("gmail", "v1", credentials=get_credentials())


def fetch_raw_message(service, message_id: str) -> bytes:
    """Fetches one message as raw RFC822 bytes -- the same format
    parse_eml_bytes() already expects from uploaded .eml files, so the rest of
    the pipeline (features/scorer/ml_predictor/decision_engine) needs no
    changes at all."""
    raw_message = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
    return base64.urlsafe_b64decode(raw_message["raw"])


def fetch_recent_raw_messages(max_results: int = 10) -> list[dict]:
    """Fetches the most recent Gmail messages as raw RFC822 bytes."""
    service = build_service()

    listing = service.users().messages().list(userId="me", maxResults=max_results, labelIds=["INBOX"]).execute()
    message_refs = listing.get("messages", [])

    return [
        {"gmail_id": ref["id"], "raw_bytes": fetch_raw_message(service, ref["id"])}
        for ref in message_refs
    ]


def get_current_history_id(service) -> str:
    """Gmail's watermark for incremental sync -- everything after this
    historyId is "new" the next time we poll."""
    profile = service.users().getProfile(userId="me").execute()
    return profile["historyId"]


def fetch_new_message_ids_since(service, start_history_id: str) -> tuple[list[str], str]:
    """Returns (new_message_ids, latest_history_id) for INBOX messages added
    since start_history_id. Raises HistoryExpired if Gmail has already
    discarded that historyId (it only retains a rolling ~1 week of history),
    signaling the caller to fall back to a fresh baseline instead of missing
    messages silently."""
    from googleapiclient.errors import HttpError

    message_ids: list[str] = []
    page_token = None
    latest_history_id = start_history_id

    try:
        while True:
            response = service.users().history().list(
                userId="me",
                startHistoryId=start_history_id,
                historyTypes=["messageAdded"],
                labelId="INBOX",
                pageToken=page_token,
            ).execute()

            for record in response.get("history", []):
                for added in record.get("messagesAdded", []):
                    message_ids.append(added["message"]["id"])

            latest_history_id = response.get("historyId", latest_history_id)
            page_token = response.get("nextPageToken")
            if not page_token:
                break
    except HttpError as exc:
        if exc.resp.status == 404:
            raise HistoryExpired() from exc
        raise

    # dedupe while preserving order (the same message can appear in multiple
    # history records, e.g. added then labeled)
    seen = set()
    unique_ids = []
    for mid in message_ids:
        if mid not in seen:
            seen.add(mid)
            unique_ids.append(mid)

    return unique_ids, latest_history_id


class HistoryExpired(Exception):
    """Raised when Gmail no longer has history for the requested historyId."""
