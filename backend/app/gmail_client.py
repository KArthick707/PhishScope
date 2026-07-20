import base64

from googleapiclient.discovery import build

from app.gmail_auth import get_credentials


def fetch_recent_raw_messages(max_results: int = 10) -> list[dict]:
    """Fetches the most recent Gmail messages as raw RFC822 bytes -- the same
    format parse_eml_bytes() already expects from uploaded .eml files, so the
    rest of the pipeline (features/scorer/ml_predictor/decision_engine) needs
    no changes at all."""
    credentials = get_credentials()
    service = build("gmail", "v1", credentials=credentials)

    listing = service.users().messages().list(userId="me", maxResults=max_results, labelIds=["INBOX"]).execute()
    message_refs = listing.get("messages", [])

    results = []
    for ref in message_refs:
        raw_message = service.users().messages().get(userId="me", id=ref["id"], format="raw").execute()
        raw_bytes = base64.urlsafe_b64decode(raw_message["raw"])
        results.append({
            "gmail_id": ref["id"],
            "raw_bytes": raw_bytes,
        })

    return results
