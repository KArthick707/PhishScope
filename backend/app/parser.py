from email import policy
from email.parser import BytesParser
from email import message_from_string
from bs4 import BeautifulSoup
import re


URL_REGEX = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)


def clean_html(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text(separator=" ", strip=True)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []

    urls = URL_REGEX.findall(text)
    return list(set(urls))


def parse_eml_bytes(file_bytes: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    subject = msg.get("subject", "")
    sender = msg.get("from", "")
    recipient = msg.get("to", "")
    date = msg.get("date", "")
    reply_to = msg.get("reply-to", "")
    return_path = msg.get("return-path", "")

    text_body = ""
    html_body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":
                attachments.append({
                    "filename": part.get_filename(),
                    "content_type": content_type
                })
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                text_body += str(content) + " "
            elif content_type == "text/html":
                html_body += str(content) + " "
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""

        if content_type == "text/plain":
            text_body = str(content)
        elif content_type == "text/html":
            html_body = str(content)

    html_text = clean_html(html_body) if html_body else ""
    full_text = f"{text_body} {html_text}"

    urls = extract_urls(full_text + " " + html_body)

    headers = {
        "authentication_results": msg.get("authentication-results", ""),
        "received_spf": msg.get("received-spf", ""),
        "dkim_signature": msg.get("dkim-signature", ""),
        "reply_to": reply_to,
        "return_path": return_path,
    }

    return {
        "email": {
            "subject": subject,
            "from": sender,
            "to": recipient,
            "date": date,
            "reply_to": reply_to,
            "return_path": return_path,
        },
        "headers": headers,
        "body": {
            "text": text_body.strip(),
            "html": html_body.strip(),
            "preview": full_text[:1000].strip()
        },
        "urls": urls,
        "url_count": len(urls),
        "attachments": attachments,
        "attachment_count": len(attachments)
    }


def parse_headers_and_body(
    headers_text: str,
    html_body: str = "",
    text_body: str = "",
    attachments: list[dict] | None = None,
) -> dict:
    """Builds the same parsed-email dict as parse_eml_bytes() from headers and
    body delivered separately.

    Outlook add-ins (office.js) cannot access a message's raw MIME in a read
    taskpane -- they expose getAllInternetHeadersAsync() (full header block as
    one string) and the rendered body. Re-gluing those into synthetic RFC822
    would break: the original Content-Type header declares multipart
    boundaries that no longer exist in the rendered body. So this parses the
    header block directly and reuses the same body helpers instead.
    """
    msg = message_from_string(headers_text or "", policy=policy.default)
    attachments = attachments or []

    subject = msg.get("subject", "")
    sender = msg.get("from", "")
    recipient = msg.get("to", "")
    date = msg.get("date", "")
    reply_to = msg.get("reply-to", "")
    return_path = msg.get("return-path", "")

    html_text = clean_html(html_body) if html_body else ""
    full_text = f"{text_body} {html_text}"

    urls = extract_urls(full_text + " " + html_body)

    headers = {
        "authentication_results": msg.get("authentication-results", ""),
        "received_spf": msg.get("received-spf", ""),
        "dkim_signature": msg.get("dkim-signature", ""),
        "reply_to": reply_to,
        "return_path": return_path,
    }

    return {
        "email": {
            "subject": subject,
            "from": sender,
            "to": recipient,
            "date": date,
            "reply_to": reply_to,
            "return_path": return_path,
        },
        "headers": headers,
        "body": {
            "text": text_body.strip(),
            "html": html_body.strip(),
            "preview": full_text[:1000].strip()
        },
        "urls": urls,
        "url_count": len(urls),
        "attachments": attachments,
        "attachment_count": len(attachments)
    }