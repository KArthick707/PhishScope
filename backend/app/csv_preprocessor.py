import os
import re
import pandas as pd

from app.scorer import score_email


INPUT_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\raw\phishing\email_text.csv"

OUTPUT_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\email_text_processed.csv"


URL_REGEX = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)

URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify", "suspend", "restricted",
    "limited time", "action required", "confirm", "security alert"
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "sign in", "credential", "account",
    "mfa", "2fa", "authentication", "reset"
]


def extract_urls(text: str) -> list[str]:
    if not isinstance(text, str):
        return []
    return URL_REGEX.findall(text)


def build_features(text: str) -> dict:
    text = str(text).lower()
    urls = extract_urls(text)

    return {
        "reply_to_mismatch": False,
        "return_path_mismatch": False,

        "spf_fail": False,
        "dmarc_fail": False,
        "dkim_missing": True,

        "url_count": len(urls),
        "ip_url_count": 0,
        "shortener_count": 0,
        "suspicious_tld_count": 0,

        "urgency_keyword_count": sum(1 for word in URGENCY_KEYWORDS if word in text),
        "credential_keyword_count": sum(1 for word in CREDENTIAL_KEYWORDS if word in text),

        "attachment_count": 0,
    }


def main():
    df = pd.read_csv(INPUT_FILE)

    rows = []

    for index, row in df.iterrows():

        label = int(row["label"])
        text = str(row["text"])

        features = build_features(text)

        scoring = score_email(features)

        rows.append({
            "label": label,
            "text": text,
            "text_length": len(text),

            "url_count": features["url_count"],
            "urgency_keyword_count": features["urgency_keyword_count"],
            "credential_keyword_count": features["credential_keyword_count"],

            "risk_score": scoring["score"],
            "rule_verdict": scoring["verdict"],

            **features
        })

    output_df = pd.DataFrame(rows)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    output_df.to_csv(OUTPUT_FILE, index=False)

    print(f"Saved processed dataset to: {OUTPUT_FILE}")
    print(f"Total samples: {len(output_df)}")

    print("\nLabel Distribution:")
    print(output_df["label"].value_counts())


if __name__ == "__main__":
    main()