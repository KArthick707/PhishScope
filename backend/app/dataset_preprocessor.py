import os
import pandas as pd

from app.parser import parse_eml_bytes, clean_html
from app.features import extract_features
from app.scorer import score_email


PHISHING_DIR = r"C:\Users\karth\Desktop\phishscope\datasets\raw\phishing"


LEGITIMATE_DIR = r"C:\Users\karth\Desktop\phishscope\datasets\raw\legitimate"

OUTPUT_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\phishscope_dataset.csv"


def source_from_filename(filename: str) -> str:
    if filename.startswith("easy_ham_") or filename.startswith("hard_ham_"):
        return "spamassassin_public_corpus"
    if filename.startswith("phishing0.mbox_") or filename.startswith("phishing1.mbox_"):
        return "nazario_public_corpus"
    return "real_2026_inbox"


def process_directory(directory: str, label: int):
    rows = []

    for filename in os.listdir(directory):
        if not filename.endswith(".eml"):
            continue

        file_path = os.path.join(directory, filename)

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            parsed = parse_eml_bytes(file_bytes)

            features = extract_features(parsed)

            scoring = score_email(features)

            body = parsed["body"]
            html_text = clean_html(body["html"]) if body["html"] else ""
            text = " ".join(
                part for part in (parsed["email"]["subject"], body["text"], html_text) if part
            ).strip()

            row = {
                "filename": filename,
                "label": label,
                "source": source_from_filename(filename),

                "text": text,
                "text_length": len(text),

                "subject": parsed["email"]["subject"],
                "from": parsed["email"]["from"],

                "url_count": parsed["url_count"],
                "attachment_count": parsed["attachment_count"],

                "reply_to_mismatch": features["reply_to_mismatch"],
                "return_path_mismatch": features["return_path_mismatch"],

                "spf_fail": features["spf_fail"],
                "dmarc_fail": features["dmarc_fail"],
                "dkim_missing": features["dkim_missing"],

                "ip_url_count": features["ip_url_count"],
                "shortener_count": features["shortener_count"],
                "suspicious_tld_count": features["suspicious_tld_count"],

                "urgency_keyword_count": features["urgency_keyword_count"],
                "credential_keyword_count": features["credential_keyword_count"],

                "risk_score": scoring["score"],
                "rule_verdict": scoring["verdict"]
            }

            rows.append(row)

            print(f"[+] Processed: {filename}")

        except Exception as e:
            print(f"[!] Failed: {filename} -> {e}")

    return rows


def main():
    phishing_rows = process_directory(PHISHING_DIR, 1)
    legitimate_rows = process_directory(LEGITIMATE_DIR, 0)

    all_rows = phishing_rows + legitimate_rows

    df = pd.DataFrame(all_rows)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nDataset saved to: {OUTPUT_FILE}")
    print(f"Total samples: {len(df)}")


if __name__ == "__main__":
    main()