import os
import pandas as pd

from app.parser import parse_eml_bytes
from app.features import extract_features
from app.scorer import score_email


EMAIL_FOLDER = r"C:\Users\karth\Downloads\.EML"
OUTPUT_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\raw\unlabeled_eml_collection.csv"


def process_eml(file_path):
    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    parsed = parse_eml_bytes(raw_bytes)
    features = extract_features(parsed)
    scoring = score_email(features)

    email_text = (
        parsed.get("email", {}).get("subject", "") + " " +
        parsed.get("body", {}).get("preview", "")
    )

    return {
        "file_name": os.path.basename(file_path),
        "label": "",
        "category": "",

        "sender": parsed.get("email", {}).get("from", ""),
        "subject": parsed.get("email", {}).get("subject", ""),
        "text": email_text,

        "rule_score": scoring["score"],
        "rule_verdict": scoring["verdict"],

        **features
    }


def main():
    rows = []

    for file in os.listdir(EMAIL_FOLDER):
        if not file.lower().endswith(".eml"):
            continue

        file_path = os.path.join(EMAIL_FOLDER, file)

        try:
            row = process_eml(file_path)
            rows.append(row)
            print(f"[+] Processed: {file}")

        except Exception as e:
            print(f"[!] Failed: {file} -> {e}")

    df = pd.DataFrame(rows)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print("\nSaved to:", OUTPUT_FILE)
    print("Total samples:", len(df))


if __name__ == "__main__":
    main()