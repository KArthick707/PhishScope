import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

import joblib
import os


DATASET_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\email_text_processed.csv"

MODEL_OUTPUT = r"C:\Users\karth\Desktop\phishscope\models\random_forest_phishing.pkl"


FEATURE_COLUMNS = [
    "url_count",
    "urgency_keyword_count",
    "credential_keyword_count",
    "risk_score"
]


def main():
    print("[+] Loading dataset...")

    df = pd.read_csv(DATASET_FILE)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    print(f"[+] Total samples: {len(df)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("[+] Training Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X_train, y_train)

    print("[+] Evaluating model...")

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n========== RESULTS ==========")

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:\n")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs(os.path.dirname(MODEL_OUTPUT), exist_ok=True)

    joblib.dump(model, MODEL_OUTPUT)

    print(f"\n[+] Model saved to:")
    print(MODEL_OUTPUT)


if __name__ == "__main__":
    main()