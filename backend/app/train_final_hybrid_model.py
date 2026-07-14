import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score


DATASET_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\email_text_processed.csv"
MODEL_OUTPUT = r"C:\Users\karth\Desktop\phishscope\models\hybrid_linear_svm_final.pkl"

RULE_FEATURES = [
    "url_count",
    "urgency_keyword_count",
    "credential_keyword_count",
    "risk_score",
    "text_length"
]


def main():
    df = pd.read_csv(DATASET_FILE)
    df = df.dropna(subset=["text", "label"])

    X = df[["text"] + RULE_FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("text", TfidfVectorizer(
                max_features=30000,
                ngram_range=(1, 2),
                stop_words="english"
            ), "text"),
            ("rules", StandardScaler(), RULE_FEATURES)
        ]
    )

    model = Pipeline([
        ("features", preprocessor),
        ("classifier", LinearSVC())
    ])

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("Accuracy :", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred))
    print("Recall   :", recall_score(y_test, y_pred))
    print("F1 Score :", f1_score(y_test, y_pred))
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    os.makedirs(os.path.dirname(MODEL_OUTPUT), exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT)

    print(f"Saved final model to: {MODEL_OUTPUT}")


if __name__ == "__main__":
    main()