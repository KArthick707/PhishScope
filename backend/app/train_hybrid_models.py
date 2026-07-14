import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report


DATASET_FILE = r"C:\Users\karth\Desktop\phishscope\datasets\processed\email_text_processed.csv"
MODEL_DIR = r"C:\Users\karth\Desktop\phishscope\models"
RESULTS_FILE = r"C:\Users\karth\Desktop\phishscope\research\model_comparison_results.csv"


RULE_FEATURES = [
    "url_count",
    "urgency_keyword_count",
    "credential_keyword_count",
    "risk_score",
    "text_length"
]


def get_text(x):
    return x["text"]


def get_rule_features(x):
    return x[RULE_FEATURES]


def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)

    results = {
        "model": name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
    }

    print(f"\n========== {name} ==========")
    print(f"Accuracy : {results['accuracy']:.4f}")
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall   : {results['recall']:.4f}")
    print(f"F1 Score : {results['f1_score']:.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    return results


def make_text_pipeline(model):
    return Pipeline([
        ("text_selector", FunctionTransformer(get_text, validate=False)),
        ("tfidf", TfidfVectorizer(
            max_features=30000,
            ngram_range=(1, 2),
            stop_words="english"
        )),
        ("model", model)
    ])


def make_hybrid_pipeline(model):
    text_branch = Pipeline([
        ("text_selector", FunctionTransformer(get_text, validate=False)),
        ("tfidf", TfidfVectorizer(
            max_features=30000,
            ngram_range=(1, 2),
            stop_words="english"
        ))
    ])

    rule_branch = Pipeline([
        ("rule_selector", FunctionTransformer(get_rule_features, validate=False)),
        ("scaler", StandardScaler())
    ])

    return Pipeline([
        ("features", FeatureUnion([
            ("text_features", text_branch),
            ("rule_features", rule_branch)
        ])),
        ("model", model)
    ])


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)

    print("[+] Loading dataset...")
    df = pd.read_csv(DATASET_FILE)

    df = df.dropna(subset=["text", "label"])

    X = df[["text"] + RULE_FEATURES]
    y = df["label"]

    print(f"[+] Total samples: {len(df)}")
    print("[+] Label distribution:")
    print(y.value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    models = {
        "Naive Bayes": make_text_pipeline(MultinomialNB()),
        "Logistic Regression": make_text_pipeline(
            LogisticRegression(max_iter=1000)
        ),
        "Linear SVM": make_text_pipeline(
            LinearSVC()
        ),
        "Random Forest Rules Only": Pipeline([
            ("rule_selector", FunctionTransformer(get_rule_features, validate=False)),
            ("model", RandomForestClassifier(n_estimators=100, random_state=42))
        ]),
        "Hybrid Logistic Regression": make_hybrid_pipeline(
            LogisticRegression(max_iter=1000)
        ),
        "Hybrid Linear SVM": make_hybrid_pipeline(
            LinearSVC()
        ),
        "Voting Ensemble": VotingClassifier(
            estimators=[
                ("lr", make_text_pipeline(LogisticRegression(max_iter=1000))),
                ("nb", make_text_pipeline(MultinomialNB())),
                ("rf", Pipeline([
                    ("rule_selector", FunctionTransformer(get_rule_features, validate=False)),
                    ("model", RandomForestClassifier(n_estimators=100, random_state=42))
                ]))
            ],
            voting="hard"
        )
    }

    all_results = []

    for name, model in models.items():
        print(f"\n[+] Training {name}...")
        model.fit(X_train, y_train)

        result = evaluate_model(name, model, X_test, y_test)
        all_results.append(result)

        model_path = os.path.join(
            MODEL_DIR,
            name.lower().replace(" ", "_") + ".pkl"
        )

        joblib.dump(model, model_path)
        print(f"[+] Saved model: {model_path}")

    results_df = pd.DataFrame(all_results)
    results_df = results_df.sort_values(by="f1_score", ascending=False)

    results_df.to_csv(RESULTS_FILE, index=False)

    print("\n========== FINAL COMPARISON ==========")
    print(results_df)

    print(f"\n[+] Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()