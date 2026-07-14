# PhishScope Architecture

PhishScope is an explainable hybrid phishing detection framework.

## Final Proposed Architecture

1. Email/Text Input
2. Parser
3. Feature Extraction
4. Rule-Based Risk Engine
5. Linear SVM Text Classifier
6. Hybrid Decision Layer
7. Explainability Layer
8. Final Analyst Verdict

## Winning Model

Based on experimental evaluation across seven models, the Hybrid Linear SVM achieved the best performance.

| Model | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Hybrid Linear SVM | 0.9940 | 0.9915 | 0.9978 | 0.9947 |
| Linear SVM | 0.9939 | 0.9914 | 0.9978 | 0.9946 |
| Hybrid Logistic Regression | 0.9902 | 0.9871 | 0.9955 | 0.9913 |
| Logistic Regression | 0.9899 | 0.9866 | 0.9955 | 0.9910 |
| Voting Ensemble | 0.9857 | 0.9888 | 0.9856 | 0.9872 |
| Naive Bayes | 0.9751 | 0.9917 | 0.9634 | 0.9774 |
| Random Forest Rules Only | 0.6458 | 0.6649 | 0.7355 | 0.6984 |

## Why Hybrid Linear SVM Was Selected

The Hybrid Linear SVM was selected because it achieved the best balance between accuracy, precision, recall, and F1-score.

It combines:
- semantic text classification
- rule-based phishing indicators
- URL and credential-related features
- explainable scoring signals

This makes it suitable for analyst-centered phishing detection.