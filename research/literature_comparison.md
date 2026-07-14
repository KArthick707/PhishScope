# Literature Comparison

Published benchmark numbers for phishing/spam email detection, for positioning PhishScope's results against prior work. All numbers below are as reported by the cited papers on their own datasets/splits — not reproduced independently, so treat as approximate context rather than a controlled comparison.

| Study | Dataset | Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Advancing Phishing Email Detection: A Comparative Study of Deep Learning Models (PMC11013960) | Phishing Corpus (2,278) + SpamAssassin (6,047) | Random Forest (best traditional ML) | 99.91% | 99% | - | - |
| Advancing Phishing Email Detection: A Comparative Study of Deep Learning Models (PMC11013960) | same | 1D-CNN + Bi-GRU (best deep learning) | 99.68% | 100% | 99.32% | 99.66% |
| Evolution of Phishing Detection with AI (arXiv:2507.07406) | TREC / Enron-Spam combined | Logistic Regression | 97.04% | - | - | 96.86% |
| Evolution of Phishing Detection with AI (arXiv:2507.07406) | same | SVM | 97.11% | - | - | 96.94% |
| Evolution of Phishing Detection with AI (arXiv:2507.07406) | same | Bi-GRU (best DL hybrid) | 98.77% | - | - | - (AUC-ROC 0.9987) |
| General ML benchmark survey (multiple studies, via search) | Various | Soft-voting ensemble | 99.42% | - | - | 99.42% |

## PhishScope's own results, for comparison

| Slice | Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Bulk text corpus (53,668 rows, 5-fold CV) | Hybrid Linear SVM | 99.28% | 99.02% | 99.63% | 99.33% |
| All real header-aware emails (3,450 rows: personal inbox + SpamAssassin + Nazario, out-of-fold) | Hybrid Linear SVM | 97.48% | 89.34% | 98.30% | 93.61% |
| Same real-header slice | Text-only Linear SVM (no rule features) | 95.77% | 82.18% | 98.92% | 89.78% |

## Takeaways for the paper

- PhishScope's bulk-corpus number (99.3% F1) is in line with published SVM/ensemble results on similarly-sized text corpora (96.9%-99.4% F1 range across the cited studies) — not an outlier, which is reassuring but also means it isn't a differentiator on its own.
- The differentiating result is the **real-header slice comparison**: hybrid vs. text-only on genuinely header-bearing email (93.6% vs 89.8% F1, driven mostly by a large precision gap — 89.3% vs 82.2%). None of the surveyed papers report this specific ablation (hybrid-with-headers vs. text-only on the *same* real corpus), which is a gap PhishScope's evaluation methodology fills.
- Deep-learning approaches (Bi-GRU, 1D-CNN) report ~1-2 points higher accuracy than SVM/LR baselines in the literature, at ~1000x higher inference cost per the cited paper. Worth stating explicitly why PhishScope chose a linear model (interpretability + speed) rather than claiming raw accuracy superiority over DL approaches.

## Sources

- [Advancing Phishing Email Detection: A Comparative Study of Deep Learning Models](https://pmc.ncbi.nlm.nih.gov/articles/PMC11013960/)
- [Evolution of Phishing Detection with AI: A Comparative Review of Next-Generation Techniques](https://arxiv.org/html/2507.07406v1)
- [Comparative Investigation of Traditional Machine-Learning Models and Transformer Models for Phishing Email Detection](https://www.mdpi.com/2079-9292/13/24/4877) (not independently verified — MDPI blocked automated fetch; title/abstract only)
- [In-Depth Analysis of Phishing Email Detection Across Multiple Datasets](https://www.mdpi.com/2076-3417/15/6/3396) (not independently verified — MDPI blocked automated fetch; title/abstract only)
