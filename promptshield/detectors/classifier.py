"""Optional ML detector: TF-IDF (word + char n-grams) + logistic regression.

Lightweight, CPU-only, trains in seconds on the public benchmark and catches
paraphrases that regexes miss. Requires the `ml` extra (scikit-learn, joblib).
"""
from __future__ import annotations

from pathlib import Path

from .base import Finding
from .normalize import normalize


class ClassifierDetector:
    name = "classifier"

    def __init__(self, pipeline):
        self.pipeline = pipeline

    @classmethod
    def train(cls, texts: list[str], labels: list[int]) -> "ClassifierDetector":
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import FeatureUnion, Pipeline

        features = FeatureUnion([
            ("word", TfidfVectorizer(preprocessor=normalize, ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("char", TfidfVectorizer(preprocessor=normalize, analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ])
        pipe = Pipeline([("features", features),
                         ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced"))])
        pipe.fit(texts, labels)
        return cls(pipe)

    def save(self, path: str | Path) -> None:
        import joblib
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, path)

    @classmethod
    def load(cls, path: str | Path) -> "ClassifierDetector":
        # Only load model files you trained yourself: joblib/pickle can execute code.
        import joblib
        return cls(joblib.load(path))

    def probability(self, text: str) -> float:
        return float(self.pipeline.predict_proba([text])[0][1])

    def scan(self, text: str) -> list[Finding]:
        p = self.probability(text)
        return [Finding(self.name, "tfidf_logreg", p, f"p={p:.2f}")] if p >= 0.05 else []
