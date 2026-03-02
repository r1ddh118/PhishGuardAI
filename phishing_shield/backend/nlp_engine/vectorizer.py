import re
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy.sparse import csr_matrix, hstack

# relative imports inside backend.nlp_engine
from .preprocess import clean_text
from .url_analyzer import analyze_urls
from .urgency_detector import urgency_score
from .impersonation_detector import impersonation_score
from .credential_detector import credential_request_score


def _tokenize_no_clean(text: str):
    return re.findall(r"\w+", text.lower())


def _identity(x):
    return x


class EnhancedVectorizer:
    """TF-IDF + engineered numeric security features pipeline for backend use.

    Numeric features:
    [url_count, suspicious_url_score, ip_url_count, shortener_url_count,
     suspicious_subdomain_count, lookalike_domain_count, urgency_score,
     impersonation_score, credential_request_score, digit_count, length]
    """

    def __init__(self, max_features: int = 2000, ngram_range=(1, 2)):
        # TF-IDF expects already-cleaned text; use a module-level identity preprocessor (picklable)
        self.tfidf = TfidfVectorizer(preprocessor=_identity, tokenizer=_tokenize_no_clean,
                                     ngram_range=ngram_range, max_features=max_features)
        self.scaler = StandardScaler()
        self._is_fitted = False

    def _numeric_features(self, cleaned_texts):
        rows = []
        for t in cleaned_texts:
            url_info = analyze_urls(t)
            urgency = urgency_score(t)
            impersonation = impersonation_score(t)
            credential_score = credential_request_score(t)
            digit_count = sum(c.isdigit() for c in t)
            length = len(t)
            rows.append([
                url_info.get('url_count', 0),
                url_info.get('suspicious_score', 0),
                url_info.get('ip_url_count', 0),
                url_info.get('shortener_url_count', 0),
                url_info.get('suspicious_subdomain_count', 0),
                url_info.get('lookalike_domain_count', 0),
                urgency,
                impersonation,
                credential_score,
                digit_count,
                length,
            ])
        if not rows:
            return np.empty((0, 11), dtype=float)
        return np.asarray(rows, dtype=float)

    def fit(self, texts):
        cleaned = [clean_text(t) for t in texts]
        self.tfidf.fit(cleaned)
        num = self._numeric_features(cleaned)
        if num.size:
            self.scaler.fit(num)
        self._is_fitted = True
        return self

    def transform(self, texts):
        cleaned = [clean_text(t) for t in texts]
        X_text = self.tfidf.transform(cleaned)
        num = self._numeric_features(cleaned)
        if self._is_fitted and num.size:
            num = self.scaler.transform(num)
        X_num = csr_matrix(num)
        return hstack([X_text, X_num], format="csr")

    def fit_transform(self, texts):
        self.fit(texts)
        return self.transform(texts)

    def save(self, path):
        joblib.dump({"tfidf": self.tfidf, "scaler": self.scaler}, path)

    def load(self, path):
        obj = joblib.load(path)
        self.tfidf = obj["tfidf"]
        self.scaler = obj["scaler"]
        self._is_fitted = True
        return self
