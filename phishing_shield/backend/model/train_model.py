from pathlib import Path
from time import perf_counter
import sys
import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression, PassiveAggressiveClassifier, Perceptron, SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.nlp_engine.vectorizer import EnhancedVectorizer

# --- Constants ---
HIGH_RISK_MIN = 0.8
LOW_RISK_MAX = 0.5

def _metrics(y_true, y_pred, y_prob):
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
    }

def _risk_thresholds(proba: float) -> str:
    if proba >= HIGH_RISK_MIN:
        return "High"
    if proba >= LOW_RISK_MAX:
        return "Medium"
    return "Low"

def _severity_bucket(probability: float) -> str:
    if probability >= 0.8:
        return "high"
    if probability >= 0.5:
        return "low"
    return "safe"

def _to_prob(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    decision = model.decision_function(X)
    return (decision - decision.min()) / max(decision.max() - decision.min(), 1e-8)

def train():
    root = Path(__file__).resolve().parents[2]
    data_path = root / "data" / "features.csv"
    npz_path = root / "data" / "features.npz"
    model_save_path = Path(__file__).resolve().parent / "model.joblib"
    metrics_save_path = Path(__file__).resolve().parent / "model_metrics.joblib"
    vectorizer_save_path = Path(__file__).resolve().parent / "vectorizer.joblib"

    print(f"Loading data from {data_path}...")
    if not data_path.exists() or not npz_path.exists():
        raise FileNotFoundError(f"Feature files not found. Run generate_features.py first.")

    df = pd.read_csv(data_path, low_memory=False)
    X = sparse.load_npz(npz_path)
    
    # Robust label mapping
    def map_label(val):
        if pd.isna(val): return np.nan
        s = str(val).strip().lower()
        if s in ('phishing', 'phish', '1', '1.0', '1'): return 1
        if s in ('legitimate', 'legit', 'safe', '0', '0.0', '0'): return 0
        return np.nan

    y = df["label"].apply(map_label)
    mask = y.notnull()
    y = y[mask].astype(int)
    X = X[mask.to_numpy()]

    print(f"Training on {X.shape[0]} samples with {X.shape[1]} features...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Note: Reduced candidates for speed in high-dim space, focus on winners
    candidates = {
        "logistic_regression": (LogisticRegression(max_iter=1000), {"C": [1.0]}),
        "random_forest": (RandomForestClassifier(random_state=42, n_jobs=-1), {"n_estimators": [100]}),
    }

    best_name = None
    best_model = None
    best_score = -1.0
    all_metrics = {}

    for name, (base_model, grid) in candidates.items():
        print(f"Evaluating {name}...")
        # Reduce CV folds for speed given the large feature set
        search = GridSearchCV(base_model, grid, scoring="f1", cv=2, n_jobs=-1)
        search.fit(X_train, y_train)

        model = search.best_estimator_
        y_pred = model.predict(X_test)
        y_prob = _to_prob(model, X_test)

        m = _metrics(y_test, y_pred, y_prob)
        m["best_params"] = search.best_params_
        all_metrics[name] = m

        print(f"  F1 Score: {m['f1']:.4f}")

        if m["f1"] > best_score:
            best_score = m["f1"]
            best_name = name
            best_model = model

    t0 = perf_counter()
    _ = best_model.predict(X_test[:50])
    inference_ms = (perf_counter() - t0) * 1000

    best_prob = _to_prob(best_model, X_test)
    best_pred = best_model.predict(X_test)

    distribution = {"safe": 0, "low": 0, "high": 0}
    for p in best_prob:
        distribution[_severity_bucket(float(p))] += 1

    total = max(len(best_prob), 1)
    severity_percentages = {k: round((v / total) * 100.0, 2) for k, v in distribution.items()}

    sample_thresholds = {
        "low": _risk_thresholds(0.2),
        "medium": _risk_thresholds(0.5),
        "high": _risk_thresholds(0.9),
    }

    joblib.dump(best_model, model_save_path)
    joblib.dump(
        {
            "best_model": best_name,
            "models_evaluated": len(all_metrics),
            "metrics": all_metrics,
            "inference_ms_for_50_samples": round(inference_ms, 3),
            "risk_thresholds": sample_thresholds,
            "classes": ["safe", "suspicious", "phishing"],
            "severity_distribution": distribution,
            "severity_percentages": severity_percentages,
            "test_set_size": int(total),
            "phishing_rate_percent": round(float(best_pred.mean() * 100.0), 2),
        },
        metrics_save_path,
    )

    print(f"Saved best model ({best_name}) to {model_save_path}")
    print(f"Saved model metrics to {metrics_save_path}")

if __name__ == "__main__":
    train()
