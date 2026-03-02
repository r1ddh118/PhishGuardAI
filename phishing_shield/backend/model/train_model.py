
import argparse
import time
import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report
from pathlib import Path

# Optional XGBoost
try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "backend" / "model"
FEATURE_CSV = DATA_DIR / "features.csv"
FEATURE_NPZ = DATA_DIR / "features.npz"
MODEL_PATH = MODEL_DIR / "model.joblib"


def load_data():
    if not FEATURE_CSV.exists() or not FEATURE_NPZ.exists():
        raise FileNotFoundError(f"Feature files not found in {DATA_DIR}. Run generate_features.py first.")
    
    print("Loading features...")
    df = pd.read_csv(FEATURE_CSV, low_memory=False)
    X = sparse.load_npz(FEATURE_NPZ)
    
    print(f"Loaded {X.shape[1]} features from {FEATURE_NPZ.name}")
    
    # Extract labels
    def map_label(val):
        if pd.isna(val):
            return np.nan
        s = str(val).strip().lower()
        if s in ('phishing', 'phish', '1', '1.0', '1'):
            return 1
        if s in ('legitimate', 'legit', 'safe', '0', '0.0', '0'):
            return 0
        return np.nan

    y = df['label'].apply(map_label).values
    
    mask = ~np.isnan(y)
    if not np.all(mask):
        print(f"Dropping {len(y) - np.sum(mask)} rows with missing/invalid labels")
        y = y[mask].astype(int)
        X = X[mask]
    
    return X, y


def train_and_evaluate(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    if HAS_XGB:
        models['XGBoost'] = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    
    results = {}
    best_model = None
    best_f1 = 0.0
    
    print("\nTraining models...")
    for name, model in models.items():
        print(f"Training {name}...")
        start_time = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - start_time
        
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_prob)
        
        results[name] = {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1,
            'roc_auc': roc,
            'train_time': train_time
        }
        
        print(f"  Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}, ROC-AUC: {roc:.4f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            
    return results, best_model, X_test, y_test


def optimize_model(model, X_train, y_train):
    # Determine model type and tune
    if isinstance(model, RandomForestClassifier):
        param_dist = {
            'n_estimators': [100, 200, 300],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        search = RandomizedSearchCV(model, param_distributions=param_dist, n_iter=10, cv=3, scoring='f1', random_state=42, n_jobs=-1)
        print("\nTuning Random Forest...")
        search.fit(X_train, y_train)
        print(f"Best params: {search.best_params_}")
        return search.best_estimator_
        
    elif HAS_XGB and isinstance(model, xgb.XGBClassifier):
        param_dist = {
            'n_estimators': [100, 200, 300],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [3, 5, 7],
            'subsample': [0.8, 1.0]
        }
        search = RandomizedSearchCV(model, param_distributions=param_dist, n_iter=10, cv=3, scoring='f1', random_state=42, n_jobs=-1)
        print("\nTuning XGBoost...")
        search.fit(X_train, y_train)
        print(f"Best params: {search.best_params_}")
        return search.best_estimator_
        
    return model


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    X, y = load_data()
    print(f"Data suited for training: {X.shape[0]} samples, {X.shape[1]} features")
    
    # 1. Train and select best base model
    results, best_model, X_test, y_test = train_and_evaluate(X, y)
    
    print(f"\nBest base model: {type(best_model).__name__}")
    
    # 2. Optimize best model
    # Split again to find X_train for optimization (or just pass it from train_and_evaluate if refactored)
    # For simplicity, let's retrain best model architecture with tuning on full train set
    X_train, X_test_final, y_train, y_test_final = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    final_model = optimize_model(best_model, X_train, y_train)
    
    # 3. Final Evaluation
    print("\nFinal Model Evaluation:")
    y_pred = final_model.predict(X_test_final)
    y_prob = final_model.predict_proba(X_test_final)[:, 1]
    
    print(classification_report(y_test_final, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test_final, y_prob):.4f}")
    
    # 4. Save Model
    joblib.dump(final_model, MODEL_PATH)
    print(f"\nModel and metadata saved to {MODEL_DIR}")
    
    # 5. Inference Speed Test
    print("\nTesting inference speed...")
    sample = X_test_final[:100]
    start = time.time()
    final_model.predict(sample)
    duration = time.time() - start
    print(f"Inference time for 100 samples: {duration:.4f}s ({duration/100:.6f}s/sample)")
    
    # 6. Define Thresholds
    # Simple quantile-based or fixed thresholds
    # We want high confidence for High Risk
    # Low Risk: < 0.3, Medium: 0.3 - 0.8, High: > 0.8 (Example)
    # Let's just print a suggested threshold config
    print("\nRecommended Risk Thresholds (Probability of Phishing):")
    print("  Low Risk:    < 0.30")
    print("  Medium Risk: 0.30 - 0.80")
    print("  High Risk:   > 0.80")


if __name__ == "__main__":
    main()
