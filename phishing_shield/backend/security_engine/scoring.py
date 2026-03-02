import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, Tuple

# Absolute imports assuming running from root or as module
from backend.nlp_engine.feature_extractor import extract_features
from backend.nlp_engine.vectorizer import EnhancedVectorizer

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "backend" / "model" / "model.joblib"
VECTORIZER_PATH = ROOT / "backend" / "model" / "vectorizer.joblib"

class SecurityEngine:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self._load_model()

    def _load_model(self):
        if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
            raise FileNotFoundError("Model or Vectorizer not found. Run training script first.")
        
        self.model = joblib.load(MODEL_PATH)
        self.vectorizer = EnhancedVectorizer()
        self.vectorizer.load(VECTORIZER_PATH)
        print("Security Engine: Model and Vectorizer loaded successfully.")

    def analyze_email(self, email_data: Dict[str, Any], mode: str = "field") -> Dict[str, Any]:
        """
        Analyze an email and return risk assessment.
        
        Args:
            email_data: Dict containing 'subject', 'body', 'sender', etc.
            mode: 'field' (concise) or 'analyst' (detailed).
        
        Returns:
            Dict with 'risk_score', 'risk_level', 'explanation', etc.
        """
        # 1. Feature Extraction
        features = extract_features(email_data)
        
        # 2. ML Prediction
        # Helper to convert features dict to vector expected by model
        # Note: The training script used `generate_features.py` which used `EnhancedVectorizer`
        # `EnhancedVectorizer` handles raw text list, but here we might have structured data.
        # Actually, `EnhancedVectorizer` takes a list of texts. `extract_features` returns a dict.
        # We need to construct the text input for the vectorizer exactly as done during training.
        
        combined_text = features.get('text', '')
        
        # The vectorizer pipeline (`EnhancedVectorizer`) handles cleaning and feature extraction internally 
        # when we pass it raw text.
        # Let's verify `vectorizer.py`: `fit_transform(texts)` calls `clean_text` then `tfidf` then `_numeric_features`.
        # So we just need to pass `[combined_text]` to `transform`.
        
        X = self.vectorizer.transform([combined_text])
        ml_prob = self.model.predict_proba(X)[0][1] # Probability of phishing (class 1)
        
        # 3. Rule Application & Hybrid Scoring
        final_score, rules_triggered = self._calculate_hybrid_score(ml_prob, features)
        
        # 4. Risk Level classification
        risk_level = self._classify_risk(final_score)
        
        # 5. Construct Response based on Mode
        result = {
            "risk_score": round(final_score, 4),
            "risk_level": risk_level,
            "ml_confidence": round(ml_prob, 4),
            "rules_triggered": rules_triggered
        }
        
        if mode == "analyst":
            result["features"] = features
            result["explanation"] = self._generate_explanation(features, rules_triggered, ml_prob)
            
        return result

    def _calculate_hybrid_score(self, ml_score: float, features: Dict[str, Any]) -> Tuple[float, list]:
        """Combine ML score with heuristic rules and overrides."""
        triggers = []
        score = ml_score
        
        # --- Rule Overrides ---
        
        # 1. High Suspicious URL Score -> Force High Risk
        # (Assuming threshold > 1 indicates multiple suspicious traits or many suspicious URLs)
        if features.get('suspicious_url_score', 0) > 1:
            score = max(score, 0.95)
            triggers.append("CRITICAL: High volume of suspicious URL indicators detected.")

        # 2. Urgency + Impersonation -> Boost Risk
        urgency = features.get('urgency_score', 0)
        impersonation = features.get('impersonation_score', 0)
        
        if urgency > 0 and impersonation > 0:
            boost = 0.15
            if score < 0.85: # Don't boost if already very high, simply clamp
                score += boost
            triggers.append(f"risk_boost: Detected urgency ({urgency}) combined with impersonation language ({impersonation}).")

        # 3. Credential Harvesting cues (if available from recent merge)
        cred_score = features.get('credential_request_score', 0)
        if cred_score > 0:
             boost = 0.2
             if score < 0.8:
                 score += boost
             triggers.append("risk_boost: Credential harvesting language detected.")

        # Clamp score 0-1
        score = min(max(score, 0.0), 1.0)
        
        return score, triggers

    def _classify_risk(self, score: float) -> str:
        if score > 0.80:
            return "High"
        elif score > 0.30:
            return "Medium"
        else:
            return "Low"

    def _generate_explanation(self, features: Dict[str, Any], triggers: list, ml_prob: float) -> str:
        lines = []
        lines.append(f"ML Model Analysis: Calculated phishing probability of {ml_prob:.2%}.")
        
        if triggers:
            lines.append("Heuristic Rules Triggered:")
            for t in triggers:
                lines.append(f"- {t}")
        
        if features.get('explanations'):
             lines.append("Feature Insights:")
             for exp in features['explanations']:
                 lines.append(f"- {exp['feature']}: {exp['reason']} (Value: {exp['value']})")
                 
        return "\n".join(lines)
