from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
from pathlib import Path
import numpy as np
from backend.nlp_engine.vectorizer import EnhancedVectorizer
from backend.nlp_engine.feature_extractor import extract_features

app = FastAPI(title="Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "model" / "model.joblib"
VECTORIZER_PATH = ROOT / "model" / "vectorizer.joblib"

# Global variables for model and vectorizer
model = None
vectorizer = None

@app.on_event("startup")
def load_model():
    global model, vectorizer
    if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
        raise RuntimeError(f"Model or Vectorizer not found in {ROOT / 'model'}. Run training first.")
    
    print("Loading model and vectorizer...")
    model = joblib.load(MODEL_PATH)
    vectorizer = EnhancedVectorizer().load(VECTORIZER_PATH)
    print("Model and vectorizer loaded successfully.")

class PredictRequest(BaseModel):
    content: str
    subject: str = None
    sender: str = None

class PredictResponse(BaseModel):
    prediction: str
    confidence: float
    riskLevel: str
    triggeredFeatures: list
    explanation: str

@app.get("/")
def read_root():
    return {"status": "online", "model_version": "1.0.0"}

@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    if model is None or vectorizer is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    # 1. Extract features for explainability
    email_data = {
        "body": request.content,
        "subject": request.subject,
        "sender": request.sender
    }
    features_dict = extract_features(email_data)
    
    # 2. Transform text for model
    # EnhancedVectorizer handles both text and engineered features
    X = vectorizer.transform([request.content])
    
    # 3. Predict
    prediction_idx = int(model.predict(X)[0])
    probabilities = list(model.predict_proba(X)[0])
    confidence = float(probabilities[prediction_idx])
    
    # 4. Determine risk level
    # logic similar to train_model thresholds
    phishing_prob = float(probabilities[1])
    
    import uuid
    request_id = str(uuid.uuid4())[:8]
    
    print(f"\n--- [Request {request_id}] ---")
    print(f"Content: {request.content[:50]}...")
    print(f"Engineered Features: { {k:v for k,v in features_dict.items() if k != 'text'} }")
    print(f"Model Classes: {model.classes_}")
    print(f"Prediction Index: {prediction_idx}")
    print(f"Probabilities: {probabilities}")
    print(f"Initial Phishing Prob: {phishing_prob}")
    
    if phishing_prob < 0.3:
        prediction = "safe"
        riskLevel = "low"
    elif phishing_prob < 0.8:
        prediction = "suspicious"
        riskLevel = "medium"
    else:
        prediction = "phishing"
        riskLevel = "high"
        if phishing_prob > 0.95:
            riskLevel = "critical"

    # --- SAFETY SHIELD HEURISTIC ---
    # Downgrade if: 
    # 1. Short message (< 100 chars)
    # 2. No URLs
    # 3. No other high-risk indicators
    is_short = features_dict.get("length", 0) < 100
    has_no_urls = features_dict.get("url_count", 0) == 0
    has_no_urgency = features_dict.get("urgency_score", 0) == 0
    has_low_impersonation = features_dict.get("impersonation_score", 0) < 2
    has_no_credentials = features_dict.get("credential_request_score", 0) == 0
    
    if is_short and has_no_urls and has_no_urgency and has_low_impersonation and has_no_credentials:
        if riskLevel in ["medium", "high", "critical"]:
            print(f"[Request {request_id}] Safety Shield Triggered: Downgrading {riskLevel} to low/safe.")
            prediction = "safe"
            riskLevel = "low"
            # Adjust confidence to reflect the safety override if it was leaning phishing
            if phishing_prob > 0.5:
                # If model was over 50% phishing but we are sure it is safe, 
                # we return the probability of it being SAFE (1 - phishing_prob)
                confidence = float(1.0 - phishing_prob)
            
    # 5. Format response
    triggered_explanations = features_dict.get("explanations", [])
    triggeredFeatures = [
        {"name": f["feature"], "detected": True, "severity": float(f["value"]) if isinstance(f["value"], (int, float)) else 1.0}
        for f in triggered_explanations
    ]
    
    explanation_text = " | ".join([f"{f['feature']}: {f['reason']}" for f in triggered_explanations])
    if not explanation_text:
        explanation_text = "No specific phishing indicators detected."

    return PredictResponse(
        prediction=prediction,
        confidence=confidence,
        riskLevel=riskLevel,
        triggeredFeatures=triggeredFeatures,
        explanation=explanation_text
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
