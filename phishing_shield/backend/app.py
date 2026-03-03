from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
import joblib
from pathlib import Path
import os
import socket
import sys
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.nlp_engine.vectorizer import EnhancedVectorizer
from backend.nlp_engine.feature_extractor import extract_features




ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
FRONTEND_DIST = PROJECT_ROOT / "PWA_frontend" / "dist"
MODEL_PATH = ROOT / "model" / "model.joblib"
VECTORIZER_PATH = ROOT / "model" / "vectorizer.joblib"

# Global variables for model and vectorizer
model = None
vectorizer = None

def load_model():
    global model, vectorizer
    if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
        raise RuntimeError(f"Model or Vectorizer not found in {ROOT / 'model'}. Run training first.")
    
    print("Loading model and vectorizer...")
    model = joblib.load(MODEL_PATH)
    vectorizer = EnhancedVectorizer().load(VECTORIZER_PATH)
    print("Model and vectorizer loaded successfully.")


@asynccontextmanager
async def lifespan(_: FastAPI):
    load_model()
    yield

app = FastAPI(title="Phishing Detection API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

class ScanRequest(BaseModel):
    text: str

class BatchScanRequest(BaseModel):
    texts: list[str]

@app.get("/health")
def read_health():
    return {
        "status": "online",
        "model_version": "2.4.0",
        "frontend_dist_found": FRONTEND_DIST.exists(),
    }


@app.get("/updates/check")
def check_updates():
    return {
        "status": "up_to_date",
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None,
        "model_version": "2.4.0",
        "last_updated": "2026-03-02T14:00:00Z"
    }

def perform_prediction(content: str):
    # 1. Extract features for explainability
    features_dict = extract_features(content)
    
    # 2. Transform for model using EnhancedVectorizer (2011 features)
    if vectorizer is None or model is None:
        return {"error": "Model or vectorizer not loaded"}
        
    X = vectorizer.transform([content])
    
    # 3. Predict
    probabilities = list(model.predict_proba(X)[0])
    phishing_prob = float(probabilities[1])
    
    # 4. Initial Verdict
    if phishing_prob < 0.3:
        prediction = "safe"
        risk_level = "Low"
    elif phishing_prob < 0.8:
        prediction = "suspicious"
        risk_level = "Medium"
    else:
        prediction = "phishing"
        risk_level = "High"
        if phishing_prob > 0.95:
            risk_level = "Critical"

    # --- SAFETY SHIELD HEURISTIC ---
    is_short = features_dict.get("length", 0) < 100
    has_no_urls = features_dict.get("url_count", 0) == 0
    has_no_urgency = features_dict.get("urgency_score", 0) == 0
    has_low_impersonation = features_dict.get("impersonation_score", 0) < 2
    has_no_credentials = features_dict.get("credential_request_score", 0) == 0
    
    if is_short and has_no_urls and has_no_urgency and has_low_impersonation and has_no_credentials:
        if risk_level in ["Medium", "High", "Critical"]:
            print(f"Safety Shield Triggered: Downgrading {risk_level} to Low.")
            risk_level = "Low"
            prediction = "safe"
            if phishing_prob > 0.5:
                phishing_prob = 1.0 - phishing_prob

    return {
        "is_phishing": prediction == "phishing",
        "confidence": float(max(probabilities) if prediction != "safe" else (1.0 - phishing_prob)),
        "risk_level": risk_level,
        "explanations": features_dict.get("explanations", []),
        "highlighted_lines": features_dict.get("highlighted_lines", [])
    }

@app.post("/scan")
async def scan(request: ScanRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    return perform_prediction(request.text)

@app.post("/batch-scan")
async def batch_scan(request: BatchScanRequest):
    results = []
    for text in request.texts:
        res = perform_prediction(text)
        results.append({
            "text_preview": text[:50] + "...",
            "is_phishing": res["is_phishing"],
            "confidence": res["confidence"],
            "risk_level": res["risk_level"]
        })
    return {"batch_results": results, "total_scanned": len(results)}

@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    # Backward compatibility for old frontend
    res = perform_prediction(request.content)
    prediction = "phishing" if res["is_phishing"] else ("suspicious" if res["risk_level"] == "Medium" else "safe")
    
    return PredictResponse(
        prediction=prediction,
        confidence=res["confidence"],
        riskLevel=res["risk_level"].lower(),
        triggeredFeatures=[{"name": f["feature"], "detected": True, "severity": 0.8} for f in res["explanations"]],
        explanation=" | ".join([f"{f['feature']}: {f['reason']}" for f in res["explanations"]]) or "No specific phishing indicators detected."
    )

if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

    @app.get("/")
    def serve_index():
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        candidate = FRONTEND_DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/")
    def read_root():
        return JSONResponse(
            {
                "status": "online",
                "model_version": "2.4.0",
                "message": "Frontend build not found. Run `npm run build` in phishing_shield/PWA_frontend.",
            }
        )

if __name__ == "__main__":
    import uvicorn

    def resolve_port(default_port: int = 8000) -> int:
        configured_port = int(os.environ.get("PORT", default_port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sock.connect_ex(("127.0.0.1", configured_port)) != 0:
                return configured_port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            fallback_port = sock.getsockname()[1]

        print(
            f"Port {configured_port} is already in use. "
            f"Starting server on available port {fallback_port} instead."
        )
        return fallback_port

    uvicorn.run(app, host="0.0.0.0", port=resolve_port())
