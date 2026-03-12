from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
import joblib
from pathlib import Path
import os
import socket
import sys

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


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def _normalize_probabilities(raw_scores: dict[str, float]) -> dict[str, float]:
    safe_scores = {k: max(0.0, float(v)) for k, v in raw_scores.items()}
    total = sum(safe_scores.values())
    if total <= 0:
        return {"safe": 33.34, "suspicious": 33.33, "phishing": 33.33}
    return {k: round((v / total) * 100.0, 2) for k, v in safe_scores.items()}


def _build_weighted_risk_features(features_dict: dict) -> tuple[float, list[dict]]:
    factor_config = {
        "suspicious_url_score": {"label": "Suspicious URL patterns", "weight": 0.20, "cap": 10.0},
        "credential_request_score": {"label": "Credential request signals", "weight": 0.24, "cap": 6.0},
        "impersonation_score": {"label": "Impersonation language", "weight": 0.16, "cap": 4.0},
        "urgency_score": {"label": "Urgency / pressure language", "weight": 0.12, "cap": 4.0},
        "ip_url_count": {"label": "Raw IP URLs", "weight": 0.10, "cap": 2.0},
        "shortener_url_count": {"label": "Shortened URLs", "weight": 0.06, "cap": 3.0},
        "lookalike_domain_count": {"label": "Lookalike domains", "weight": 0.12, "cap": 2.0},
    }

    details = []
    weighted_sum = 0.0
    for key, config in factor_config.items():
        raw_value = float(features_dict.get(key, 0) or 0)
        normalized = _clamp(raw_value / config["cap"])
        weighted = normalized * config["weight"]
        weighted_sum += weighted
        details.append(
            {
                "factor": config["label"],
                "feature": key,
                "raw_value": round(raw_value, 3),
                "weight": config["weight"],
                "normalized_score": round(normalized, 4),
                "weighted_contribution": round(weighted, 4),
            }
        )

    return _clamp(weighted_sum), details

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

# Serve favicon to avoid 404 noise in logs; return a tiny inline SVG when not present
@app.get("/favicon.ico")
def favicon():
    fav = FRONTEND_DIST / "favicon.ico"
    if fav.is_file():
        return FileResponse(fav)
    svg = """<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'>\n<rect width='16' height='16' fill='#ef4444'/>\n<text x='8' y='11' font-size='10' text-anchor='middle' fill='white' font-family='Arial'>P</text>\n</svg>"""
    return Response(content=svg, media_type='image/svg+xml')

def perform_prediction(content: str):
    # 1. Extract features for explainability
    features_dict = extract_features(content)
    
    # 2. Transform for model using EnhancedVectorizer (2011 features)
    if vectorizer is None or model is None:
        return {"error": "Model or vectorizer not loaded"}
        
    X = vectorizer.transform([content])
    
    # 3. Predict
    probabilities = list(model.predict_proba(X)[0])
    phishing_prob = _clamp(float(probabilities[1]))
    safe_prob_model = _clamp(float(probabilities[0]))

    # 4. Weighted hybrid scoring from learned probability + explainable factors
    weighted_factor_score, risk_factors = _build_weighted_risk_features(features_dict)
    uncertainty_band = 1.0 - abs(phishing_prob - 0.5) * 2.0

    raw_class_scores = {
        "phishing": (phishing_prob * 0.65) + (weighted_factor_score * 0.35),
        "suspicious": (uncertainty_band * 0.50) + (weighted_factor_score * 0.50),
        "safe": (safe_prob_model * 0.65) + ((1.0 - weighted_factor_score) * 0.35),
    }
    class_percentages = _normalize_probabilities(raw_class_scores)
    prediction = max(class_percentages, key=class_percentages.get)
    top_confidence = class_percentages[prediction] / 100.0

    risk_score = _clamp((phishing_prob * 0.55) + (weighted_factor_score * 0.45))
    if risk_score >= 0.82 or (prediction == "phishing" and class_percentages["phishing"] >= 70):
        risk_level = "Critical"
    elif risk_score >= 0.62 or prediction == "phishing":
        risk_level = "High"
    elif risk_score >= 0.38 or prediction == "suspicious":
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not features_dict.get("explanations"):
        features_dict["explanations"] = [
            {
                "feature": "model_score",
                "value": round(phishing_prob, 4),
                "reason": "Model probability was used to classify this message.",
                "contribution_percent": 100.0,
            }
        ]

    return {
        "is_phishing": risk_level in ["High", "Critical"],
        "classification": prediction,
        "confidence": round(float(top_confidence), 4),
        "risk_level": risk_level,
        "risk_score": round(float(risk_score), 4),
        "risk_factors": risk_factors,
        "class_percentages": class_percentages,
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
    prediction = res.get("classification", "phishing" if res["is_phishing"] else ("suspicious" if res["risk_level"] == "Medium" else "safe"))
    
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
