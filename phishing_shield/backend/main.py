import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.nlp_engine.feature_extractor import extract_features, to_vector
from backend.nlp_engine.vectorizer import EnhancedVectorizer

app = FastAPI(title="TechNova Phishing Shield API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_PATH = MODEL_DIR / "model.joblib"
VECTORIZER_PATH = MODEL_DIR / "vectorizer.joblib"
DB_PATH = Path(__file__).resolve().parent / "storage.db"

model = None
vectorizer: Optional[EnhancedVectorizer] = None
EXPECTED_FEATURES = 12


LOW_RISK_MAX = 0.35
HIGH_RISK_MIN = 0.7


def _triage_percentages(probability: float) -> Dict[str, float]:
    p = min(max(float(probability), 0.0), 1.0)

    safe_raw = max(0.0, 1.0 - (p / LOW_RISK_MAX)) if LOW_RISK_MAX else 0.0
    phishing_raw = max(0.0, (p - LOW_RISK_MAX) / (1.0 - LOW_RISK_MAX))

    if p <= LOW_RISK_MAX:
        suspicious_raw = p / LOW_RISK_MAX
    elif p >= HIGH_RISK_MIN:
        suspicious_raw = max(0.0, (1.0 - p) / (1.0 - HIGH_RISK_MIN))
    else:
        midpoint = (LOW_RISK_MAX + HIGH_RISK_MIN) / 2
        radius = (HIGH_RISK_MIN - LOW_RISK_MAX) / 2
        suspicious_raw = max(0.0, 1.0 - abs(p - midpoint) / radius)

    total = safe_raw + suspicious_raw + phishing_raw
    if total <= 0:
        return {"safe": 0.0, "suspicious": 0.0, "phishing": 100.0}

    return {
        "safe": round((safe_raw / total) * 100, 2),
        "suspicious": round((suspicious_raw / total) * 100, 2),
        "phishing": round((phishing_raw / total) * 100, 2),
    }

class ScanRequest(BaseModel):
    text: str = Field(..., min_length=5, description="Email/message content")


class BatchScanRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1)

    @field_validator("texts")
    @classmethod
    def validate_texts(cls, values: List[str]) -> List[str]:
        filtered = [v for v in values if isinstance(v, str) and v.strip()]
        if not filtered:
            raise ValueError("At least one non-empty text is required")
        return filtered


class CredentialCreateRequest(BaseModel):
    account_type: str = Field(default="google", description="e.g. google")
    google_email: str = Field(..., min_length=5)
    username: Optional[str] = None
    password: str = Field(..., min_length=1)


class CredentialResponse(BaseModel):
    id: int
    account_type: str
    google_email: str
    username: Optional[str]
    created_at: str


class AuditLogResponse(BaseModel):
    id: int
    created_at: str
    mode: str
    text_preview: str
    risk_level: str
    confidence: float
    rule_score: int
    explanations: List[Dict[str, Any]]
    highlighted_lines: List[Dict[str, Any]]
    class_percentages: Dict[str, float]


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                mode TEXT NOT NULL,
                text_preview TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                rule_score INTEGER NOT NULL,
                explanations_json TEXT NOT NULL
            )
            """
        )

        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(audit_logs)").fetchall()
        }

        if "highlighted_lines_json" not in existing_columns:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN highlighted_lines_json TEXT NOT NULL DEFAULT '[]'")
        if "class_percentages_json" not in existing_columns:
            conn.execute(
                "ALTER TABLE audit_logs ADD COLUMN class_percentages_json TEXT NOT NULL DEFAULT '{\"safe\":0,\"suspicious\":0,\"phishing\":0}'"
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_type TEXT NOT NULL,
                google_email TEXT NOT NULL,
                username TEXT,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def load_artifacts() -> None:
    global model, vectorizer, EXPECTED_FEATURES

    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        if hasattr(model, "n_features_in_"):
            EXPECTED_FEATURES = int(model.n_features_in_)

    if VECTORIZER_PATH.exists():
        vectorizer = EnhancedVectorizer().load(VECTORIZER_PATH)


def align_features(vector: List[float], expected_count: int) -> np.ndarray:
    arr = np.asarray(vector, dtype=float)
    if arr.shape[0] == expected_count:
        return arr
    if arr.shape[0] < expected_count:
        return np.pad(arr, (0, expected_count - arr.shape[0]), mode="constant")
    return arr[:expected_count]


def _rule_score(features: Dict[str, Any]) -> int:
    score = 0
    score += int(features.get("suspicious_url_score", 0)) * 2
    score += int(features.get("credential_request_score", 0)) * 3
    score += int(features.get("impersonation_score", 0)) * 2
    score += int(features.get("urgency_score", 0))

    if int(features.get("ip_url_count", 0)) > 0:
        score += 4
    if int(features.get("shortener_url_count", 0)) > 0:
        score += 2
    if int(features.get("lookalike_domain_count", 0)) > 0:
        score += 4
    return score


def _apply_hybrid_risk(ml_confidence: float, features: Dict[str, Any]) -> Dict[str, Any]:
    rule_score = _rule_score(features)

    hybrid_score = (ml_confidence * 0.7) + (min(rule_score, 20) / 20.0 * 0.3)

    if features.get("suspicious_url_score", 0) >= 4:
        risk = "High"
    elif features.get("urgency_score", 0) > 0 and features.get("impersonation_score", 0) > 0:
        risk = "High"
    elif hybrid_score >= HIGH_RISK_MIN:
        risk = "High"
    elif hybrid_score >= LOW_RISK_MAX:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_level": risk,
        "rule_score": rule_score,
        "hybrid_score": round(float(hybrid_score), 4),
    }




def _classification_label(confidence: float, risk_level: str) -> str:
    if confidence >= 0.8 or risk_level == "High":
        return "phishing"
    if confidence >= 0.45 or risk_level == "Medium":
        return "suspicious"
    return "safe"


def _class_percentages(confidence: float) -> Dict[str, float]:
    phishing = max(0.0, min(100.0, confidence * 100.0))
    remainder = max(0.0, 100.0 - phishing)
    suspicious = round(remainder * 0.65, 2)
    safe = round(max(0.0, remainder - suspicious), 2)
    return {
        "phishing": round(phishing, 2),
        "suspicious": suspicious,
        "safe": safe,
    }

def _predict(text: str) -> Dict[str, Any]:
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    features_dict = extract_features(text)

    if vectorizer is not None:
        X = vectorizer.transform([text])
        try:
            prediction = int(model.predict(X)[0])
            probability = float(model.predict_proba(X)[0][1])
        except Exception:
            classic_vector = align_features(to_vector(features_dict), EXPECTED_FEATURES)
            prediction = int(model.predict([classic_vector])[0])
            probability = float(model.predict_proba([classic_vector])[0][1])
    else:
        classic_vector = align_features(to_vector(features_dict), EXPECTED_FEATURES)
        prediction = int(model.predict([classic_vector])[0])
        probability = float(model.predict_proba([classic_vector])[0][1])

    hybrid = _apply_hybrid_risk(probability, features_dict)

    confidence = round(probability, 4)
    class_percentages = _class_percentages(confidence)

    return {
        "is_phishing": bool(prediction),
        "classification": _classification_label(confidence, hybrid["risk_level"]),
        "confidence": confidence,
        "risk_level": hybrid["risk_level"],
        "hybrid_score": hybrid["hybrid_score"],
        "rule_score": hybrid["rule_score"],
        "class_percentages": class_percentages,
        "explanations": features_dict.get("explanations", []),
        "highlighted_lines": features_dict.get("highlighted_lines", []),
    }


def _log_audit(mode: str, text: str, result: Dict[str, Any]) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                created_at,
                mode,
                text_preview,
                risk_level,
                confidence,
                rule_score,
                explanations_json,
                highlighted_lines_json,
                class_percentages_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                mode,
                text[:120],
                result["risk_level"],
                result["confidence"],
                int(result.get("rule_score", 0)),
                json.dumps(result.get("explanations", [])),
                json.dumps(result.get("highlighted_lines", [])),
                json.dumps(result.get("class_percentages", {})),
            ),
        )


def _load_recent_audit_logs(limit: int = 100) -> List[AuditLogResponse]:
    safe_limit = max(1, min(limit, 500))
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                created_at,
                mode,
                text_preview,
                risk_level,
                confidence,
                rule_score,
                explanations_json,
                COALESCE(highlighted_lines_json, '[]'),
                COALESCE(class_percentages_json, '{"safe":0,"suspicious":0,"phishing":0}')
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    logs: List[AuditLogResponse] = []
    for row in rows:
        try:
            explanations = json.loads(row[7]) if row[7] else []
        except json.JSONDecodeError:
            explanations = []

        try:
            highlighted_lines = json.loads(row[8]) if row[8] else []
        except json.JSONDecodeError:
            highlighted_lines = []

        try:
            class_percentages = json.loads(row[9]) if row[9] else {}
        except json.JSONDecodeError:
            class_percentages = {}

        logs.append(
            AuditLogResponse(
                id=row[0],
                created_at=row[1],
                mode=row[2],
                text_preview=row[3],
                risk_level=row[4],
                confidence=float(row[5]),
                rule_score=int(row[6]),
                explanations=explanations if isinstance(explanations, list) else [],
                highlighted_lines=highlighted_lines if isinstance(highlighted_lines, list) else [],
                class_percentages=class_percentages if isinstance(class_percentages, dict) else {},
            )
        )

    return logs


@app.on_event("startup")
def _startup() -> None:
    init_db()
    load_artifacts()


@app.get("/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "online",
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None,
        "expected_features": EXPECTED_FEATURES,
        "db_path": str(DB_PATH),
        "api_version": app.version,
    }


@app.get("/history", response_model=List[AuditLogResponse])
def get_history(limit: int = 100) -> List[AuditLogResponse]:
    return _load_recent_audit_logs(limit)


@app.get("/updates/check")
def check_updates() -> Dict[str, Any]:
    latest_artifact_time = max(
        MODEL_PATH.stat().st_mtime if MODEL_PATH.exists() else 0,
        VECTORIZER_PATH.stat().st_mtime if VECTORIZER_PATH.exists() else 0,
    )
    last_updated = (
        datetime.fromtimestamp(latest_artifact_time, tz=timezone.utc).isoformat()
        if latest_artifact_time
        else None
    )
    return {
        "status": "up_to_date",
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None,
        "model_version": app.version,
        "last_updated": last_updated,
    }


@app.post("/scan")
async def scan_single(request: ScanRequest) -> Dict[str, Any]:
    try:
        result = _predict(request.text)
        _log_audit("single", request.text, result)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Inference error: {exc}") from exc


@app.post("/batch-scan")
async def scan_batch(request: BatchScanRequest) -> Dict[str, Any]:
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    results = []
    for text in request.texts:
        try:
            result = _predict(text)
            _log_audit("batch", text, result)
            results.append({
                "text_preview": f"{text[:60]}..." if len(text) > 60 else text,
                **result,
            })
        except Exception as exc:
            results.append(
                {
                    "text_preview": text[:60],
                    "error": str(exc),
                }
            )

    return {"batch_results": results, "total_scanned": len(request.texts)}


@app.post("/credentials", response_model=CredentialResponse)
def create_credential(payload: CredentialCreateRequest) -> CredentialResponse:
    password_hash = hashlib.sha256(payload.password.encode("utf-8")).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            INSERT INTO credentials (account_type, google_email, username, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.account_type.lower(),
                payload.google_email.lower(),
                payload.username,
                password_hash,
                created_at,
            ),
        )
        credential_id = int(cur.lastrowid)

    return CredentialResponse(
        id=credential_id,
        account_type=payload.account_type.lower(),
        google_email=payload.google_email.lower(),
        username=payload.username,
        created_at=created_at,
    )


@app.get("/credentials", response_model=List[CredentialResponse])
def list_credentials() -> List[CredentialResponse]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, account_type, google_email, username, created_at FROM credentials ORDER BY id DESC"
        ).fetchall()

    return [
        CredentialResponse(
            id=row[0],
            account_type=row[1],
            google_email=row[2],
            username=row[3],
            created_at=row[4],
        )
        for row in rows
    ]
