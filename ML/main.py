#!/usr/bin/env python3
"""
FastAPI ML Prediction Service for Wazuh SOC Alert Classification
================================================================
Serves the Random Forest model to classify Wazuh alerts as:
  - 0 = False Positive (false alarm)
  - 1 = True Positive (real threat)

Features are computed on-the-fly per srcip, matching the training pipeline exactly.
Frozen feature order: [rule_level, inter_arrival_time, alert_count_10s,
                       alert_count_30s, alert_count_60s, iat_std]
"""

import json
import time
import logging
import statistics
import re
from urllib.parse import urlparse
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
MODEL_PATH = Path(__file__).parent / "model.pkl"
FEATURES_PATH = Path(__file__).parent / "features.json"

# Web-related rule IDs the model was trained on
WEB_RULE_IDS = {
    "31101", "31103", "31104", "31105", "31106",
    "31151", "100112", "100113",
}

# How long to keep history per srcip (seconds) — 120s is enough for 60s window + buffer
HISTORY_TTL = 120.0

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Path(__file__).parent / "ml-api.log"),
    ],
)
logger = logging.getLogger("ml-api")

# ---------------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Wazuh ML Alert Classifier",
    description="Classifies Wazuh alerts as True Positive or False Positive",
    version="1.0.0",
)

# Global state
model = None
features = None
# Per-srcip history: {srcip: deque of epoch timestamps}
ip_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
# Per-srcip last 5 inter-arrival times for iat_std
ip_iat_buffer: dict[str, deque] = defaultdict(lambda: deque(maxlen=5))

# Prediction counters
stats = {
    "total": 0, "tp": 0, "fp": 0, "errors": 0, "start_time": None,
    "phishing_total": 0, "phishing_tp": 0, "phishing_fp": 0
}


# ---------------------------------------------------------------------------
# MODELS (Pydantic)
# ---------------------------------------------------------------------------
class AlertInput(BaseModel):
    rule_level: int
    rule_id: str
    srcip: Optional[str] = "unknown"
    timestamp: Optional[str] = None  # ISO format; if None, use server time


class PredictionResponse(BaseModel):
    prediction: int
    label: str
    confidence: float
    features_used: dict
    srcip: str
    rule_id: str


class PhishingInput(BaseModel):
    url: str
    srcip: Optional[str] = "unknown"
    timestamp: Optional[str] = None


class PhishingPredictionResponse(BaseModel):
    prediction: int  # 1 = TP (phishing), 0 = FP (benign)
    label: str       # "TP" or "FP"
    score: float     # Threat score (0.0 to 1.0)
    features: dict
    srcip: str
    url: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    features: list
    uptime_seconds: float
    total_predictions: int
    tp_count: int
    fp_count: int
    phishing_total: int
    phishing_tp: int
    phishing_fp: int


# ---------------------------------------------------------------------------
# STARTUP
# ---------------------------------------------------------------------------
@app.on_event("startup")
def load_model():
    global model, features
    logger.info("Loading model from %s", MODEL_PATH)
    if not MODEL_PATH.exists():
        logger.error("model.pkl not found at %s", MODEL_PATH)
        raise FileNotFoundError(f"model.pkl not found at {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    logger.info("Model loaded: %s", type(model).__name__)

    logger.info("Loading features from %s", FEATURES_PATH)
    if not FEATURES_PATH.exists():
        logger.error("features.json not found at %s", FEATURES_PATH)
        raise FileNotFoundError(f"features.json not found at {FEATURES_PATH}")
    features = json.loads(FEATURES_PATH.read_text())
    logger.info("Features (frozen order): %s", features)

    stats["start_time"] = time.time()
    logger.info("ML API ready.")


# ---------------------------------------------------------------------------
# FEATURE ENGINEERING (identical to training pipeline)
# ---------------------------------------------------------------------------
def compute_features(rule_level: int, srcip: str, alert_epoch: float) -> dict:
    """
    Compute temporal features for a single alert, matching the Colab training
    pipeline exactly:
      - inter_arrival_time: seconds since last alert from same srcip (9999.0 if first)
      - alert_count_10s/30s/60s: count of alerts from same srcip in last 10/30/60s
      - iat_std: std dev of last 5 inter-arrival times (0.0 if < 2 samples)
    """
    history = ip_history[srcip]

    # --- inter_arrival_time ---
    if len(history) == 0:
        iat = 9999.0
    else:
        iat = alert_epoch - history[-1]
        if iat < 0:
            iat = 0.0  # clock skew safety

    # Store IAT in rolling buffer
    ip_iat_buffer[srcip].append(iat if len(history) > 0 else None)

    # --- iat_std (rolling window of 5, matching training's rolling(5).std()) ---
    valid_iats = [x for x in ip_iat_buffer[srcip] if x is not None]
    if len(valid_iats) >= 2:
        iat_std = statistics.stdev(valid_iats)
    else:
        iat_std = 0.0

    # --- alert_count_Xs (count in last X seconds, including current) ---
    # Prune old entries beyond TTL
    cutoff = alert_epoch - HISTORY_TTL
    while history and history[0] < cutoff:
        history.popleft()

    # Add current alert to history
    history.append(alert_epoch)

    count_10 = sum(1 for t in history if alert_epoch - t <= 10.0)
    count_30 = sum(1 for t in history if alert_epoch - t <= 30.0)
    count_60 = sum(1 for t in history if alert_epoch - t <= 60.0)

    return {
        "rule_level": float(rule_level),
        "inter_arrival_time": round(iat, 4),
        "alert_count_10s": float(count_10),
        "alert_count_30s": float(count_30),
        "alert_count_60s": float(count_60),
        "iat_std": round(iat_std, 4),
    }


def parse_timestamp(ts_str: Optional[str]) -> float:
    """Parse ISO timestamp to epoch. Falls back to current time."""
    if not ts_str:
        return time.time()
    try:
        # Handle Wazuh format: 2026-06-21T16:33:05.176+0000
        ts_str = ts_str.replace("+0000", "+00:00").replace("+0700", "+07:00")
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return time.time()


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse)
def health_check():
    uptime = time.time() - stats["start_time"] if stats["start_time"] else 0
    return HealthResponse(
        status="healthy" if model is not None else "model_not_loaded",
        model_loaded=model is not None,
        features=features or [],
        uptime_seconds=round(uptime, 1),
        total_predictions=stats["total"],
        tp_count=stats["tp"],
        fp_count=stats["fp"],
        phishing_total=stats["phishing_total"],
        phishing_tp=stats["phishing_tp"],
        phishing_fp=stats["phishing_fp"],
    )


def evaluate_phishing_url(url: str) -> dict:
    """
    Evaluates a URL using lexical features, presence of suspicious keywords,
    SSL protocol type, and a local whitelist. Returns a threat score and prediction.
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            parsed = urlparse("http://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        domain = url.lower()
        path = ""
        parsed = None

    if ":" in domain:
        domain = domain.split(":")[0]

    whitelist_domains = {
        "google.com", "microsoft.com", "apple.com", "github.com",
        "yahoo.com", "facebook.com", "wikipedia.org", "netflix.com",
        "amazon.com", "google.co.id", "go.id", "ac.id", "co.id"
    }
    
    is_whitelisted = False
    for wd in whitelist_domains:
        if domain == wd or domain.endswith("." + wd):
            is_whitelisted = True
            break
            
    if is_whitelisted:
        return {
            "score": 0.0,
            "prediction": 0,
            "label": "FP",
            "features": {
                "is_whitelisted": True,
                "url_length": len(url),
                "num_dots": domain.count("."),
                "has_hyphen": "-" in domain,
                "has_at": "@" in url,
                "is_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)),
                "suspicious_keywords": 0,
                "uses_http": parsed.scheme == "http" if parsed else True
            }
        }

    url_len = len(url)
    num_dots = domain.count(".")
    has_hyphen = "-" in domain
    has_at = "@" in url
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
    uses_http = parsed.scheme == "http" if parsed else True
    has_double_slash = "//" in path

    keywords = [
        "login", "signin", "verify", "verification", "secure", "update",
        "banking", "paypal", "microsoft", "google", "bank", "account",
        "recover", "webscr", "cmd", "free", "bonus", "confirm", "support"
    ]
    suspicious_kws = [kw for kw in keywords if kw in domain or kw in path]
    num_suspicious_kws = len(suspicious_kws)

    score = 0.0
    
    if is_ip:
        score += 0.35
    if num_dots > 3:
        score += 0.15
    elif num_dots > 2:
        score += 0.07
    if has_hyphen:
        score += 0.20
    if has_at:
        score += 0.30
    if has_double_slash:
        score += 0.20
    if uses_http:
        score += 0.15
    if num_suspicious_kws > 0:
        score += min(0.15 * num_suspicious_kws, 0.40)
    if url_len > 75:
        score += 0.10

    score = min(score, 1.0)
    prediction = 1 if score >= 0.50 else 0
    label = "TP" if prediction == 1 else "FP"

    return {
        "score": round(score, 4),
        "prediction": prediction,
        "label": label,
        "features": {
            "is_whitelisted": False,
            "url_length": url_len,
            "num_dots": num_dots,
            "has_hyphen": has_hyphen,
            "has_at": has_at,
            "is_ip": is_ip,
            "suspicious_keywords": num_suspicious_kws,
            "uses_http": uses_http,
            "found_keywords": suspicious_kws
        }
    }


@app.post("/predict-phishing", response_model=PhishingPredictionResponse)
def predict_phishing(payload: PhishingInput):
    url = payload.url.strip()
    srcip = payload.srcip or "unknown"
    
    result = evaluate_phishing_url(url)
    
    stats["phishing_total"] += 1
    if result["prediction"] == 1:
        stats["phishing_tp"] += 1
    else:
        stats["phishing_fp"] += 1
        
    logger.info(
        "PREDICT_PHISHING srcip=%s url=%s → %s (score=%.4f) | features=%s",
        srcip, url, result["label"], result["score"], result["features"]
    )
    
    return PhishingPredictionResponse(
        prediction=result["prediction"],
        label=result["label"],
        score=result["score"],
        features=result["features"],
        srcip=srcip,
        url=url
    )


@app.post("/predict", response_model=PredictionResponse)
def predict(alert: AlertInput):
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # Parse timestamp
    alert_epoch = parse_timestamp(alert.timestamp)
    srcip = alert.srcip or "unknown"

    # Compute features
    feat = compute_features(alert.rule_level, srcip, alert_epoch)

    # Build feature vector in frozen order
    feature_vector = pd.DataFrame([feat], columns=features)

    # Predict
    try:
        prediction = int(model.predict(feature_vector)[0])
        probas = model.predict_proba(feature_vector)[0]
        confidence = float(probas[prediction])
    except Exception as e:
        stats["errors"] += 1
        logger.error("Prediction error: %s | features=%s", e, feat)
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")

    label = "TP" if prediction == 1 else "FP"

    # Update stats
    stats["total"] += 1
    if prediction == 1:
        stats["tp"] += 1
    else:
        stats["fp"] += 1

    logger.info(
        "PREDICT srcip=%s rule_id=%s → %s (conf=%.3f) | feat=%s",
        srcip, alert.rule_id, label, confidence, feat,
    )

    return PredictionResponse(
        prediction=prediction,
        label=label,
        confidence=round(confidence, 4),
        features_used=feat,
        srcip=srcip,
        rule_id=alert.rule_id,
    )


@app.get("/stats")
def get_stats():
    """Return prediction statistics."""
    uptime = time.time() - stats["start_time"] if stats["start_time"] else 0
    return {
        **stats,
        "uptime_seconds": round(uptime, 1),
        "tracked_ips": len(ip_history),
    }


@app.post("/reset")
def reset_state():
    """Reset IP history and counters (for testing)."""
    ip_history.clear()
    ip_iat_buffer.clear()
    stats.update({"total": 0, "tp": 0, "fp": 0, "errors": 0})
    logger.info("State reset.")
    return {"status": "reset_ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
