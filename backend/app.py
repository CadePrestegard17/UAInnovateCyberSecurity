"""
Risk scoring backend: anomaly per window per IP, trend/acceleration, coordinated escalation forecast.
TensorFlow autoencoder when available (Python 3.9–3.12); else numpy-only distance-from-mean anomaly (no sklearn).
"""
from collections import defaultdict
from typing import Any, Optional

import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

_USE_TF = False
try:
    import tensorflow as tf  # noqa: F401
    _USE_TF = True
except Exception:
    pass

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
WINDOW_MINUTES = 15
WINDOW_MS = WINDOW_MINUTES * 60 * 1000
HISTORY_WINDOWS = 10
TREND_WINDOWS = 5
TREND_THRESHOLD = 0.02
ACCEL_THRESHOLD = 0.02
MIN_IPS_FOR_COORDINATED = 2
FEATURE_DIM = 9

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
event_store: list = []
score_history: list = []
autoencoder = None
feature_mean: Optional[np.ndarray] = None
feature_std: Optional[np.ndarray] = None
max_train_mse: float = 1.0
# Numpy fallback: max L2 distance in standardized space (when TF not installed)
_max_dist: float = 1.0


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------
class PredictRequest(BaseModel):
    events: list[dict[str, Any]]


class AddDataRequest(BaseModel):
    events: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Feature engineering: per (window, IP)
# ---------------------------------------------------------------------------
def _ms_to_window(ts_ms: int) -> int:
    return (ts_ms // WINDOW_MS) * WINDOW_MS


def build_features(events: list) -> list:
    """Returns list of (window_end_ms, ip, feature_vec)."""
    by_window_ip = defaultdict(
        lambda: {
            "count": 0,
            "auth_fail": 0,
            "auth_success": 0,
            "dns": 0,
            "firewall_allow": 0,
            "firewall_block": 0,
            "malware": 0,
            "high_sev": 0,
            "critical_sev": 0,
        }
    )
    for e in events:
        ts = int(e.get("timestamp", 0))
        ip = str(e.get("sourceIp", "") or "").strip() or "-"
        if not ip or ip == "-":
            continue
        win = _ms_to_window(ts)
        key = (win, ip)
        by_window_ip[key]["count"] += 1
        src = (e.get("fileSource") or "").lower()
        sev = (e.get("severity") or "").lower()
        rule = (e.get("rule") or "").lower()
        if "auth" in src:
            if "fail" in rule or sev == "high":
                by_window_ip[key]["auth_fail"] += 1
            else:
                by_window_ip[key]["auth_success"] += 1
        elif "dns" in src:
            by_window_ip[key]["dns"] += 1
        elif "firewall" in src:
            if "block" in rule or "deny" in rule:
                by_window_ip[key]["firewall_block"] += 1
            else:
                by_window_ip[key]["firewall_allow"] += 1
        elif "malware" in src:
            by_window_ip[key]["malware"] += 1
        if sev == "high":
            by_window_ip[key]["high_sev"] += 1
        elif sev == "critical":
            by_window_ip[key]["critical_sev"] += 1

    out = []
    for (win, ip), counts in by_window_ip.items():
        vec = [
            float(counts["count"]),
            float(counts["auth_fail"]),
            float(counts["auth_success"]),
            float(counts["dns"]),
            float(counts["firewall_allow"]),
            float(counts["firewall_block"]),
            float(counts["malware"]),
            float(counts["high_sev"]),
            float(counts["critical_sev"]),
        ]
        out.append((win, ip, vec))
    return out


def get_feature_matrix(rows: list) -> np.ndarray:
    return np.array([r[2] for r in rows], dtype=np.float64)


def normalize(X: np.ndarray) -> np.ndarray:
    global feature_mean, feature_std
    if feature_mean is None or feature_std is None:
        return X
    std_safe = np.where(feature_std > 1e-8, feature_std, 1.0)
    return (X - feature_mean) / std_safe


# ---------------------------------------------------------------------------
# Anomaly model: TensorFlow autoencoder or sklearn Isolation Forest
# ---------------------------------------------------------------------------
def build_autoencoder(input_dim: int = FEATURE_DIM):
    import tensorflow as _tf
    inp = _tf.keras.layers.Input(shape=(input_dim,))
    x = _tf.keras.layers.Dense(6, activation="relu")(inp)
    x = _tf.keras.layers.Dense(3, activation="relu")(x)
    x = _tf.keras.layers.Dense(6, activation="relu")(x)
    out = _tf.keras.layers.Dense(input_dim, activation="linear")(x)
    model = _tf.keras.Model(inp, out)
    model.compile(optimizer="adam", loss="mse")
    return model


def ensure_model(X: np.ndarray) -> None:
    global autoencoder, feature_mean, feature_std, max_train_mse, _max_dist
    if X.shape[0] < 2:
        return
    feature_mean = np.mean(X, axis=0)
    feature_std = np.std(X, axis=0)
    std_safe = np.where(feature_std > 1e-8, feature_std, 1.0)
    X_norm = (X - feature_mean) / std_safe
    if _USE_TF:
        autoencoder = build_autoencoder(X_norm.shape[1])
        autoencoder.fit(X_norm, X_norm, epochs=20, batch_size=min(32, X_norm.shape[0]), verbose=0)
        train_recon = autoencoder.predict(X_norm, verbose=0)
        mse_per_sample = np.mean((X_norm - train_recon) ** 2, axis=1)
        max_train_mse = float(np.max(mse_per_sample)) or 1.0
    else:
        # Numpy-only: L2 distance from mean in standardized space
        dists = np.linalg.norm(X_norm, axis=1)
        _max_dist = float(np.max(dists)) or 1.0


def score_events(events: list) -> tuple[dict[str, float], float]:
    """Returns (scores_per_ip, global_anomaly_score). Higher = more anomalous."""
    rows = build_features(events)
    if not rows:
        return {}, 0.0
    X = get_feature_matrix(rows)
    if (autoencoder is None and not _USE_TF) or (feature_mean is None):
        if X.shape[0] >= 2:
            ensure_model(X)
    if feature_mean is None:
        return {ip: 0.0 for (_, ip, _) in rows}, 0.0

    X_norm = normalize(X)
    if _USE_TF and autoencoder is not None:
        recon = autoencoder.predict(X_norm, verbose=0)
        mse_per_sample = np.mean((X_norm - recon) ** 2, axis=1)
        anomaly_01 = np.clip(mse_per_sample / max_train_mse, 0, 1).astype(np.float64)
    else:
        dists = np.linalg.norm(X_norm, axis=1)
        anomaly_01 = np.clip(dists / _max_dist, 0, 1).astype(np.float64)
    scores_per_ip = {}
    for i, (_, ip, _) in enumerate(rows):
        scores_per_ip[ip] = float(anomaly_01[i])
    global_score = float(np.mean(anomaly_01))
    return scores_per_ip, global_score


# ---------------------------------------------------------------------------
# Trend and acceleration (per IP)
# ---------------------------------------------------------------------------
def get_trend_and_acceleration(scores_per_ip: dict, window_end_ms: int) -> tuple:
    global score_history
    score_history.append({"window_end_ms": window_end_ms, "scores": dict(scores_per_ip)})
    if len(score_history) > HISTORY_WINDOWS:
        score_history = score_history[-HISTORY_WINDOWS:]

    trend_per_ip = {}
    accel_per_ip = {}
    ip_series = defaultdict(list)
    for h in score_history:
        for ip in set(list(h["scores"].keys()) + list(ip_series.keys())):
            ip_series[ip].append(h["scores"].get(ip, 0.0))
    for ip in list(ip_series.keys()):
        series = ip_series[ip][-HISTORY_WINDOWS:]
        if len(series) < 2:
            trend_per_ip[ip] = 0.0
            accel_per_ip[ip] = 0.0
            continue
        use = series[-TREND_WINDOWS:] if len(series) >= TREND_WINDOWS else series
        x = np.arange(len(use), dtype=float)
        slope = np.polyfit(x, use, 1)[0]
        trend_per_ip[ip] = float(slope)
        if len(series) >= 3:
            prev_slope = np.polyfit(np.arange(2), series[-3:-1], 1)[0]
            accel_per_ip[ip] = float(slope - prev_slope)
        else:
            accel_per_ip[ip] = 0.0
    return trend_per_ip, accel_per_ip


def is_coordinated_escalation(trend_per_ip: dict, accel_per_ip: dict) -> bool:
    rising = [
        ip
        for ip in trend_per_ip
        if trend_per_ip[ip] > TREND_THRESHOLD and accel_per_ip.get(ip, 0) > ACCEL_THRESHOLD
    ]
    return len(rising) >= MIN_IPS_FOR_COORDINATED


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
MIN_FEATURE_ROWS_FOR_PREDICT = 5  # Fewer (window, IP) rows → score is unreliable and tends to 100%

@app.post("/predict")
def predict(req: PredictRequest) -> dict:
    events = req.events
    if not events:
        return {
            "anomalyScore": 0.0,
            "message": "No events to score.",
            "coordinatedEscalation": False,
            "trendSummary": "",
        }
    rows = build_features(events)
    if len(rows) < MIN_FEATURE_ROWS_FOR_PREDICT:
        return {
            "anomalyScore": 0.0,
            "message": "Insufficient data in this window. Widen the time range for a meaningful score.",
            "coordinatedEscalation": False,
            "trendSummary": "",
        }
    scores_per_ip, global_score = score_events(events)
    ts_list = [int(e.get("timestamp", 0)) for e in events]
    window_end = _ms_to_window(max(ts_list)) if ts_list else 0
    trend_per_ip, accel_per_ip = get_trend_and_acceleration(scores_per_ip, window_end)
    coordinated = is_coordinated_escalation(trend_per_ip, accel_per_ip)

    rising_ips = [
        ip
        for ip in trend_per_ip
        if trend_per_ip[ip] > TREND_THRESHOLD and accel_per_ip.get(ip, 0) > ACCEL_THRESHOLD
    ]
    trend_summary = f"{len(rising_ips)} IP(s) trending up" if rising_ips else "Normal"
    if coordinated:
        message = f"High likelihood of coordinated escalation in the next {WINDOW_MINUTES} minutes."
    else:
        message = "Normal" if global_score < 0.5 else "Elevated — unusual activity in the last window."

    return {
        "anomalyScore": round(global_score, 3),
        "message": message,
        "coordinatedEscalation": coordinated,
        "trendSummary": trend_summary,
    }


@app.post("/add-data")
def add_data(req: AddDataRequest) -> dict:
    global event_store
    event_store.extend(req.events)
    rows = build_features(event_store)
    if len(rows) >= 2:
        X = get_feature_matrix(rows)
        ensure_model(X)
    return {"status": "ok", "eventCount": len(event_store)}


@app.get("/")
def root() -> dict:
    return {"service": "UA Innovate Risk API", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
