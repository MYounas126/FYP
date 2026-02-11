"""
SentinelFlow - Development Server with Real ML Models

Uses trained XGBoost classifier for attack detection with 8 MITRE ATT&CK categories.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, List, Optional
from datetime import datetime
from pathlib import Path
import random
import numpy as np

from fastapi import FastAPI, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel
import asyncio

# ML Model loading
import joblib
import warnings
warnings.filterwarnings('ignore')

# Simple in-memory storage for demo
demo_alerts = []
demo_traffic = []

# ML Models (loaded at startup)
ml_models = {
    "classifier": None,
    "scaler": None,
    "attack_labels": None,
    "loaded": False
}

# MITRE ATT&CK categories from trained model
ATTACK_CATEGORIES = [
    "Credential Access",
    "Defense Evasion",
    "Exfiltration",
    "Initial Access",
    "Persistence",
    "Privilege Escalation",
    "Reconnaissance",
    "none"
]

SEVERITY_MAP = {
    "Credential Access": "critical",
    "Defense Evasion": "high",
    "Exfiltration": "critical",
    "Initial Access": "critical",
    "Persistence": "high",
    "Privilege Escalation": "critical",
    "Reconnaissance": "medium",
    "none": "low"
}

MITRE_TECHNIQUES = {
    "Credential Access": {"id": "T1110", "name": "Brute Force"},
    "Defense Evasion": {"id": "T1070", "name": "Indicator Removal"},
    "Exfiltration": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "Initial Access": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "Persistence": {"id": "T1078", "name": "Valid Accounts"},
    "Privilege Escalation": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "Reconnaissance": {"id": "T1595", "name": "Active Scanning"},
    "none": {"id": "N/A", "name": "Benign Traffic"}
}


def load_ml_models():
    """Load trained ML models from disk."""
    global ml_models

    # Try multiple paths for model directory
    possible_paths = [
        Path(__file__).parent.parent.parent.parent / "ml" / "models",
        Path("/home/ml-siem/Downloads/FYP/SentinelFlow/ml/models"),
        Path("../ml/models"),
    ]

    model_path = None
    for p in possible_paths:
        if p.exists() and (p / "classifier.joblib").exists():
            model_path = p
            break

    if not model_path:
        print("⚠️  ML models not found, using demo mode")
        return False

    try:
        ml_models["classifier"] = joblib.load(model_path / "classifier.joblib")
        ml_models["scaler"] = joblib.load(model_path / "scaler_classifier.joblib")
        ml_models["attack_labels"] = joblib.load(model_path / "attack_labels.joblib")
        ml_models["loaded"] = True
        print(f"✅ ML models loaded from {model_path}")
        print(f"   Classes: {list(ml_models['attack_labels'].values())}")
        return True
    except Exception as e:
        print(f"⚠️  Error loading ML models: {e}")
        return False


def predict_attack(traffic_data: dict) -> dict:
    """Run ML prediction on traffic data."""
    if not ml_models["loaded"]:
        # Fallback to random for demo
        category = random.choice(ATTACK_CATEGORIES)
        return {
            "attack_category": category,
            "confidence": random.uniform(0.7, 0.99),
            "mitre_technique": MITRE_TECHNIQUES.get(category, {}),
            "is_attack": category != "none"
        }

    # Extract features in order expected by model
    features = np.array([[
        traffic_data.get("packets_sent", 0),      # orig_pkts
        traffic_data.get("packets_received", 0),  # resp_pkts
        traffic_data.get("bytes_sent", 0),        # orig_bytes
        traffic_data.get("bytes_received", 0),    # resp_bytes
        traffic_data.get("bytes_sent", 0) + 40,   # orig_ip_bytes (approx)
        traffic_data.get("bytes_received", 0) + 40,  # resp_ip_bytes
        traffic_data.get("duration", 0.1),        # duration
        0,                                         # missed_bytes
        traffic_data.get("dst_port", 80),         # dest_port
        traffic_data.get("src_port", 50000),      # src_port
    ]])

    features = np.nan_to_num(features, nan=0, posinf=0, neginf=0)
    features_scaled = ml_models["scaler"].transform(features)

    prediction = ml_models["classifier"].predict(features_scaled)[0]
    probabilities = ml_models["classifier"].predict_proba(features_scaled)[0]

    category = ml_models["attack_labels"][prediction]
    confidence = float(max(probabilities))

    return {
        "attack_category": category,
        "confidence": confidence,
        "mitre_technique": MITRE_TECHNIQUES.get(category, {}),
        "is_attack": category != "none"
    }


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan - load ML models and generate demo data."""
    print("🚀 SentinelFlow Development Server Starting...")

    # Load ML models
    if load_ml_models():
        print("📊 Running with REAL ML models (8 MITRE ATT&CK categories)")
    else:
        print("📊 Running in demo mode (no ML models)")

    # Generate demo data using ML predictions
    generate_demo_data()

    print("✅ Server ready!")
    yield
    print("👋 Server shutting down...")


def generate_demo_data():
    """Generate demo data using real ML predictions."""
    global demo_alerts, demo_traffic

    demo_alerts = []
    demo_traffic = []

    # Attack simulation profiles for realistic traffic
    attack_profiles = {
        "Credential Access": {"dst_port": [22, 3389, 21], "pkts": (100, 500), "bytes": (5000, 20000)},
        "Reconnaissance": {"dst_port": [80, 443, 22, 445], "pkts": (1, 10), "bytes": (40, 500)},
        "Initial Access": {"dst_port": [80, 443, 8080], "pkts": (50, 300), "bytes": (10000, 50000)},
        "Exfiltration": {"dst_port": [443, 53, 8443], "pkts": (500, 2000), "bytes": (100000, 500000)},
        "Benign": {"dst_port": [80, 443, 53], "pkts": (10, 100), "bytes": (1000, 50000)},
    }

    # Generate 50 traffic records with ML predictions
    protocols = ["TCP", "UDP", "ICMP"]
    alert_id = 0

    for i in range(50):
        # Pick attack type (30% benign, 70% attacks)
        if random.random() < 0.3:
            profile_name = "Benign"
        else:
            profile_name = random.choice(list(attack_profiles.keys())[:-1])

        profile = attack_profiles[profile_name]

        traffic = {
            "id": i + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "dst_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice(profile["dst_port"]),
            "protocol": random.choice(protocols),
            "bytes_sent": random.randint(*profile["bytes"]),
            "bytes_received": random.randint(profile["bytes"][0]//2, profile["bytes"][1]//2),
            "packets_sent": random.randint(*profile["pkts"]),
            "packets_received": random.randint(profile["pkts"][0]//2, profile["pkts"][1]//2),
            "duration": round(random.uniform(0.1, 30), 3),
        }

        # Run ML prediction
        prediction = predict_attack(traffic)

        traffic["is_anomaly"] = prediction["is_attack"]
        traffic["anomaly_score"] = round(prediction["confidence"], 2) if prediction["is_attack"] else round(random.uniform(0, 0.3), 2)
        traffic["attack_category"] = prediction["attack_category"] if prediction["is_attack"] else None
        traffic["mitre_technique"] = prediction["mitre_technique"] if prediction["is_attack"] else None

        demo_traffic.append(traffic)

        # Create alert for attacks
        if prediction["is_attack"] and prediction["confidence"] > 0.5:
            alert_id += 1
            demo_alerts.append({
                "id": f"alert-{alert_id}",
                "timestamp": traffic["timestamp"],
                "severity": SEVERITY_MAP.get(prediction["attack_category"], "medium"),
                "title": f"{prediction['attack_category']} Attack Detected",
                "description": f"MITRE ATT&CK: {prediction['mitre_technique'].get('id', 'N/A')} - {prediction['mitre_technique'].get('name', 'Unknown')}",
                "src_ip": traffic["src_ip"],
                "dst_ip": traffic["dst_ip"],
                "dst_port": traffic["dst_port"],
                "attack_category": prediction["attack_category"],
                "mitre_tactic": prediction["attack_category"],
                "mitre_technique": prediction["mitre_technique"].get("id", "N/A"),
                "status": "new",
                "anomaly_score": traffic["anomaly_score"],
                "confidence": round(prediction["confidence"], 2),
            })


app = FastAPI(
    title="SentinelFlow",
    description="ML-Powered Network Intrusion Detection System (Dev Mode)",
    version="0.1.0-dev",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Auth Schemas & Endpoints
# =============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: str
    role: str
    is_active: bool


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(form_data: LoginRequest):
    """Demo login - accepts admin/admin123."""
    if form_data.username == "admin" and form_data.password == "admin123":
        return TokenResponse(
            access_token="demo-access-token-12345",
            refresh_token="demo-refresh-token-67890",
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password"
    )


@app.get("/api/v1/auth/me", response_model=UserResponse)
async def get_me():
    """Get current user (demo)."""
    return UserResponse(
        id="user-1",
        email="admin@sentinelflow.local",
        username="admin",
        full_name="System Administrator",
        role="admin",
        is_active=True
    )


# =============================================================================
# Dashboard Endpoints
# =============================================================================

@app.get("/api/v1/dashboard/overview")
async def dashboard_overview():
    """Dashboard overview with demo data."""
    anomaly_count = len([t for t in demo_traffic if t["is_anomaly"]])

    return {
        "traffic": {
            "total_flows_24h": len(demo_traffic),
            "total_bytes_24h": sum(t["bytes_sent"] + t["bytes_received"] for t in demo_traffic),
            "anomalies_24h": anomaly_count,
            "flows_last_hour": len(demo_traffic) // 2,
            "anomaly_rate": round(anomaly_count / len(demo_traffic) * 100, 2)
        },
        "alerts": {
            "total_24h": len(demo_alerts),
            "critical": len([a for a in demo_alerts if a["severity"] == "critical"]),
            "high": len([a for a in demo_alerts if a["severity"] == "high"]),
            "medium": len([a for a in demo_alerts if a["severity"] == "medium"]),
            "low": len([a for a in demo_alerts if a["severity"] == "low"]),
            "unresolved": len([a for a in demo_alerts if a["status"] == "new"])
        },
        "recent_alerts": demo_alerts[:5],
        "system": {
            "status": "healthy",
            "last_updated": datetime.utcnow().isoformat()
        }
    }


@app.get("/api/v1/dashboard/timeline")
async def dashboard_timeline(hours: int = 24):
    """Timeline data for charts."""
    # Generate hourly data
    traffic_data = []
    alert_data = []

    for i in range(hours):
        traffic_data.append({
            "timestamp": datetime.utcnow().isoformat(),
            "flows": random.randint(50, 200),
            "bytes": random.randint(100000, 1000000),
            "anomalies": random.randint(0, 10)
        })
        alert_data.append({
            "timestamp": datetime.utcnow().isoformat(),
            "critical": random.randint(0, 2),
            "high": random.randint(0, 5),
            "medium": random.randint(0, 10),
            "low": random.randint(0, 15)
        })

    return {"traffic": traffic_data, "alerts": alert_data}


@app.get("/api/v1/dashboard/attack-distribution")
async def attack_distribution():
    """Attack category distribution."""
    categories = {}
    for alert in demo_alerts:
        cat = alert.get("attack_category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1

    return [{"category": k, "count": v} for k, v in categories.items()]


# =============================================================================
# Traffic Endpoints
# =============================================================================

@app.get("/api/v1/traffic")
async def list_traffic(is_anomaly: bool = None, limit: int = 100):
    """List traffic records."""
    result = demo_traffic
    if is_anomaly is not None:
        result = [t for t in demo_traffic if t["is_anomaly"] == is_anomaly]
    return result[:limit]


@app.get("/api/v1/traffic/stats")
async def traffic_stats():
    """Traffic statistics."""
    anomaly_count = len([t for t in demo_traffic if t["is_anomaly"]])
    return {
        "total_flows": len(demo_traffic),
        "total_bytes": sum(t["bytes_sent"] + t["bytes_received"] for t in demo_traffic),
        "total_packets": sum(t["packets_sent"] + t["packets_received"] for t in demo_traffic),
        "anomaly_count": anomaly_count,
        "anomaly_percentage": round(anomaly_count / len(demo_traffic) * 100, 2),
        "top_sources": [],
        "top_destinations": [],
        "protocol_distribution": {"TCP": 30, "UDP": 15, "ICMP": 5},
        "attack_categories": {},
        "time_range": {"start": datetime.utcnow().isoformat(), "end": datetime.utcnow().isoformat()}
    }


@app.get("/api/v1/traffic/anomalies")
async def traffic_anomalies(limit: int = 100):
    """List anomalous traffic."""
    return [t for t in demo_traffic if t["is_anomaly"]][:limit]


# =============================================================================
# Alerts Endpoints
# =============================================================================

@app.get("/api/v1/alerts")
async def list_alerts(severity: str = None, status: str = None, limit: int = 100):
    """List alerts with optional filters."""
    result = demo_alerts
    if severity:
        result = [a for a in result if a["severity"] == severity]
    if status:
        result = [a for a in result if a["status"] == status]
    return result[:limit]


@app.get("/api/v1/alerts/stats")
async def alert_stats():
    """Alert statistics."""
    return {
        "total_alerts": len(demo_alerts),
        "new_alerts": len([a for a in demo_alerts if a["status"] == "new"]),
        "investigating_alerts": 0,
        "resolved_alerts": 0,
        "false_positives": 0,
        "severity_distribution": {
            "critical": len([a for a in demo_alerts if a["severity"] == "critical"]),
            "high": len([a for a in demo_alerts if a["severity"] == "high"]),
            "medium": len([a for a in demo_alerts if a["severity"] == "medium"]),
            "low": len([a for a in demo_alerts if a["severity"] == "low"]),
        },
        "category_distribution": {},
        "hourly_trend": []
    }


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get single alert."""
    for alert in demo_alerts:
        if alert["id"] == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


# =============================================================================
# WebSocket Endpoint (Demo)
# =============================================================================

@app.websocket("/api/v1/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates (demo)."""
    await websocket.accept()

    # Send initial connection message
    await websocket.send_json({"type": "connection", "status": "connected"})

    try:
        while True:
            # Send periodic heartbeat
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "timestamp": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        pass


# =============================================================================
# ML Prediction Endpoints
# =============================================================================

class TrafficInput(BaseModel):
    src_ip: str = "192.168.1.100"
    dst_ip: str = "10.0.0.1"
    src_port: int = 50000
    dst_port: int = 80
    protocol: str = "TCP"
    bytes_sent: int = 1000
    bytes_received: int = 500
    packets_sent: int = 10
    packets_received: int = 5
    duration: float = 1.0


@app.post("/api/v1/ml/predict")
async def ml_predict(traffic: TrafficInput):
    """Run ML prediction on traffic data."""
    traffic_dict = traffic.model_dump()
    prediction = predict_attack(traffic_dict)

    return {
        "input": traffic_dict,
        "prediction": prediction,
        "model_loaded": ml_models["loaded"],
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/ml/status")
async def ml_status():
    """Get ML model status."""
    return {
        "loaded": ml_models["loaded"],
        "model_type": "XGBoost Classifier" if ml_models["loaded"] else "Demo Mode",
        "classes": list(ml_models["attack_labels"].values()) if ml_models["loaded"] else ATTACK_CATEGORIES,
        "mitre_techniques": MITRE_TECHNIQUES
    }


@app.post("/api/v1/ml/simulate-attack")
async def simulate_attack(attack_type: str = "random", count: int = 5):
    """Simulate attack traffic and run ML detection."""
    global demo_alerts, demo_traffic

    attack_profiles = {
        "credential_access": {"dst_port": [22, 3389, 21], "pkts": (100, 500), "bytes": (5000, 20000)},
        "reconnaissance": {"dst_port": [80, 443, 22, 445], "pkts": (1, 10), "bytes": (40, 500)},
        "initial_access": {"dst_port": [80, 443, 8080], "pkts": (50, 300), "bytes": (10000, 50000)},
        "exfiltration": {"dst_port": [443, 53, 8443], "pkts": (500, 2000), "bytes": (100000, 500000)},
        "benign": {"dst_port": [80, 443, 53], "pkts": (10, 100), "bytes": (1000, 50000)},
    }

    if attack_type == "random":
        attack_type = random.choice(list(attack_profiles.keys()))

    if attack_type not in attack_profiles:
        raise HTTPException(status_code=400, detail=f"Unknown attack type. Choose from: {list(attack_profiles.keys())}")

    profile = attack_profiles[attack_type]
    results = []

    for i in range(min(count, 20)):  # Limit to 20
        traffic = {
            "id": len(demo_traffic) + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "dst_ip": f"10.0.{random.randint(1, 5)}.{random.randint(1, 254)}",
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice(profile["dst_port"]),
            "protocol": "TCP",
            "bytes_sent": random.randint(*profile["bytes"]),
            "bytes_received": random.randint(profile["bytes"][0]//2, profile["bytes"][1]//2),
            "packets_sent": random.randint(*profile["pkts"]),
            "packets_received": random.randint(profile["pkts"][0]//2, profile["pkts"][1]//2),
            "duration": round(random.uniform(0.1, 30), 3),
        }

        # Run ML prediction
        prediction = predict_attack(traffic)

        traffic["is_anomaly"] = prediction["is_attack"]
        traffic["anomaly_score"] = round(prediction["confidence"], 2)
        traffic["attack_category"] = prediction["attack_category"]
        traffic["mitre_technique"] = prediction["mitre_technique"]

        demo_traffic.append(traffic)

        # Create alert
        if prediction["is_attack"] and prediction["confidence"] > 0.5:
            alert = {
                "id": f"alert-{len(demo_alerts) + 1}",
                "timestamp": traffic["timestamp"],
                "severity": SEVERITY_MAP.get(prediction["attack_category"], "medium"),
                "title": f"{prediction['attack_category']} Attack Detected",
                "description": f"MITRE ATT&CK: {prediction['mitre_technique'].get('id', 'N/A')} - {prediction['mitre_technique'].get('name', 'Unknown')}",
                "src_ip": traffic["src_ip"],
                "dst_ip": traffic["dst_ip"],
                "dst_port": traffic["dst_port"],
                "attack_category": prediction["attack_category"],
                "mitre_tactic": prediction["attack_category"],
                "mitre_technique": prediction["mitre_technique"].get("id", "N/A"),
                "status": "new",
                "anomaly_score": traffic["anomaly_score"],
                "confidence": round(prediction["confidence"], 2),
            }
            demo_alerts.insert(0, alert)

        results.append({
            "traffic": traffic,
            "prediction": prediction
        })

    return {
        "attack_type_simulated": attack_type,
        "count": len(results),
        "results": results,
        "total_alerts": len(demo_alerts),
        "total_traffic": len(demo_traffic)
    }


# =============================================================================
# Real-Time Network Monitoring Endpoints
# =============================================================================

from app.services.network_capture import capture_service, NetworkFlow

# Store for WebSocket connections
active_websockets: List[WebSocket] = []


class MonitoringConfig(BaseModel):
    interface: str
    duration: int = 60  # seconds
    target_ip: Optional[str] = None


@app.get("/api/v1/monitor/interfaces")
async def get_interfaces():
    """Get available network interfaces for monitoring."""
    interfaces = capture_service.get_available_interfaces()
    return {
        "interfaces": interfaces,
        "note": "Use 'any' to capture on all interfaces. Requires sudo/root for actual capture."
    }


@app.post("/api/v1/monitor/start")
async def start_monitoring(config: MonitoringConfig):
    """Start real-time network monitoring."""
    global demo_alerts, demo_traffic

    def on_flow_update(flow: NetworkFlow):
        """Callback when flow is updated - run ML prediction."""
        flow_dict = flow.to_dict()
        ml_features = flow.get_ml_features()

        # Run ML prediction
        prediction = predict_attack(ml_features)

        flow_dict["is_anomaly"] = prediction["is_attack"]
        flow_dict["attack_category"] = prediction["attack_category"]
        flow_dict["confidence"] = prediction["confidence"]
        flow_dict["mitre_technique"] = prediction["mitre_technique"]

        # Add to traffic list
        flow_dict["id"] = len(demo_traffic) + 1
        demo_traffic.append(flow_dict)

        # Create alert if attack detected
        if prediction["is_attack"] and prediction["confidence"] > 0.5:
            alert = {
                "id": f"alert-{len(demo_alerts) + 1}",
                "timestamp": flow_dict["timestamp"],
                "severity": SEVERITY_MAP.get(prediction["attack_category"], "medium"),
                "title": f"{prediction['attack_category']} Attack Detected",
                "description": f"MITRE ATT&CK: {prediction['mitre_technique'].get('id', 'N/A')} - {prediction['mitre_technique'].get('name', 'Unknown')}",
                "src_ip": flow_dict["src_ip"],
                "dst_ip": flow_dict["dst_ip"],
                "dst_port": flow_dict["dst_port"],
                "attack_category": prediction["attack_category"],
                "mitre_tactic": prediction["attack_category"],
                "mitre_technique": prediction["mitre_technique"].get("id", "N/A"),
                "status": "new",
                "anomaly_score": round(prediction["confidence"], 2),
                "confidence": round(prediction["confidence"], 2),
                "is_real_traffic": True  # Flag to indicate this is from real capture
            }
            demo_alerts.insert(0, alert)

            # Broadcast alert to WebSocket clients
            asyncio.create_task(broadcast_alert(alert))

        # Broadcast flow to WebSocket clients
        asyncio.create_task(broadcast_flow(flow_dict))

    result = capture_service.start_capture(
        interface=config.interface,
        duration=config.duration,
        target_ip=config.target_ip,
        on_flow=on_flow_update
    )

    return result


@app.post("/api/v1/monitor/stop")
async def stop_monitoring():
    """Stop active network monitoring."""
    result = capture_service.stop_capture()
    return result


@app.get("/api/v1/monitor/status")
async def get_monitoring_status():
    """Get current monitoring status."""
    status = capture_service.get_status()

    # Add recent traffic stats
    recent_traffic = demo_traffic[-20:] if demo_traffic else []
    recent_alerts = demo_alerts[:10] if demo_alerts else []

    attacks_detected = len([t for t in demo_traffic if t.get("is_anomaly") and t.get("is_real_traffic")])

    return {
        **status,
        "recent_traffic_count": len(recent_traffic),
        "total_alerts": len(demo_alerts),
        "attacks_detected": attacks_detected,
        "recent_alerts": recent_alerts[:5]
    }


@app.get("/api/v1/monitor/flows")
async def get_captured_flows(limit: int = 100):
    """Get captured network flows."""
    flows = capture_service.get_flows()
    return flows[:limit]


async def broadcast_alert(alert: dict):
    """Broadcast alert to all connected WebSocket clients."""
    message = {"type": "alert", "data": alert}
    for ws in active_websockets:
        try:
            await ws.send_json(message)
        except:
            pass


async def broadcast_flow(flow: dict):
    """Broadcast flow update to all connected WebSocket clients."""
    message = {"type": "flow", "data": flow}
    for ws in active_websockets:
        try:
            await ws.send_json(message)
        except:
            pass


# Enhanced WebSocket endpoint for real-time monitoring
@app.websocket("/api/v1/ws/monitor")
async def websocket_monitor(websocket: WebSocket):
    """WebSocket endpoint for real-time monitoring updates."""
    await websocket.accept()
    active_websockets.append(websocket)

    # Send initial status
    await websocket.send_json({
        "type": "connection",
        "status": "connected",
        "monitoring_active": capture_service.is_capturing
    })

    try:
        while True:
            # Send periodic status updates
            await asyncio.sleep(2)

            status = capture_service.get_status()
            await websocket.send_json({
                "type": "status",
                "data": status
            })

            # Check if monitoring has stopped
            if not capture_service.is_capturing and status["packets_captured"] > 0:
                await websocket.send_json({
                    "type": "monitoring_complete",
                    "data": {
                        "packets_captured": status["packets_captured"],
                        "flows_detected": status["flows_detected"],
                        "alerts_generated": len([a for a in demo_alerts if a.get("is_real_traffic")])
                    }
                })

    except WebSocketDisconnect:
        active_websockets.remove(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        if websocket in active_websockets:
            active_websockets.remove(websocket)


# =============================================================================
# Health & Info
# =============================================================================

@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "mode": "development",
        "version": "0.1.0-dev",
        "ml_models_loaded": ml_models["loaded"],
        "monitoring_active": capture_service.is_capturing
    }


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "SentinelFlow",
        "version": "0.1.0-dev",
        "mode": "development",
        "docs": "/docs",
        "health": "/health",
        "monitoring": "/api/v1/monitor/status"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
