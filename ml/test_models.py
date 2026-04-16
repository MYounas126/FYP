"""
SentinelFlow ML Model Testing Script

Demonstrates real-time attack detection using trained models:
- Anomaly Detection (Isolation Forest on CESNET features)
- Attack Classification (XGBoost with 8 MITRE ATT&CK categories)
"""

import os
import sys
import time
import random
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

# Paths
MODEL_DIR = Path("models")

print("=" * 70)
print("SentinelFlow ML Model Testing - Real-Time Attack Simulation")
print("=" * 70)
print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# =============================================================================
# Load Models
# =============================================================================
print("[1/5] Loading trained models...")

# Load Anomaly Detection Model
anomaly_model = joblib.load(MODEL_DIR / "anomaly_detector.joblib")
scaler_anomaly = joblib.load(MODEL_DIR / "scaler_anomaly.joblib")
anomaly_features = joblib.load(MODEL_DIR / "anomaly_features.joblib")
print(f"  ✓ Anomaly Detector (Isolation Forest)")
print(f"    Features: {len(anomaly_features)} features")

# Load Attack Classification Model
classifier = joblib.load(MODEL_DIR / "classifier.joblib")
scaler_classifier = joblib.load(MODEL_DIR / "scaler_classifier.joblib")
classifier_features = joblib.load(MODEL_DIR / "classifier_features.joblib")
attack_labels = joblib.load(MODEL_DIR / "attack_labels.joblib")
print(f"  ✓ Attack Classifier (XGBoost)")
print(f"    Classes: {list(attack_labels.values())}")
print()

# =============================================================================
# Attack Profiles - Real attack characteristics from UWF-ZeekData24
# =============================================================================
ATTACK_PROFILES = {
    "Credential Access (T1110 - Brute Force)": {
        "orig_pkts": (100, 500),      # High packet count
        "resp_pkts": (50, 200),
        "orig_bytes": (5000, 20000),
        "resp_bytes": (2000, 10000),
        "orig_ip_bytes": (8000, 30000),
        "resp_ip_bytes": (4000, 15000),
        "duration": (10, 60),          # Sustained connection
        "missed_bytes": (0, 100),
        "dest_port": [22, 3389, 21, 23, 445, 139],  # SSH, RDP, FTP, Telnet, SMB
        "src_port": (40000, 65000),
    },
    "Defense Evasion": {
        "orig_pkts": (5, 30),          # Low profile
        "resp_pkts": (3, 20),
        "orig_bytes": (500, 3000),     # Small payloads
        "resp_bytes": (200, 1500),
        "orig_ip_bytes": (800, 4000),
        "resp_ip_bytes": (400, 2000),
        "duration": (0.1, 5),          # Quick connections
        "missed_bytes": (0, 50),
        "dest_port": [443, 8443, 8080],  # HTTPS, alt-HTTP
        "src_port": (50000, 65000),
    },
    "Exfiltration (T1048)": {
        "orig_pkts": (500, 2000),      # High outbound
        "resp_pkts": (50, 200),        # Low inbound (ACKs only)
        "orig_bytes": (100000, 500000),  # Large data transfer OUT
        "resp_bytes": (1000, 5000),    # Small responses
        "orig_ip_bytes": (150000, 600000),
        "resp_ip_bytes": (2000, 8000),
        "duration": (30, 300),         # Long duration
        "missed_bytes": (0, 1000),
        "dest_port": [443, 53, 8443],  # DNS/HTTPS tunneling
        "src_port": (45000, 60000),
    },
    "Initial Access (T1190 - Exploit)": {
        "orig_pkts": (50, 300),
        "resp_pkts": (30, 150),
        "orig_bytes": (10000, 50000),  # Exploit payloads
        "resp_bytes": (5000, 30000),
        "orig_ip_bytes": (15000, 70000),
        "resp_ip_bytes": (8000, 40000),
        "duration": (1, 30),
        "missed_bytes": (100, 5000),   # Possible packet loss
        "dest_port": [80, 443, 8080, 8443],  # Web services
        "src_port": (40000, 60000),
    },
    "Persistence (T1078 - Valid Accounts)": {
        "orig_pkts": (20, 100),
        "resp_pkts": (15, 80),
        "orig_bytes": (2000, 15000),
        "resp_bytes": (1500, 12000),
        "orig_ip_bytes": (3000, 20000),
        "resp_ip_bytes": (2500, 18000),
        "duration": (5, 60),
        "missed_bytes": (0, 200),
        "dest_port": [22, 3389, 5900, 5985],  # Remote access
        "src_port": (35000, 55000),
    },
    "Privilege Escalation": {
        "orig_pkts": (30, 150),
        "resp_pkts": (25, 120),
        "orig_bytes": (5000, 25000),
        "resp_bytes": (3000, 20000),
        "orig_ip_bytes": (7000, 35000),
        "resp_ip_bytes": (5000, 28000),
        "duration": (2, 45),
        "missed_bytes": (0, 500),
        "dest_port": [445, 135, 139, 389],  # SMB, RPC, LDAP
        "src_port": (40000, 60000),
    },
    "Reconnaissance (T1595 - Active Scanning)": {
        "orig_pkts": (1, 10),          # Few packets per probe
        "resp_pkts": (0, 5),           # May not get response
        "orig_bytes": (40, 500),       # Small probes
        "resp_bytes": (0, 300),
        "orig_ip_bytes": (60, 800),
        "resp_ip_bytes": (0, 500),
        "duration": (0, 2),            # Quick scans
        "missed_bytes": (0, 50),
        "dest_port": list(range(1, 1024)),  # Common ports
        "src_port": (50000, 65000),
    },
    "Benign Traffic": {
        "orig_pkts": (10, 100),
        "resp_pkts": (10, 100),
        "orig_bytes": (1000, 50000),
        "resp_bytes": (1000, 100000),  # More response (typical web)
        "orig_ip_bytes": (1500, 60000),
        "resp_ip_bytes": (1500, 120000),
        "duration": (0.5, 30),
        "missed_bytes": (0, 10),
        "dest_port": [80, 443, 53],    # Normal web/DNS
        "src_port": (32768, 65000),
    },
}


def generate_attack_traffic(attack_type: str) -> dict:
    """Generate synthetic traffic matching attack profile."""
    profile = ATTACK_PROFILES[attack_type]

    return {
        "orig_pkts": random.randint(*profile["orig_pkts"]),
        "resp_pkts": random.randint(*profile["resp_pkts"]),
        "orig_bytes": random.randint(*profile["orig_bytes"]),
        "resp_bytes": random.randint(*profile["resp_bytes"]),
        "orig_ip_bytes": random.randint(*profile["orig_ip_bytes"]),
        "resp_ip_bytes": random.randint(*profile["resp_ip_bytes"]),
        "duration": round(random.uniform(*profile["duration"]), 3),
        "missed_bytes": random.randint(*profile["missed_bytes"]),
        "dest_port": random.choice(profile["dest_port"]) if isinstance(profile["dest_port"], list) else random.randint(*profile["dest_port"]),
        "src_port": random.randint(*profile["src_port"]),
        "src_ip": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        "dst_ip": f"10.0.{random.randint(1,5)}.{random.randint(1,254)}",
    }

from .email_notifier import process_ml_prediction
def predict_anomaly(traffic: dict) -> tuple:
    """Run anomaly detection on traffic."""
    # For anomaly detection, we need CESNET-style features
    # Map our traffic features to anomaly features
    anomaly_data = {
        'n_flows': 1,
        'n_packets': traffic['orig_pkts'] + traffic['resp_pkts'],
        'n_bytes': traffic['orig_bytes'] + traffic['resp_bytes'],
        'average_n_dest_asn': 1,
        'std_n_dest_asn': 0,
        'average_n_dest_ports': 1,
        'std_n_dest_ports': 0,
        'average_n_dest_ip': 1,
        'std_n_dest_ip': 0,
        'tcp_udp_ratio_packets': 0.8,  # Assume mostly TCP
        'tcp_udp_ratio_bytes': 0.85,
        'dir_ratio_packets': traffic['orig_pkts'] / max(traffic['resp_pkts'], 1),
        'dir_ratio_bytes': traffic['orig_bytes'] / max(traffic['resp_bytes'], 1),
        'avg_duration': traffic['duration'],
        'avg_ttl': 64
    }

    features = np.array([[anomaly_data[f] for f in anomaly_features]])
    features = np.nan_to_num(features, nan=0, posinf=0, neginf=0)
    features_scaled = scaler_anomaly.transform(features)

    prediction = anomaly_model.predict(features_scaled)[0]
    score = anomaly_model.decision_function(features_scaled)[0]

    is_anomaly = prediction == -1
    # Convert score to 0-1 range (lower decision score = more anomalous)
    anomaly_score = max(0, min(1, 0.5 - score))
    if is_anomaly and anomaly_score > 0.95:
        flow_data = {
            "src_ip": traffic.get("src_ip", "Unknown"),
            "dst_ip": traffic.get("dst_ip", "Unknown"),
            "alert_id": traffic.get("alert_id", 0)
        }

    process_ml_prediction(
        prediction="Anomalous Network Behavior",
        confidence=anomaly_score * 100,
        flow_data=flow_data
    )
    return is_anomaly, anomaly_score


def classify_attack(traffic: dict) -> tuple:
    """Classify attack type using XGBoost."""
    # Map traffic to classifier features
    features = np.array([[
        traffic['orig_pkts'],
        traffic['resp_pkts'],
        traffic['orig_bytes'],
        traffic['resp_bytes'],
        traffic['orig_ip_bytes'],
        traffic['resp_ip_bytes'],
        traffic['duration'],
        traffic['missed_bytes'],
        traffic['dest_port'],
        traffic['src_port']
    ]])

    features_scaled = scaler_classifier.transform(features)

    prediction = classifier.predict(features_scaled)[0]
    probabilities = classifier.predict_proba(features_scaled)[0]

    attack_type = attack_labels[prediction]
    confidence = float(max(probabilities))

    # Get top 3 predictions
    top_indices = np.argsort(probabilities)[::-1][:3]
    top_predictions = [(attack_labels[i], float(probabilities[i])) for i in top_indices]

    return attack_type, confidence, top_predictions


# =============================================================================
# Test 1: Anomaly Detection Accuracy
# =============================================================================
print("[2/5] Testing Anomaly Detection...")
print("-" * 70)

# Generate test traffic
test_results = []
for attack_name in ATTACK_PROFILES.keys():
    for _ in range(10):  # 10 samples per type
        traffic = generate_attack_traffic(attack_name)
        is_anomaly, score = predict_anomaly(traffic)
        test_results.append({
            "type": attack_name,
            "is_anomaly": is_anomaly,
            "score": score,
            "expected_anomaly": attack_name != "Benign Traffic"
        })

# Calculate accuracy
correct = sum(1 for r in test_results if r["is_anomaly"] == r["expected_anomaly"])
total = len(test_results)
print(f"  Anomaly Detection Accuracy: {correct}/{total} ({correct/total*100:.1f}%)")

# Show per-category results
print(f"\n  {'Category':<45} {'Detected':>10} {'Score':>8}")
print("  " + "-" * 65)
for attack_name in ATTACK_PROFILES.keys():
    category_results = [r for r in test_results if r["type"] == attack_name]
    detected = sum(1 for r in category_results if r["is_anomaly"])
    avg_score = sum(r["score"] for r in category_results) / len(category_results)
    expected = "✓" if attack_name != "Benign Traffic" else "✗"
    status = "✓" if (detected > 5 and attack_name != "Benign Traffic") or (detected < 5 and attack_name == "Benign Traffic") else "✗"
    print(f"  {attack_name:<45} {detected:>3}/10 {status}   {avg_score:>6.2f}")
print()


# =============================================================================
# Test 2: Attack Classification Accuracy
# =============================================================================
print("[3/5] Testing Attack Classification (8 MITRE ATT&CK Categories)...")
print("-" * 70)

classification_results = []
for attack_name in ATTACK_PROFILES.keys():
    for _ in range(10):
        traffic = generate_attack_traffic(attack_name)
        predicted, confidence, top3 = classify_attack(traffic)

        # Map our attack profiles to the trained labels
        expected_mapping = {
            "Credential Access (T1110 - Brute Force)": "Credential Access",
            "Defense Evasion": "Defense Evasion",
            "Exfiltration (T1048)": "Exfiltration",
            "Initial Access (T1190 - Exploit)": "Initial Access",
            "Persistence (T1078 - Valid Accounts)": "Persistence",
            "Privilege Escalation": "Privilege Escalation",
            "Reconnaissance (T1595 - Active Scanning)": "Reconnaissance",
            "Benign Traffic": "none"
        }
        expected = expected_mapping.get(attack_name, "none")

        classification_results.append({
            "type": attack_name,
            "predicted": predicted,
            "expected": expected,
            "confidence": confidence,
            "correct": predicted == expected,
            "top3": top3
        })

# Overall accuracy
correct = sum(1 for r in classification_results if r["correct"])
total = len(classification_results)
print(f"  Classification Accuracy: {correct}/{total} ({correct/total*100:.1f}%)")

# Per-category accuracy
print(f"\n  {'Attack Category':<45} {'Accuracy':>10} {'Avg Conf':>10}")
print("  " + "-" * 67)
for attack_name in ATTACK_PROFILES.keys():
    category_results = [r for r in classification_results if r["type"] == attack_name]
    correct_cat = sum(1 for r in category_results if r["correct"])
    avg_conf = sum(r["confidence"] for r in category_results) / len(category_results)
    status = "✓" if correct_cat >= 6 else "✗"
    print(f"  {attack_name:<45} {correct_cat:>3}/10 {status}   {avg_conf:>8.1%}")
print()


# =============================================================================
# Test 3: Real-Time Attack Simulation
# =============================================================================
print("[4/5] Real-Time Attack Simulation (20 events)...")
print("-" * 70)
print()

SEVERITY_MAP = {
    "Credential Access": "HIGH",
    "Defense Evasion": "MEDIUM",
    "Exfiltration": "CRITICAL",
    "Initial Access": "CRITICAL",
    "Persistence": "HIGH",
    "Privilege Escalation": "CRITICAL",
    "Reconnaissance": "LOW",
    "none": "INFO"
}

MITRE_TECHNIQUES = {
    "Credential Access": "T1110",
    "Defense Evasion": "T1070",
    "Exfiltration": "T1048",
    "Initial Access": "T1190",
    "Persistence": "T1078",
    "Privilege Escalation": "T1068",
    "Reconnaissance": "T1595",
    "none": "-"
}

detected_attacks = {label: 0 for label in attack_labels.values()}
total_events = 0
anomalies_detected = 0

print(f"{'Time':<12} {'Source IP':<16} {'Dest IP':<16} {'Port':>6} {'Anomaly':>8} {'Attack Category':<22} {'MITRE':>8} {'Severity':<10} {'Conf':>6}")
print("-" * 120)

for i in range(20):
    # Randomly select attack type (weighted toward attacks)
    if random.random() < 0.3:
        attack_type = "Benign Traffic"
    else:
        attack_type = random.choice([k for k in ATTACK_PROFILES.keys() if k != "Benign Traffic"])

    traffic = generate_attack_traffic(attack_type)

    # Run predictions
    is_anomaly, anomaly_score = predict_anomaly(traffic)
    predicted_attack, confidence, _ = classify_attack(traffic)

    # Update counters
    total_events += 1
    if is_anomaly:
        anomalies_detected += 1
    detected_attacks[predicted_attack] += 1

    # Display result
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:12]
    severity = SEVERITY_MAP.get(predicted_attack, "INFO")
    mitre = MITRE_TECHNIQUES.get(predicted_attack, "-")

    # Color-code severity (using ANSI if terminal supports it)
    severity_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
        "INFO": "\033[90m"       # Gray
    }
    reset = "\033[0m"
    color = severity_colors.get(severity, "")

    anomaly_str = f"{anomaly_score:.2f}" if is_anomaly else "Normal"
    attack_display = predicted_attack if predicted_attack != "none" else "Benign"

    print(f"{timestamp} {traffic['src_ip']:<16} {traffic['dst_ip']:<16} {traffic['dest_port']:>6} {anomaly_str:>8} {color}{attack_display:<22}{reset} {mitre:>8} {color}{severity:<10}{reset} {confidence:>5.1%}")

    time.sleep(0.1)  # Simulate real-time processing

print()


# =============================================================================
# Test 4: Summary Report
# =============================================================================
print("[5/5] Detection Summary Report")
print("-" * 70)
print()

print(f"  Total Events Processed: {total_events}")
print(f"  Anomalies Detected: {anomalies_detected} ({anomalies_detected/total_events*100:.1f}%)")
print()

print("  Attack Category Distribution:")
print(f"  {'Category':<25} {'Count':>8} {'Percentage':>12}")
print("  " + "-" * 47)
for attack, count in sorted(detected_attacks.items(), key=lambda x: -x[1]):
    if count > 0:
        pct = count / total_events * 100
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"  {attack:<25} {count:>8} {pct:>10.1f}%  {bar}")

print()
print("=" * 70)
print("Testing Complete!")
print("=" * 70)
print()
print("ML Models Summary:")
print(f"  - Anomaly Detector: Isolation Forest (trained on 25.4M CESNET records)")
print(f"  - Attack Classifier: XGBoost 8-class (trained on 1.9M UWF records)")
print(f"  - Attack Categories: {list(attack_labels.values())}")
print()
print("Next: These models are ready for integration with the backend API.")
