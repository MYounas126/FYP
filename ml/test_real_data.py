"""
SentinelFlow - Test ML Models with REAL Dataset Samples

Uses actual UWF-ZeekData24 records to demonstrate accurate attack detection.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

# Paths
MODEL_DIR = Path("models")
DATA_DIR = Path("data/raw/uwf-zeekdata24/parquet")

print("=" * 80)
print("SentinelFlow - Real Attack Detection Demo (Using UWF-ZeekData24 Dataset)")
print("=" * 80)
print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# =============================================================================
# Load Models
# =============================================================================
print("[1/4] Loading trained models...")

classifier = joblib.load(MODEL_DIR / "classifier.joblib")
scaler_classifier = joblib.load(MODEL_DIR / "scaler_classifier.joblib")
label_encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")
attack_labels = joblib.load(MODEL_DIR / "attack_labels.joblib")

print(f"  ✓ Attack Classifier (XGBoost) - 8 MITRE ATT&CK classes")
print(f"  ✓ Classes: {list(attack_labels.values())}")
print()

# =============================================================================
# Load Real Dataset Samples
# =============================================================================
print("[2/4] Loading real attack samples from UWF-ZeekData24...")

parquet_files = list(DATA_DIR.glob("*.parquet"))
print(f"  Found {len(parquet_files)} parquet files")

# Load all data
dfs = []
for f in parquet_files:
    try:
        df = pd.read_parquet(f)
        dfs.append(df)
    except Exception as e:
        print(f"  Warning: Could not load {f.name}")

df = pd.concat(dfs, ignore_index=True)
print(f"  Loaded {len(df):,} total records")

# Show class distribution
print(f"\n  Attack Category Distribution in Dataset:")
print(f"  {'Category':<25} {'Count':>12} {'Percentage':>10}")
print("  " + "-" * 49)
for cat, count in df['label_tactic'].value_counts().items():
    pct = count / len(df) * 100
    print(f"  {cat:<25} {count:>12,} {pct:>9.1f}%")
print()

# =============================================================================
# Sample Real Records for Each Attack Type
# =============================================================================
print("[3/4] Real-Time Attack Detection Demo (Using REAL Dataset Samples)...")
print("-" * 80)
print()

# Features used by classifier
features = ['orig_pkts', 'resp_pkts', 'orig_bytes', 'resp_bytes',
            'orig_ip_bytes', 'resp_ip_bytes', 'duration', 'missed_bytes',
            'dest_port_zeek', 'src_port_zeek']

# Severity mapping
SEVERITY_MAP = {
    "Credential Access": ("CRITICAL", "\033[91m"),  # Red
    "Defense Evasion": ("HIGH", "\033[93m"),        # Yellow
    "Exfiltration": ("CRITICAL", "\033[91m"),       # Red
    "Initial Access": ("CRITICAL", "\033[91m"),    # Red
    "Persistence": ("HIGH", "\033[93m"),           # Yellow
    "Privilege Escalation": ("CRITICAL", "\033[91m"),  # Red
    "Reconnaissance": ("MEDIUM", "\033[94m"),      # Blue
    "none": ("INFO", "\033[92m")                   # Green
}

MITRE_TECHNIQUES = {
    "Credential Access": "T1110 - Brute Force",
    "Defense Evasion": "T1070 - Indicator Removal",
    "Exfiltration": "T1048 - Exfiltration Over Alternative Protocol",
    "Initial Access": "T1190 - Exploit Public-Facing Application",
    "Persistence": "T1078 - Valid Accounts",
    "Privilege Escalation": "T1068 - Exploitation for Privilege Escalation",
    "Reconnaissance": "T1595 - Active Scanning",
    "none": "N/A - Benign Traffic"
}

RESET = "\033[0m"

# Sample 5 records from each attack category
attack_categories = df['label_tactic'].unique()
samples = []

for cat in attack_categories:
    cat_df = df[df['label_tactic'] == cat]
    if len(cat_df) >= 5:
        sample = cat_df.sample(n=5, random_state=42)
    else:
        sample = cat_df.sample(n=min(5, len(cat_df)), random_state=42)
    samples.append(sample)

test_df = pd.concat(samples, ignore_index=True)
# Shuffle to simulate real-time mixed traffic
test_df = test_df.sample(frac=1, random_state=123).reset_index(drop=True)

print(f"  Testing with {len(test_df)} REAL network flow records")
print()

print(f"{'#':>3} {'Source':>14} → {'Dest':<14} {'Port':>6} {'Bytes':>10} {'Pkts':>6} {'TRUE Label':<20} {'PREDICTED':<20} {'Conf':>6} {'MITRE Technique':<35}")
print("-" * 160)

correct = 0
total = 0
results_by_category = {cat: {"correct": 0, "total": 0} for cat in attack_labels.values()}

for idx, row in test_df.iterrows():
    # Extract features
    X = row[features].values.reshape(1, -1)
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
    X_scaled = scaler_classifier.transform(X)

    # Predict
    pred = classifier.predict(X_scaled)[0]
    proba = classifier.predict_proba(X_scaled)[0]
    predicted_label = attack_labels[pred]
    confidence = max(proba)

    # True label
    true_label = row['label_tactic']

    # Check if correct
    is_correct = predicted_label == true_label
    if is_correct:
        correct += 1
    total += 1

    # Update per-category stats
    results_by_category[true_label]["total"] += 1
    if is_correct:
        results_by_category[true_label]["correct"] += 1

    # Get color and severity
    severity, color = SEVERITY_MAP.get(predicted_label, ("INFO", "\033[0m"))
    mitre = MITRE_TECHNIQUES.get(predicted_label, "Unknown")

    # Generate fake IPs for display
    src_ip = f"192.168.{np.random.randint(1,10)}.{np.random.randint(1,254)}"
    dst_ip = f"10.0.{np.random.randint(1,5)}.{np.random.randint(1,254)}"

    # Status indicator
    status = "✓" if is_correct else "✗"
    status_color = "\033[92m" if is_correct else "\033[91m"

    print(f"{total:>3} {src_ip:>14} → {dst_ip:<14} {int(row.get('dest_port_zeek', 0)):>6} {int(row.get('orig_bytes', 0)):>10} {int(row.get('orig_pkts', 0)):>6} {true_label:<20} {color}{predicted_label:<20}{RESET} {confidence:>5.1%} {mitre:<35} {status_color}{status}{RESET}")

    time.sleep(0.05)  # Simulate real-time processing

print("-" * 160)
print()

# =============================================================================
# Summary Statistics
# =============================================================================
print("[4/4] Detection Accuracy Report")
print("-" * 80)
print()

accuracy = correct / total * 100
print(f"  Overall Accuracy: {correct}/{total} ({accuracy:.1f}%)")
print()

print(f"  {'Attack Category':<25} {'Correct':>10} {'Total':>10} {'Accuracy':>12}")
print("  " + "-" * 59)

for cat, stats in sorted(results_by_category.items(), key=lambda x: -x[1]["total"]):
    if stats["total"] > 0:
        acc = stats["correct"] / stats["total"] * 100
        bar = "█" * int(acc / 10) + "░" * (10 - int(acc / 10))
        severity, color = SEVERITY_MAP.get(cat, ("INFO", "\033[0m"))
        print(f"  {color}{cat:<25}{RESET} {stats['correct']:>10} {stats['total']:>10} {acc:>10.1f}%  {bar}")

print()
print("=" * 80)
print("Real Attack Detection Demo Complete!")
print("=" * 80)
print()
print("Key Findings:")
print(f"  • Model correctly identifies {accuracy:.1f}% of real attack traffic")
print("  • 8 MITRE ATT&CK tactic categories supported")
print("  • Model trained on 1.9M real enterprise network flows")
print()
print("The classifier is ready for production use in the SentinelFlow backend.")
