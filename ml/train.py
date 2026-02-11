"""
SentinelFlow ML Training Pipeline

Trains:
1. Isolation Forest for anomaly detection (using CESNET-TimeSeries24)
2. XGBoost for attack classification (using UWF-ZeekData22 with MITRE ATT&CK labels)
"""

import os
import sys
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
)
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

# Configuration
DATA_DIR = Path("data/raw")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SentinelFlow ML Training Pipeline")
print("=" * 60)
print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()


# =============================================================================
# 1. Load CESNET-TimeSeries24 for Anomaly Detection
# =============================================================================
print("[1/4] Loading CESNET-TimeSeries24 dataset...")

# Try full dataset first, fall back to sample
cesnet_full_dir = DATA_DIR / "cesnet-timeseries24" / "ip_addresses_full" / "agg_1_hour"
cesnet_sample_dir = DATA_DIR / "cesnet-timeseries24" / "ip_addresses_sample" / "agg_1_hour"

if cesnet_full_dir.exists():
    cesnet_dir = cesnet_full_dir
    print("  Using FULL dataset (275K+ IPs)")
    # Full dataset has nested directories (1/, 2/, etc.)
    csv_files = list(cesnet_dir.glob("**/*.csv"))
else:
    cesnet_dir = cesnet_sample_dir
    print("  Using SAMPLE dataset (1K IPs)")
    csv_files = list(cesnet_dir.glob("*.csv"))

if not cesnet_dir.exists():
    print(f"ERROR: CESNET dataset not found at {cesnet_dir}")
    sys.exit(1)

# For full dataset, sample to manage memory (32GB RAM available)
MAX_FILES = 20000  # ~20K IPs to stay within 32GB RAM (was 50K, caused OOM)
if len(csv_files) > MAX_FILES:
    print(f"  Sampling {MAX_FILES:,} of {len(csv_files):,} files to manage memory...")
    import random
    random.seed(42)
    csv_files = random.sample(csv_files, MAX_FILES)

print(f"  Loading {len(csv_files):,} IP time series files...")

cesnet_dfs = []
loaded_count = 0
for i, f in enumerate(csv_files):
    try:
        df = pd.read_csv(f)
        df['ip_id'] = f.stem  # Add IP identifier
        cesnet_dfs.append(df)
        loaded_count += 1
        if (i + 1) % 5000 == 0:
            print(f"    Progress: {i + 1:,}/{len(csv_files):,} files loaded...")
    except Exception as e:
        pass
print(f"    Successfully loaded {loaded_count:,} files")

df_cesnet = pd.concat(cesnet_dfs, ignore_index=True)
print(f"  Loaded {len(df_cesnet):,} records from CESNET")

# Select features for anomaly detection
cesnet_features = [
    'n_flows', 'n_packets', 'n_bytes',
    'average_n_dest_asn', 'std_n_dest_asn',
    'average_n_dest_ports', 'std_n_dest_ports',
    'average_n_dest_ip', 'std_n_dest_ip',
    'tcp_udp_ratio_packets', 'tcp_udp_ratio_bytes',
    'dir_ratio_packets', 'dir_ratio_bytes',
    'avg_duration', 'avg_ttl'
]

# Prepare CESNET features
X_cesnet = df_cesnet[cesnet_features].copy()
X_cesnet = X_cesnet.fillna(0)
X_cesnet = X_cesnet.replace([np.inf, -np.inf], 0)

print(f"  Features shape: {X_cesnet.shape}")
print()


# =============================================================================
# 2. Train Isolation Forest (Anomaly Detection)
# =============================================================================
print("[2/4] Training Isolation Forest for anomaly detection...")

# Split data FIRST to prevent data leakage
# NOTE: For unsupervised anomaly detection, we still split to have a held-out set
# for evaluation, but we only fit the scaler on the training portion
from sklearn.model_selection import train_test_split as anomaly_split
X_anomaly_train, X_anomaly_test = anomaly_split(X_cesnet, test_size=0.2, random_state=42)

print(f"  Anomaly detection training set: {len(X_anomaly_train):,} samples")
print(f"  Anomaly detection test set: {len(X_anomaly_test):,} samples")

# Scale features - FIT ONLY ON TRAINING DATA to prevent data leakage
scaler_anomaly = StandardScaler()
X_anomaly_train_scaled = scaler_anomaly.fit_transform(X_anomaly_train)
X_anomaly_test_scaled = scaler_anomaly.transform(X_anomaly_test)  # Transform test separately

# Train Isolation Forest
isolation_forest = IsolationForest(
    n_estimators=100,
    contamination=0.1,  # Expect ~10% anomalies
    max_samples='auto',
    random_state=42,
    n_jobs=-1,
    verbose=0
)

isolation_forest.fit(X_anomaly_train_scaled)

# Evaluate on test set
train_predictions = isolation_forest.predict(X_anomaly_train_scaled)
test_predictions = isolation_forest.predict(X_anomaly_test_scaled)
train_anomaly_count = (train_predictions == -1).sum()
test_anomaly_count = (test_predictions == -1).sum()

print(f"  Model trained successfully!")
print(f"  Training anomalies: {train_anomaly_count:,} ({train_anomaly_count/len(train_predictions)*100:.1f}%)")
print(f"  Test anomalies: {test_anomaly_count:,} ({test_anomaly_count/len(test_predictions)*100:.1f}%)")

# Save anomaly detection model
joblib.dump(isolation_forest, MODEL_DIR / "anomaly_detector.joblib")
joblib.dump(scaler_anomaly, MODEL_DIR / "scaler_anomaly.joblib")
joblib.dump(cesnet_features, MODEL_DIR / "anomaly_features.joblib")
print(f"  Saved: anomaly_detector.joblib, scaler_anomaly.joblib")
print()


# =============================================================================
# 3. Load UWF-ZeekData24 for Attack Classification
# =============================================================================
print("[3/4] Loading UWF-ZeekData24 dataset...")

uwf_dir = DATA_DIR / "uwf-zeekdata24"
parquet_dir = uwf_dir / "parquet"

if not uwf_dir.exists():
    print(f"ERROR: UWF dataset not found at {uwf_dir}")
    sys.exit(1)

# Try parquet files first (more data), fall back to CSV
if parquet_dir.exists():
    parquet_files = [f for f in parquet_dir.glob("*.parquet") if f.stat().st_size > 1000]
    if parquet_files:
        print(f"  Loading {len(parquet_files)} parquet files (preferred format)...")
        uwf_dfs = []
        for f in parquet_files:
            try:
                df = pd.read_parquet(f)
                uwf_dfs.append(df)
                print(f"    - {f.name}: {len(df):,} records")
            except Exception as e:
                print(f"  Warning: Could not load {f.name}: {e}")
        df_uwf = pd.concat(uwf_dfs, ignore_index=True)

        # Parquet uses 'label_tactic' instead of 'mitre_attack_tactics'
        label_column = 'label_tactic'
        # Parquet uses different port column names
        port_columns = {'dest_port': 'dest_port_zeek', 'src_port': 'src_port_zeek'}
    else:
        parquet_dir = None

if not parquet_dir or not parquet_files:
    # Fall back to CSV files
    csv_files = list(uwf_dir.glob("*.csv"))
    print(f"  Loading {len(csv_files)} CSV files...")
    uwf_dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            uwf_dfs.append(df)
        except Exception as e:
            print(f"  Warning: Could not load {f.name}: {e}")
    df_uwf = pd.concat(uwf_dfs, ignore_index=True)
    label_column = 'mitre_attack_tactics'
    port_columns = {'dest_port': 'dest_port', 'src_port': 'src_port'}

print(f"  Loaded {len(df_uwf):,} records from UWF-ZeekData24")

# Check for MITRE ATT&CK labels
if label_column not in df_uwf.columns:
    print(f"ERROR: No MITRE ATT&CK labels found (looking for '{label_column}')")
    print(f"Available columns: {list(df_uwf.columns)}")
    sys.exit(1)

# Show class distribution
print(f"\n  Attack categories distribution:")
attack_counts = df_uwf[label_column].value_counts()
for attack, count in attack_counts.items():
    print(f"    - {attack}: {count:,} ({count/len(df_uwf)*100:.1f}%)")

# Select features for classification (with column name mapping)
uwf_features = [
    'orig_pkts', 'resp_pkts',
    'orig_bytes', 'resp_bytes',
    'orig_ip_bytes', 'resp_ip_bytes',
    'duration', 'missed_bytes',
    port_columns['dest_port'], port_columns['src_port']
]

# Prepare features
X_uwf = df_uwf[uwf_features].copy()
X_uwf = X_uwf.fillna(0)
X_uwf = X_uwf.replace([np.inf, -np.inf], 0)

# Prepare labels
y_uwf = df_uwf[label_column].copy()

# Filter out rare classes (need at least 100 samples for reliable training)
MIN_SAMPLES = 100
class_counts = y_uwf.value_counts()
valid_classes = class_counts[class_counts >= MIN_SAMPLES].index.tolist()
rare_classes = class_counts[class_counts < MIN_SAMPLES].index.tolist()

if rare_classes:
    print(f"\n  Filtering rare classes (< {MIN_SAMPLES} samples): {rare_classes}")
    mask = y_uwf.isin(valid_classes)
    X_uwf = X_uwf[mask]
    y_uwf = y_uwf[mask]
    print(f"  Kept {len(y_uwf):,} records with {len(valid_classes)} classes")

# Encode labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y_uwf)

print(f"\n  Features shape: {X_uwf.shape}")
print(f"  Number of classes: {len(label_encoder.classes_)}")
print(f"  Classes: {list(label_encoder.classes_)}")
print()


# =============================================================================
# 4. Train XGBoost Classifier (Attack Classification)
# =============================================================================
print("[4/4] Training XGBoost for attack classification...")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X_uwf, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"  Training set: {len(X_train):,} samples")
print(f"  Test set: {len(X_test):,} samples")

# Scale features
scaler_classifier = StandardScaler()
X_train_scaled = scaler_classifier.fit_transform(X_train)
X_test_scaled = scaler_classifier.transform(X_test)

# =============================================================================
# Cross-Validation for reliable performance estimation
# =============================================================================
print("  Running 5-fold stratified cross-validation...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Create a temporary classifier for CV (with fewer estimators for speed)
cv_classifier = xgb.XGBClassifier(
    n_estimators=50,  # Fewer for CV speed
    max_depth=6,
    learning_rate=0.1,
    tree_method='hist',
    random_state=42,
    n_jobs=-1,
    verbosity=0
)

cv_scores = cross_val_score(cv_classifier, X_train_scaled, y_train, cv=cv, scoring='f1_weighted')
print(f"  CV F1 Scores: {cv_scores}")
print(f"  CV F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

# Train XGBoost
num_classes = len(label_encoder.classes_)
xgb_classifier = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    objective='multi:softprob' if num_classes > 2 else 'binary:logistic',
    num_class=num_classes if num_classes > 2 else None,
    tree_method='hist',  # Fast histogram-based method
    random_state=42,
    n_jobs=-1,
    verbosity=1
)

print("  Training XGBoost classifier...")
xgb_classifier.fit(
    X_train_scaled, y_train,
    eval_set=[(X_test_scaled, y_test)],
    verbose=False
)

# Evaluate
y_pred = xgb_classifier.predict(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')

print(f"\n  === Classification Results ===")
print(f"  Accuracy:  {accuracy:.4f}")
print(f"  Precision: {precision:.4f}")
print(f"  Recall:    {recall:.4f}")
print(f"  F1 Score:  {f1:.4f}")

print(f"\n  Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# Save classifier model
joblib.dump(xgb_classifier, MODEL_DIR / "classifier.joblib")
joblib.dump(scaler_classifier, MODEL_DIR / "scaler_classifier.joblib")
joblib.dump(label_encoder, MODEL_DIR / "label_encoder.joblib")
# Save original feature names used (for inference)
joblib.dump(uwf_features, MODEL_DIR / "classifier_features.joblib")
# Also save standardized feature mapping for API use
standard_features = ['orig_pkts', 'resp_pkts', 'orig_bytes', 'resp_bytes',
                     'orig_ip_bytes', 'resp_ip_bytes', 'duration', 'missed_bytes',
                     'dest_port', 'src_port']
joblib.dump(standard_features, MODEL_DIR / "classifier_features_standard.joblib")

# Save attack labels mapping
attack_labels = {i: label for i, label in enumerate(label_encoder.classes_)}
joblib.dump(attack_labels, MODEL_DIR / "attack_labels.joblib")

# =============================================================================
# Save Model Metadata for versioning and integrity verification
# =============================================================================
import hashlib

def compute_model_checksum(model) -> str:
    """Compute SHA256 checksum of serialized model."""
    return hashlib.sha256(joblib.dumps(model)).hexdigest()

model_metadata = {
    "version": "1.0.0",
    "trained_at": datetime.utcnow().isoformat(),
    "datasets": {
        "anomaly": "CESNET-TimeSeries24",
        "classifier": "UWF-ZeekData24"
    },
    "metrics": {
        "classifier": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "cv_f1_mean": float(cv_scores.mean()),
            "cv_f1_std": float(cv_scores.std()),
        }
    },
    "features": {
        "anomaly": cesnet_features,
        "classifier": standard_features,
    },
    "hyperparameters": {
        "classifier": xgb_classifier.get_params(),
        "anomaly": isolation_forest.get_params(),
    },
    "checksums": {
        "classifier": compute_model_checksum(xgb_classifier),
        "anomaly_detector": compute_model_checksum(isolation_forest),
        "scaler_classifier": compute_model_checksum(scaler_classifier),
        "scaler_anomaly": compute_model_checksum(scaler_anomaly),
    },
    "class_distribution": {
        label: int(count) for label, count in attack_counts.items()
    },
    "training_samples": {
        "anomaly_train": len(X_anomaly_train),
        "anomaly_test": len(X_anomaly_test),
        "classifier_train": len(X_train),
        "classifier_test": len(X_test),
    }
}

joblib.dump(model_metadata, MODEL_DIR / "model_metadata.joblib")
print(f"  Saved: model_metadata.joblib (version {model_metadata['version']})")

print(f"\n  Saved: classifier.joblib, scaler_classifier.joblib, label_encoder.joblib")


# =============================================================================
# Summary
# =============================================================================
print("\n" + "=" * 60)
print("Training Complete!")
print("=" * 60)
print(f"\nModels saved to: {MODEL_DIR.absolute()}")
print("\nSaved files:")
for f in MODEL_DIR.glob("*.joblib"):
    size = f.stat().st_size / 1024
    print(f"  - {f.name} ({size:.1f} KB)")

print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\nNext steps:")
print("  1. Start the backend server to use these models")
print("  2. The ML service will load models from the 'models' directory")
print("  3. Models will be used for real-time traffic analysis")
