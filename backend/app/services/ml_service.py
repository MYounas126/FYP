"""
ML Service for anomaly detection and classification.

Loads trained models and provides real-time inference.
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

import numpy as np
import joblib
from loguru import logger

from app.core.config import settings
from app.core.ml_config import (
    CLASSIFIER_FEATURE_MAPPING,
    CLASSIFIER_FEATURES,
    FEATURE_BOUNDS,
    EXPECTED_CLASSIFIER_FEATURE_COUNT,
    map_api_to_training_features,
    validate_and_clamp_features,
    extract_ordered_features,
)


class ModelLoadError(Exception):
    """Raised when model loading fails."""
    pass


class PredictionError(Exception):
    """Raised when prediction fails."""
    pass


class MLService:
    """
    Machine Learning service for network traffic analysis.

    Handles model loading and inference for:
    - Anomaly detection (Isolation Forest)
    - Attack classification (XGBoost)
    """

    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.classifier_features: List[str] = []
        self.attack_labels: Dict[int, str] = {}
        self.model_metadata: Dict[str, Any] = {}
        self._loaded = False

    async def load_models(self) -> None:
        """
        Load all trained models from disk.

        Models are loaded from the path specified in settings.ML_MODEL_PATH.
        Validates feature count and model integrity.
        """
        model_path = Path(settings.ML_MODEL_PATH)

        if not model_path.exists():
            logger.warning(f"Model path does not exist: {model_path}")
            logger.info("ML service will run in demo mode with random predictions")
            self._loaded = False
            return

        try:
            # Load anomaly detection model (Isolation Forest)
            anomaly_model_path = model_path / "anomaly_detector.joblib"
            if anomaly_model_path.exists():
                self.models["anomaly"] = joblib.load(anomaly_model_path)
                logger.info("Loaded anomaly detection model")

            # Load anomaly scaler
            anomaly_scaler_path = model_path / "scaler_anomaly.joblib"
            if anomaly_scaler_path.exists():
                self.scalers["anomaly"] = joblib.load(anomaly_scaler_path)
                logger.info("Loaded anomaly scaler")

            # Load classifier model (XGBoost)
            classifier_path = model_path / "classifier.joblib"
            if not classifier_path.exists():
                classifier_path = model_path / "attack_classifier.joblib"
            if classifier_path.exists():
                self.models["classifier"] = joblib.load(classifier_path)
                logger.info("Loaded attack classifier model")

            # Load classifier scaler
            classifier_scaler_path = model_path / "scaler_classifier.joblib"
            if not classifier_scaler_path.exists():
                classifier_scaler_path = model_path / "scaler.joblib"
            if classifier_scaler_path.exists():
                self.scalers["classifier"] = joblib.load(classifier_scaler_path)
                logger.info("Loaded classifier scaler")

            # Load classifier feature names - critical for feature alignment
            features_path = model_path / "classifier_features.joblib"
            if features_path.exists():
                self.classifier_features = joblib.load(features_path)
                logger.info(f"Loaded {len(self.classifier_features)} classifier features")

                # Validate feature count
                if len(self.classifier_features) != EXPECTED_CLASSIFIER_FEATURE_COUNT:
                    logger.warning(
                        f"Feature count mismatch: expected {EXPECTED_CLASSIFIER_FEATURE_COUNT}, "
                        f"got {len(self.classifier_features)}"
                    )
            else:
                # Use default feature order from config
                self.classifier_features = CLASSIFIER_FEATURES
                logger.info(f"Using default classifier features: {self.classifier_features}")

            # Load feature names (legacy support)
            legacy_features_path = model_path / "feature_names.joblib"
            if legacy_features_path.exists():
                self.feature_names = joblib.load(legacy_features_path)
                logger.info(f"Loaded {len(self.feature_names)} legacy feature names")

            # Load attack labels
            labels_path = model_path / "attack_labels.joblib"
            if labels_path.exists():
                self.attack_labels = joblib.load(labels_path)
                logger.info(f"Loaded {len(self.attack_labels)} attack labels")

            # Load label encoder as fallback for attack labels
            encoder_path = model_path / "label_encoder.joblib"
            if encoder_path.exists() and not self.attack_labels:
                encoder = joblib.load(encoder_path)
                self.attack_labels = {i: label for i, label in enumerate(encoder.classes_)}
                logger.info(f"Loaded attack labels from encoder: {len(self.attack_labels)}")

            # Load model metadata if available
            metadata_path = model_path / "model_metadata.joblib"
            if metadata_path.exists():
                self.model_metadata = joblib.load(metadata_path)
                logger.info(f"Loaded model metadata: v{self.model_metadata.get('version', 'unknown')}")

            self._loaded = bool(self.models)
            logger.info(f"ML service loaded: {len(self.models)} models available")

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise ModelLoadError(f"Failed to load ML models: {e}") from e

    def is_loaded(self) -> bool:
        """Check if models are loaded."""
        return self._loaded

    def extract_features(self, traffic_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract ML features from raw traffic data.

        Uses the feature mapping from ml_config to ensure consistency
        between training and inference feature names.

        Args:
            traffic_data: Dictionary containing traffic flow data

        Returns:
            Feature vector as numpy array in the correct order
        """
        # First, validate and clamp input values
        validated_data = validate_and_clamp_features(traffic_data)

        # Map API field names to training feature names
        mapped_data = map_api_to_training_features(validated_data)

        # Also include original field names for flexibility
        for key, value in validated_data.items():
            if key not in mapped_data:
                mapped_data[key] = value

        # Extract features in the correct order
        # Use classifier_features if loaded from model, otherwise use config default
        feature_order = self.classifier_features if self.classifier_features else CLASSIFIER_FEATURES

        features = extract_ordered_features(mapped_data, feature_order)

        return np.array(features).reshape(1, -1)

    async def predict(
        self,
        traffic_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform anomaly detection and classification on traffic data.

        Args:
            traffic_data: Dictionary containing traffic flow data

        Returns:
            Prediction results including:
            - is_anomaly: Boolean indicating if traffic is anomalous
            - anomaly_score: Score from anomaly detector (-1 to 1)
            - attack_category: Predicted attack type if anomalous
            - mitre_tactic: MITRE ATT&CK tactic
            - confidence: Prediction confidence

        Raises:
            PredictionError: If prediction fails due to model or data issues
        """
        if not self._loaded:
            # Demo mode - return random predictions for testing
            return self._demo_prediction()

        try:
            # Extract and validate features
            features = self.extract_features(traffic_data)

            # Scale features if scaler is available
            if "classifier" in self.scalers:
                features = self.scalers["classifier"].transform(features)
            elif "main" in self.scalers:
                features = self.scalers["main"].transform(features)

            result = {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "attack_category": None,
                "mitre_tactic": None,
                "mitre_technique": None,
                "confidence": 0.0
            }

            # Anomaly detection
            if "anomaly" in self.models:
                # Isolation Forest returns -1 for anomalies, 1 for normal
                prediction = self.models["anomaly"].predict(features)[0]
                score = self.models["anomaly"].decision_function(features)[0]

                result["is_anomaly"] = prediction == -1
                # Normalize score to 0-1 range (higher = more anomalous)
                result["anomaly_score"] = max(0, min(1, 0.5 - score))

            # Classification (only if anomalous)
            if result["is_anomaly"] and "classifier" in self.models:
                prediction = self.models["classifier"].predict(features)[0]
                probabilities = self.models["classifier"].predict_proba(features)[0]

                attack_label = self.attack_labels.get(int(prediction), "Unknown")
                confidence = float(max(probabilities))

                result["attack_category"] = attack_label
                result["confidence"] = confidence

                # Map to MITRE ATT&CK (simplified mapping)
                result["mitre_tactic"], result["mitre_technique"] = self._map_to_mitre(attack_label)

            return result

        except ValueError as e:
            logger.error(f"Feature extraction error: {e}")
            raise PredictionError(f"Invalid feature data: {e}") from e
        except Exception as e:
            logger.exception("Prediction failed")
            raise PredictionError(f"Inference error: {e}") from e

    def _demo_prediction(self) -> Dict[str, Any]:
        """Generate demo prediction for testing without models."""
        import random

        is_anomaly = random.random() > 0.9  # 10% anomaly rate

        categories = [
            "DoS", "DDoS", "Probe", "Brute Force",
            "Web Attack", "Infiltration", "Botnet"
        ]

        tactics = [
            ("Initial Access", "T1190"),
            ("Execution", "T1059"),
            ("Persistence", "T1547"),
            ("Discovery", "T1046"),
            ("Impact", "T1499")
        ]

        if is_anomaly:
            category = random.choice(categories)
            tactic, technique = random.choice(tactics)
            return {
                "is_anomaly": True,
                "anomaly_score": random.uniform(0.7, 1.0),
                "attack_category": category,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "confidence": random.uniform(0.75, 0.99)
            }

        return {
            "is_anomaly": False,
            "anomaly_score": random.uniform(0, 0.3),
            "attack_category": None,
            "mitre_tactic": None,
            "mitre_technique": None,
            "confidence": 0.0
        }

    def _map_to_mitre(self, attack_category: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Map attack category to MITRE ATT&CK framework.

        Args:
            attack_category: Detected attack type

        Returns:
            Tuple of (tactic, technique)
        """
        mitre_mapping = {
            "DoS": ("Impact", "T1499"),
            "DDoS": ("Impact", "T1498"),
            "Probe": ("Discovery", "T1046"),
            "Brute Force": ("Credential Access", "T1110"),
            "Web Attack": ("Initial Access", "T1190"),
            "SQL Injection": ("Initial Access", "T1190"),
            "XSS": ("Initial Access", "T1189"),
            "Infiltration": ("Lateral Movement", "T1021"),
            "Botnet": ("Command and Control", "T1071"),
            "Reconnaissance": ("Reconnaissance", "T1595"),
            "Fuzzers": ("Discovery", "T1046"),
            "Backdoor": ("Persistence", "T1547"),
            "Shellcode": ("Execution", "T1059"),
            "Worms": ("Lateral Movement", "T1080"),
            "Exploits": ("Execution", "T1203")
        }

        return mitre_mapping.get(attack_category, (None, None))

    async def batch_predict(
        self,
        traffic_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Perform batch predictions for efficiency.

        Args:
            traffic_list: List of traffic data dictionaries

        Returns:
            List of prediction results
        """
        return [await self.predict(traffic) for traffic in traffic_list]


# Global ML service instance
ml_service = MLService()
