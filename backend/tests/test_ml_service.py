"""
Tests for ML Service

Tests model loading, feature extraction, and predictions.
"""

import pytest
import numpy as np
from unittest.mock import MagicMock, patch, AsyncMock

from app.services.ml_service import MLService, ModelLoadError, PredictionError
from app.core.ml_config import (
    CLASSIFIER_FEATURES,
    CLASSIFIER_FEATURE_MAPPING,
    FEATURE_BOUNDS,
    map_api_to_training_features,
    validate_and_clamp_features,
)


class TestMLConfig:
    """Tests for ML configuration module."""

    def test_feature_mapping_completeness(self):
        """Test that all API features map to training features."""
        api_features = ["bytes_sent", "bytes_received", "packets_sent", "packets_received"]
        for feature in api_features:
            assert feature in CLASSIFIER_FEATURE_MAPPING
            assert CLASSIFIER_FEATURE_MAPPING[feature] is not None

    def test_map_api_to_training_features(self):
        """Test API to training feature name mapping."""
        api_data = {
            "bytes_sent": 1000,
            "bytes_received": 2000,
            "packets_sent": 10,
            "packets_received": 20,
        }
        result = map_api_to_training_features(api_data)

        assert result["orig_bytes"] == 1000
        assert result["resp_bytes"] == 2000
        assert result["orig_pkts"] == 10
        assert result["resp_pkts"] == 20

    def test_validate_and_clamp_features_normal(self):
        """Test feature validation with normal values."""
        features = {
            "bytes_sent": 1000,
            "packets_sent": 100,
            "duration": 5.0,
        }
        result = validate_and_clamp_features(features)

        assert result["bytes_sent"] == 1000
        assert result["packets_sent"] == 100
        assert result["duration"] == 5.0

    def test_validate_and_clamp_features_exceeds_max(self):
        """Test that features exceeding max are clamped."""
        features = {
            "bytes_sent": 100_000_000_000_000,  # Way over max
            "dst_port": 70000,  # Over 65535
        }
        result = validate_and_clamp_features(features)

        assert result["bytes_sent"] == FEATURE_BOUNDS["bytes_sent"]["max"]
        assert result["dst_port"] == 65535

    def test_validate_and_clamp_features_negative(self):
        """Test that negative values are clamped to 0."""
        features = {
            "bytes_sent": -1000,
            "packets_sent": -10,
        }
        result = validate_and_clamp_features(features)

        assert result["bytes_sent"] == 0
        assert result["packets_sent"] == 0


class TestMLService:
    """Tests for the ML service."""

    @pytest.fixture
    def ml_service(self):
        """Create a fresh ML service instance."""
        return MLService()

    def test_initial_state(self, ml_service):
        """Test ML service initial state."""
        assert ml_service._loaded is False
        assert ml_service.models == {}
        assert ml_service.scalers == {}

    def test_is_loaded_false_by_default(self, ml_service):
        """Test is_loaded returns False initially."""
        assert ml_service.is_loaded() is False

    def test_extract_features_with_api_names(self, ml_service):
        """Test feature extraction with API-style field names."""
        ml_service.classifier_features = CLASSIFIER_FEATURES

        traffic_data = {
            "bytes_sent": 1000,
            "bytes_received": 2000,
            "packets_sent": 10,
            "packets_received": 20,
            "orig_ip_bytes": 1100,
            "resp_ip_bytes": 2100,
            "duration": 5.0,
            "missed_bytes": 0,
            "dst_port": 443,
            "src_port": 45678,
        }

        features = ml_service.extract_features(traffic_data)

        assert features.shape == (1, 10)  # 10 features, 1 sample
        assert isinstance(features, np.ndarray)

    def test_extract_features_with_training_names(self, ml_service):
        """Test feature extraction with training-style field names."""
        ml_service.classifier_features = CLASSIFIER_FEATURES

        traffic_data = {
            "orig_bytes": 1000,
            "resp_bytes": 2000,
            "orig_pkts": 10,
            "resp_pkts": 20,
            "orig_ip_bytes": 1100,
            "resp_ip_bytes": 2100,
            "duration": 5.0,
            "missed_bytes": 0,
            "dest_port": 443,
            "src_port": 45678,
        }

        features = ml_service.extract_features(traffic_data)

        assert features.shape == (1, 10)

    @pytest.mark.asyncio
    async def test_predict_demo_mode(self, ml_service):
        """Test prediction in demo mode (models not loaded)."""
        result = await ml_service.predict({"bytes_sent": 1000})

        # Should return demo prediction
        assert "is_anomaly" in result
        assert "anomaly_score" in result
        assert "attack_category" in result
        assert "confidence" in result

    @pytest.mark.asyncio
    async def test_predict_with_models(self, ml_service):
        """Test prediction with mocked models."""
        # Setup mocked models
        mock_anomaly = MagicMock()
        mock_anomaly.predict.return_value = np.array([1])  # Normal (1 = normal, -1 = anomaly)
        mock_anomaly.decision_function.return_value = np.array([0.5])

        mock_classifier = MagicMock()
        mock_classifier.predict.return_value = np.array([0])
        mock_classifier.predict_proba.return_value = np.array([[0.9, 0.1]])

        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.zeros((1, 10))

        ml_service.models = {"anomaly": mock_anomaly, "classifier": mock_classifier}
        ml_service.scalers = {"classifier": mock_scaler}
        ml_service.classifier_features = CLASSIFIER_FEATURES
        ml_service.attack_labels = {0: "Normal", 1: "DoS"}
        ml_service._loaded = True

        result = await ml_service.predict({
            "bytes_sent": 1000,
            "bytes_received": 2000,
            "packets_sent": 10,
            "packets_received": 20,
            "orig_ip_bytes": 1100,
            "resp_ip_bytes": 2100,
            "duration": 5.0,
            "missed_bytes": 0,
            "dst_port": 443,
            "src_port": 45678,
        })

        assert result["is_anomaly"] is False
        assert isinstance(result["anomaly_score"], float)


class TestMITREMapping:
    """Tests for MITRE ATT&CK mapping."""

    @pytest.fixture
    def ml_service(self):
        return MLService()

    def test_map_dos_to_mitre(self, ml_service):
        """Test DoS attack maps to Impact tactic."""
        tactic, technique = ml_service._map_to_mitre("DoS")
        assert tactic == "Impact"
        assert technique == "T1499"

    def test_map_ddos_to_mitre(self, ml_service):
        """Test DDoS attack maps to Impact tactic."""
        tactic, technique = ml_service._map_to_mitre("DDoS")
        assert tactic == "Impact"
        assert technique == "T1498"

    def test_map_brute_force_to_mitre(self, ml_service):
        """Test Brute Force maps to Credential Access."""
        tactic, technique = ml_service._map_to_mitre("Brute Force")
        assert tactic == "Credential Access"
        assert technique == "T1110"

    def test_map_unknown_attack(self, ml_service):
        """Test unknown attack returns None."""
        tactic, technique = ml_service._map_to_mitre("UnknownAttackType")
        assert tactic is None
        assert technique is None
