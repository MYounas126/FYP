"""
ML Configuration Module

Shared feature configuration to ensure consistency between
training and inference pipelines.
"""

from typing import Dict, List

# =============================================================================
# Feature Configuration
# =============================================================================

# Mapping from API field names to training feature names
# This ensures consistency between inference and training
CLASSIFIER_FEATURE_MAPPING: Dict[str, str] = {
    "bytes_sent": "orig_bytes",
    "bytes_received": "resp_bytes",
    "packets_sent": "orig_pkts",
    "packets_received": "resp_pkts",
    "orig_ip_bytes": "orig_ip_bytes",
    "resp_ip_bytes": "resp_ip_bytes",
    "duration": "duration",
    "missed_bytes": "missed_bytes",
    "dst_port": "dest_port",
    "src_port": "src_port",
}

# Standard feature order for classifier (must match training order)
CLASSIFIER_FEATURES: List[str] = [
    "orig_pkts",
    "resp_pkts", 
    "orig_bytes",
    "resp_bytes",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "duration",
    "missed_bytes",
    "dest_port",
    "src_port",
]

# Anomaly detector features (CESNET dataset)
ANOMALY_FEATURES: List[str] = [
    "n_flows",
    "n_packets",
    "n_bytes",
    "average_n_dest_asn",
    "std_n_dest_asn",
    "average_n_dest_ports",
    "std_n_dest_ports",
    "average_n_dest_ip",
    "std_n_dest_ip",
    "tcp_udp_ratio_packets",
    "tcp_udp_ratio_bytes",
    "dir_ratio_packets",
    "dir_ratio_bytes",
    "avg_duration",
    "avg_ttl",
]

# =============================================================================
# Feature Validation Bounds
# =============================================================================

# Maximum reasonable values for feature validation (prevents adversarial inputs)
FEATURE_BOUNDS: Dict[str, Dict[str, float]] = {
    "bytes_sent": {"min": 0, "max": 10_000_000_000},      # 10GB max
    "bytes_received": {"min": 0, "max": 10_000_000_000},   # 10GB max
    "packets_sent": {"min": 0, "max": 100_000_000},        # 100M packets max
    "packets_received": {"min": 0, "max": 100_000_000},    # 100M packets max
    "orig_ip_bytes": {"min": 0, "max": 10_000_000_000},    # 10GB max
    "resp_ip_bytes": {"min": 0, "max": 10_000_000_000},    # 10GB max
    "duration": {"min": 0, "max": 86400},                   # 24 hours max
    "missed_bytes": {"min": 0, "max": 10_000_000_000},     # 10GB max
    "dst_port": {"min": 0, "max": 65535},
    "src_port": {"min": 0, "max": 65535},
}

EXPECTED_CLASSIFIER_FEATURE_COUNT = 10


# =============================================================================
# Feature Mapping Functions
# =============================================================================

def map_api_to_training_features(api_data: Dict) -> Dict:
    """
    Map API/NetworkFlow feature names to training feature names.

    Args:
        api_data: Dictionary with API-style feature names

    Returns:
        Dictionary with training-style feature names
    """
    result = {}
    for api_name, training_name in CLASSIFIER_FEATURE_MAPPING.items():
        if api_name in api_data:
            result[training_name] = api_data[api_name]
        elif training_name in api_data:
            # Already using training names
            result[training_name] = api_data[training_name]
    return result


def validate_and_clamp_features(features: Dict) -> Dict:
    """
    Validate and clamp feature values to reasonable bounds.
    Prevents adversarial inputs and ensures numerical stability.

    Args:
        features: Dictionary of feature values

    Returns:
        Dictionary with validated/clamped feature values
    """
    validated = {}
    for key, value in features.items():
        if key in FEATURE_BOUNDS:
            bounds = FEATURE_BOUNDS[key]
            validated[key] = min(max(bounds["min"], float(value or 0)), bounds["max"])
        else:
            validated[key] = value
    return validated


def extract_ordered_features(data: Dict, feature_list: List[str]) -> List[float]:
    """
    Extract features in the correct order for model input.

    Args:
        data: Dictionary containing feature values
        feature_list: List of feature names in required order

    Returns:
        List of feature values in correct order
    """
    return [float(data.get(f, 0)) for f in feature_list]
