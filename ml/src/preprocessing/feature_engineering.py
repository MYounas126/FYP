"""
Feature engineering for network traffic data.

Extracts and transforms features for ML models.
"""

from typing import List, Optional, Tuple

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from loguru import logger


class FeatureEngineer:
    """
    Feature engineering pipeline for network traffic data.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []

    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract flow-level features from raw traffic data.

        Args:
            df: Raw traffic DataFrame

        Returns:
            DataFrame with engineered features
        """
        logger.info("Extracting flow features...")

        features = pd.DataFrame()

        # Basic features
        if "bytes_sent" in df.columns and "bytes_received" in df.columns:
            features["total_bytes"] = df["bytes_sent"] + df["bytes_received"]
            features["bytes_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1)

        if "packets_sent" in df.columns and "packets_received" in df.columns:
            features["total_packets"] = df["packets_sent"] + df["packets_received"]
            features["packets_ratio"] = df["packets_sent"] / (df["packets_received"] + 1)

        # Duration features
        if "duration" in df.columns:
            features["duration"] = df["duration"]
            if "total_bytes" in features.columns:
                features["bytes_per_second"] = features["total_bytes"] / (df["duration"] + 0.001)
            if "total_packets" in features.columns:
                features["packets_per_second"] = features["total_packets"] / (df["duration"] + 0.001)

        # Port features
        if "src_port" in df.columns:
            features["src_port"] = df["src_port"].fillna(0)
            features["src_port_category"] = pd.cut(
                features["src_port"],
                bins=[0, 1024, 49152, 65535],
                labels=["well_known", "registered", "dynamic"]
            ).astype(str)

        if "dst_port" in df.columns:
            features["dst_port"] = df["dst_port"].fillna(0)
            features["dst_port_category"] = pd.cut(
                features["dst_port"],
                bins=[0, 1024, 49152, 65535],
                labels=["well_known", "registered", "dynamic"]
            ).astype(str)

        # Protocol encoding
        if "protocol" in df.columns:
            features["protocol"] = df["protocol"]

        # TTL features (if available)
        if "ttl" in df.columns:
            features["ttl"] = df["ttl"]
            features["ttl_normalized"] = df["ttl"] / 255

        # TCP flags (if available)
        if "flags" in df.columns:
            features["has_syn"] = df["flags"].str.contains("S", na=False).astype(int)
            features["has_ack"] = df["flags"].str.contains("A", na=False).astype(int)
            features["has_fin"] = df["flags"].str.contains("F", na=False).astype(int)
            features["has_rst"] = df["flags"].str.contains("R", na=False).astype(int)
            features["has_psh"] = df["flags"].str.contains("P", na=False).astype(int)

        logger.info(f"Extracted {len(features.columns)} features")
        return features

    def extract_time_features(self, df: pd.DataFrame, time_col: str = "timestamp") -> pd.DataFrame:
        """
        Extract temporal features from timestamp.

        Args:
            df: DataFrame with timestamp column
            time_col: Name of timestamp column

        Returns:
            DataFrame with time features
        """
        logger.info("Extracting time features...")

        if time_col not in df.columns:
            logger.warning(f"Time column '{time_col}' not found")
            return pd.DataFrame()

        ts = pd.to_datetime(df[time_col])

        features = pd.DataFrame({
            "hour": ts.dt.hour,
            "day_of_week": ts.dt.dayofweek,
            "is_weekend": (ts.dt.dayofweek >= 5).astype(int),
            "is_business_hours": ((ts.dt.hour >= 9) & (ts.dt.hour <= 17)).astype(int),
        })

        # Cyclical encoding
        features["hour_sin"] = np.sin(2 * np.pi * ts.dt.hour / 24)
        features["hour_cos"] = np.cos(2 * np.pi * ts.dt.hour / 24)
        features["dow_sin"] = np.sin(2 * np.pi * ts.dt.dayofweek / 7)
        features["dow_cos"] = np.cos(2 * np.pi * ts.dt.dayofweek / 7)

        return features

    def encode_categorical(
        self,
        df: pd.DataFrame,
        columns: List[str],
        fit: bool = True
    ) -> pd.DataFrame:
        """
        Encode categorical columns.

        Args:
            df: Input DataFrame
            columns: Columns to encode
            fit: Whether to fit new encoders

        Returns:
            DataFrame with encoded columns
        """
        result = df.copy()

        for col in columns:
            if col not in df.columns:
                continue

            if fit:
                self.label_encoders[col] = LabelEncoder()
                result[f"{col}_encoded"] = self.label_encoders[col].fit_transform(
                    df[col].astype(str)
                )
            else:
                if col in self.label_encoders:
                    # Handle unseen categories
                    known = set(self.label_encoders[col].classes_)
                    result[f"{col}_encoded"] = df[col].apply(
                        lambda x: self.label_encoders[col].transform([x])[0]
                        if x in known else -1
                    )

        return result

    def scale_features(
        self,
        df: pd.DataFrame,
        columns: Optional[List[str]] = None,
        fit: bool = True
    ) -> pd.DataFrame:
        """
        Scale numerical features.

        Args:
            df: Input DataFrame
            columns: Columns to scale (default: all numeric)
            fit: Whether to fit the scaler

        Returns:
            DataFrame with scaled features
        """
        if columns is None:
            columns = df.select_dtypes(include=[np.number]).columns.tolist()

        result = df.copy()

        if fit:
            result[columns] = self.scaler.fit_transform(df[columns])
        else:
            result[columns] = self.scaler.transform(df[columns])

        return result

    def prepare_dataset(
        self,
        df: pd.DataFrame,
        target_col: Optional[str] = None,
        test_size: float = 0.2
    ) -> Tuple[pd.DataFrame, pd.DataFrame, Optional[pd.Series], Optional[pd.Series]]:
        """
        Full preprocessing pipeline.

        Args:
            df: Raw DataFrame
            target_col: Name of target column (if supervised)
            test_size: Test set fraction

        Returns:
            X_train, X_test, y_train, y_test
        """
        from sklearn.model_selection import train_test_split

        logger.info("Preparing dataset...")

        # Extract features
        flow_features = self.extract_flow_features(df)
        time_features = self.extract_time_features(df)

        # Combine features
        X = pd.concat([flow_features, time_features], axis=1)

        # Encode categoricals
        cat_cols = X.select_dtypes(include=["object", "category"]).columns.tolist()
        if cat_cols:
            X = self.encode_categorical(X, cat_cols)
            # Drop original categorical columns
            X = X.drop(columns=cat_cols, errors="ignore")

        # Handle missing values
        X = X.fillna(0)

        # Extract target
        y = None
        if target_col and target_col in df.columns:
            y = df[target_col]

        # Scale features
        numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
        X = self.scale_features(X, numeric_cols)

        # Store feature names
        self.feature_names = X.columns.tolist()

        # Split
        if y is not None:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")
            return X_train, X_test, y_train, y_test
        else:
            X_train, X_test = train_test_split(X, test_size=test_size, random_state=42)
            return X_train, X_test, None, None
