"""
Model training script for SentinelFlow.

Trains anomaly detection and classification models.
"""

import os
from pathlib import Path
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
import xgboost as xgb
from loguru import logger

from ml.src.preprocessing.data_loader import DataLoader
from ml.src.preprocessing.feature_engineering import FeatureEngineer


class ModelTrainer:
    """
    Trains ML models for network intrusion detection.
    """

    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.models = {}
        self.metrics = {}

    def train_anomaly_detector(
        self,
        X_train: pd.DataFrame,
        contamination: float = 0.1,
        **kwargs
    ) -> IsolationForest:
        """
        Train Isolation Forest for anomaly detection.

        Args:
            X_train: Training features
            contamination: Expected proportion of outliers
            **kwargs: Additional parameters for IsolationForest

        Returns:
            Trained IsolationForest model
        """
        logger.info("Training Isolation Forest anomaly detector...")

        model = IsolationForest(
            n_estimators=kwargs.get("n_estimators", 100),
            contamination=contamination,
            max_samples=kwargs.get("max_samples", "auto"),
            random_state=42,
            n_jobs=-1,
            verbose=1,
        )

        model.fit(X_train)

        # Store model
        self.models["anomaly_detector"] = model
        logger.info("Anomaly detector trained successfully")

        return model

    def train_classifier(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        model_type: str = "xgboost",
        **kwargs
    ) -> Any:
        """
        Train attack classifier.

        Args:
            X_train: Training features
            y_train: Training labels
            X_test: Test features
            y_test: Test labels
            model_type: 'xgboost' or 'random_forest'
            **kwargs: Additional parameters

        Returns:
            Trained classifier
        """
        logger.info(f"Training {model_type} classifier...")

        if model_type == "xgboost":
            # Encode labels
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            y_train_enc = le.fit_transform(y_train)
            y_test_enc = le.transform(y_test)

            model = xgb.XGBClassifier(
                n_estimators=kwargs.get("n_estimators", 100),
                max_depth=kwargs.get("max_depth", 6),
                learning_rate=kwargs.get("learning_rate", 0.1),
                objective="multi:softprob",
                tree_method="hist",  # GPU: use "gpu_hist"
                random_state=42,
                n_jobs=-1,
                verbosity=1,
            )

            model.fit(
                X_train, y_train_enc,
                eval_set=[(X_test, y_test_enc)],
                verbose=True
            )

            # Evaluate
            y_pred = model.predict(X_test)
            self._evaluate_classifier(y_test_enc, y_pred, le.classes_)

            # Store label encoder with model
            model.label_encoder = le

        else:  # Random Forest
            model = RandomForestClassifier(
                n_estimators=kwargs.get("n_estimators", 100),
                max_depth=kwargs.get("max_depth", None),
                random_state=42,
                n_jobs=-1,
                verbose=1,
            )

            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            self._evaluate_classifier(y_test, y_pred)

        self.models["classifier"] = model
        logger.info("Classifier trained successfully")

        return model

    def _evaluate_classifier(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        class_names: list = None
    ) -> Dict[str, float]:
        """Evaluate classifier and store metrics."""
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="weighted"
        )

        self.metrics["classifier"] = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        }

        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall: {recall:.4f}")
        logger.info(f"F1 Score: {f1:.4f}")

        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=class_names))

        return self.metrics["classifier"]

    def save_models(self, feature_engineer: FeatureEngineer = None) -> None:
        """Save all trained models to disk."""
        logger.info(f"Saving models to {self.model_dir}")

        for name, model in self.models.items():
            path = self.model_dir / f"{name}.joblib"
            joblib.dump(model, path)
            logger.info(f"Saved {name} to {path}")

        # Save feature engineer (scaler, encoders)
        if feature_engineer:
            joblib.dump(feature_engineer.scaler, self.model_dir / "scaler.joblib")
            joblib.dump(
                feature_engineer.feature_names,
                self.model_dir / "feature_names.joblib"
            )

            if hasattr(self.models.get("classifier", {}), "label_encoder"):
                le = self.models["classifier"].label_encoder
                attack_labels = {i: label for i, label in enumerate(le.classes_)}
                joblib.dump(attack_labels, self.model_dir / "attack_labels.joblib")

        # Save metrics
        joblib.dump(self.metrics, self.model_dir / "metrics.joblib")

        logger.info("All models saved successfully")

    def load_models(self) -> None:
        """Load models from disk."""
        logger.info(f"Loading models from {self.model_dir}")

        model_files = {
            "anomaly_detector": "anomaly_detector.joblib",
            "classifier": "classifier.joblib",
        }

        for name, filename in model_files.items():
            path = self.model_dir / filename
            if path.exists():
                self.models[name] = joblib.load(path)
                logger.info(f"Loaded {name}")


def main():
    """Main training pipeline."""
    logger.info("Starting SentinelFlow ML Training Pipeline")
    logger.info("=" * 50)

    # Initialize components
    loader = DataLoader(data_dir="data/raw")
    engineer = FeatureEngineer()
    trainer = ModelTrainer(model_dir="models")

    # Check for data
    logger.info("\nChecking for datasets...")
    datasets_found = False

    try:
        # Try loading CESNET for anomaly detection
        df_cesnet = loader.load_cesnet(aggregation="1h", sample_frac=0.1)
        datasets_found = True
        logger.info("CESNET dataset found!")
    except FileNotFoundError as e:
        logger.warning(str(e))

    try:
        # Try loading UWF for classification
        df_uwf = loader.load_uwf_zeek()
        datasets_found = True
        logger.info("UWF dataset found!")
    except FileNotFoundError as e:
        logger.warning(str(e))

    if not datasets_found:
        logger.error("\nNo datasets found!")
        logger.info("Please download the datasets first:")
        logger.info("1. CESNET-TimeSeries24: https://zenodo.org/records/13382427")
        logger.info("2. UWF-ZeekData22: https://datasets.uwf.edu/")
        logger.info("\nExtract to: data/raw/cesnet-timeseries24 and data/raw/uwf-zeekdata22")
        return

    # TODO: Add actual training logic when datasets are available
    logger.info("\nTraining pipeline ready!")
    logger.info("Implement training with your downloaded datasets.")


if __name__ == "__main__":
    main()
