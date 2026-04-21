"""
ReconX - Model 4
HTTP / Traffic Anomaly Detection
Unsupervised Machine Learning Model
Algorithm: Isolation Forest
"""

import os
import joblib
import numpy as np


# Path setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "artifacts", "model4", "model4_iforest.pkl")

class HTTPAnomalyModel:
    def __init__(self, model_path=None):
        # Lazy import to avoid slow startup
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        self.model_path = model_path or DEFAULT_MODEL_PATH

        # Feature scaler
        self.scaler = StandardScaler()

        # Isolation Forest (REAL ML)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.1,
            random_state=42
        )

    # ==================================================
    # Feature Vector (NUMERICAL ONLY)
    # ==================================================
    def _vectorize(self, features: dict) -> np.ndarray:
        """
        Convert extracted HTTP features into ML vector
        """

        return np.array([
            features.get("missing_headers", 0),
            int(features.get("cors_wildcard", False)),
            int(features.get("server_exposed", False)),
            features.get("insecure_cookies", 0),
            features.get("response_size_kb", 0.0),
            features.get("error_rate", 0.0),
            features.get("status_entropy", 0.0),
            
            # --- Traffic Features (tcpdump) ---
            features.get("packet_count", 0),
            features.get("avg_packet_size", 0.0),
            features.get("tcp_syn_count", 0),
            features.get("udp_count", 0),
            features.get("unique_ips", 0)
        ]).reshape(1, -1)

    # ==================================================
    # TRAIN MODEL (RUN ONCE OFFLINE)
    # ==================================================
    def train(self, dataset: list):
        """
        dataset: list of feature dictionaries
        """

        X = np.vstack([self._vectorize(d) for d in dataset])
        X_scaled = self.scaler.fit_transform(X)

        self.model.fit(X_scaled)

        # Save model + scaler
        joblib.dump(
            (self.model, self.scaler),
            self.model_path
        )

        print("[OK] Model 4 trained and saved successfully")

    # ==================================================
    # LOAD TRAINED MODEL
    # ==================================================
    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                "[X] Model 4 is not trained yet. Train it first."
            )

        self.model, self.scaler = joblib.load(self.model_path)
        print("[OK] Model 4 loaded")

    # ==================================================
    # PREDICT ANOMALY
    # ==================================================
    def predict(self, features: dict) -> dict:
        """
        Input: feature dictionary from http_collector
        Output: anomaly score + label
        """

        X = self._vectorize(features)
        X_scaled = self.scaler.transform(X)

        anomaly_score = float(self.model.decision_function(X_scaled)[0])
        prediction = self.model.predict(X_scaled)[0]  # -1 = anomaly
        
        status = "suspicious" if prediction == -1 else "normal"
        justification = f"Classification as '{status}' is justified by a statistical anomaly score of {round(anomaly_score, 4)} indicating deviation from the learned traffic baseline."

        return {
            "model": "Model 4 - HTTP Anomaly Detection",
            "anomaly_score": round(anomaly_score, 4),
            "status": status,
            "justification": justification,
            "traffic_data": {
                "packet_count": features.get("packet_count", 0),
                "tcp_syn_count": features.get("tcp_syn_count", 0),
                "unique_ips": features.get("unique_ips", 0)
            }
        }

    # ==================================================
    # FACTUAL FINDINGS (NO HEURISTICS)
    # ==================================================
    def _signals(self, features: dict) -> list:
        signals = []

        if features.get("cors_wildcard", False):
            signals.append("CORS Policy: Wildcard (*) detected")

        if features.get("server_exposed", False):
            signals.append("Insecure Configuration: Server header disclosure")

        if features.get("insecure_cookies", 0) > 0:
            count = features.get("insecure_cookies")
            signals.append(f"Insecure Configuration: {count} cookies missing Secure/HttpOnly flags")

        if features.get("error_rate", 0.0) >= 0.5:
            signals.append("Stability: High HTTP error rate (>= 50%)")

        return signals
