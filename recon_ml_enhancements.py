import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Any

# Scikit-Learn Imports
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler

# TensorFlow Imports (For Model 4)
try:
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import LSTM, Dense, Input
except ImportError:
    pass

# ==========================================
# MODEL 1: Subdomain Discovery (Clustering)
# Unsupervised Learning: KMeans
# ==========================================
def run_subdomain_clustering(subdomains: List[str], n_clusters: int = 3) -> Dict[str, Any]:
    """
    Extracts simple features from subdomains and uses KMeans to group them.
    Flags outliers (subdomains furthest from cluster centers).
    """
    if not subdomains or len(subdomains) < n_clusters:
        return {"clusters": {}, "anomalies": []}

    keywords = ['api', 'dev', 'admin', 'test', 'staging']
    
    # Feature Extraction
    features = []
    for sub in subdomains:
        length = len(sub)
        num_parts = sub.count('.')
        has_kw = 1 if any(kw in sub.lower() for kw in keywords) else 0
        features.append([length, num_parts, has_kw])
        
    X = np.array(features)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train KMeans
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    kmeans.fit(X_scaled)
    
    # Group results
    clusters = {i: [] for i in range(n_clusters)}
    distances = kmeans.transform(X_scaled)
    
    anomalies = []
    for idx, sub in enumerate(subdomains):
        label = kmeans.labels_[idx]
        clusters[label].append(sub)
        
        # Calculate distance to assigned center
        dist = distances[idx, label]
        # Flag as anomaly if distance is significantly high (e.g., > 2.0 std devs)
        if dist > 2.0:
            anomalies.append(sub)
            
    return {
        "clusters": clusters,
        "anomalies": anomalies
    }

# ==========================================
# MODEL 2: Service Classification
# Supervised Learning: Random Forest
# ==========================================
class ServiceClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.is_trained = False
        self._train_synthetic()

    def _train_synthetic(self):
        """Trains on a tiny synthetic dataset to avoid external dependencies."""
        # Features: [port, has_http, has_ssh, has_sql]
        X_train = np.array([
            [80, 1, 0, 0], [443, 1, 0, 0], [8080, 1, 0, 0], # Web
            [22, 0, 1, 0], [2222, 0, 1, 0],                 # Infra (SSH)
            [3306, 0, 0, 1], [5432, 0, 0, 1], [1433, 0, 0, 1] # Database
        ])
        # Labels: 0=Web, 1=Infra, 2=Database
        y_train = np.array([0, 0, 0, 1, 1, 2, 2, 2])
        
        self.model.fit(X_train, y_train)
        self.is_trained = True

    def _extract_features(self, port: int, banner: str) -> np.array:
        banner = banner.lower()
        has_http = 1 if 'http' in banner or port in [80, 443, 8080] else 0
        has_ssh = 1 if 'ssh' in banner or port == 22 else 0
        has_sql = 1 if 'sql' in banner or port in [3306, 5432] else 0
        return np.array([[port, has_http, has_ssh, has_sql]])

    def predict_service(self, port: int, banner: str) -> str:
        if not self.is_trained: return "Unknown"
        
        X = self._extract_features(port, banner)
        pred = self.model.predict(X)[0]
        
        mapping = {0: "Web Service", 1: "Infrastructure", 2: "Database"}
        return mapping.get(pred, "Unknown")

# ==========================================
# MODEL 3: Vulnerability Filtering
# Supervised Learning: Decision Tree Classifier
# ==========================================
class MLHeuristicFilter:
    def __init__(self):
        self.model = DecisionTreeClassifier(max_depth=3, random_state=42)
        self.is_trained = False
        self._train_synthetic()

    def _train_synthetic(self):
        """
        Trains on synthetic data mimicking Nuclei outputs.
        Features: [severity_level, has_cve, is_generic_matcher]
        severity_level: info=1, low=2, medium=3, high=4, crit=5
        """
        X_train = np.array([
            [5, 1, 0], [4, 1, 0], [3, 1, 0], # Real vulns (high sev, cve, specific)
            [1, 0, 1], [2, 0, 1], [1, 0, 0], # False positives (low sev, no cve, generic)
            [3, 0, 1]                        # Borderline false positive
        ])
        # Labels: 1 = Real Vulnerability, 0 = False Positive Noise
        y_train = np.array([1, 1, 1, 0, 0, 0, 0])
        
        self.model.fit(X_train, y_train)
        self.is_trained = True

    def predict_validity(self, vuln_data: Dict) -> int:
        """Returns 1 if real, 0 if false positive."""
        if not self.is_trained: return 1 # Default to keeping it

        info = vuln_data.get("info", {})
        sev_str = info.get("severity", "info").lower()
        sev_map = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        sev_level = sev_map.get(sev_str, 1)

        has_cve = 1 if info.get("classification", {}).get("cve-id") else 0
        matcher = vuln_data.get("matcher-name", "").lower()
        is_generic = 1 if "generic" in matcher or "detect" in matcher else 0

        X = np.array([[sev_level, has_cve, is_generic]])
        return self.model.predict(X)[0]

# ==========================================
# MODEL 4: Anomaly Detection
# Deep Learning: LSTM Autoencoder
# ==========================================
class LSTMAnomalyDetector:
    def __init__(self, input_dim: int = 2):
        self.input_dim = input_dim
        self.model = self._build_model()
        self.is_trained = False

    def _build_model(self):
        inputs = Input(shape=(1, self.input_dim))
        encoded = LSTM(16, activation='relu', return_sequences=False)(inputs)
        decoded = Dense(self.input_dim, activation='sigmoid')(encoded)
        model = Model(inputs, decoded)
        model.compile(optimizer='adam', loss='mse')
        return model

    def fit_predict(self, features: List[Tuple[float, float]], threshold_percentile: int = 95) -> List[int]:
        """
        Trains on the fly and predicts anomalies.
        Expects a list of [status_code, content_length].
        Returns a list of binary flags (1 = anomaly, 0 = normal).
        """
        if not features: return []
        
        data = np.array(features, dtype=np.float32)
        
        # Normalize to 0-1
        max_vals = np.max(data, axis=0)
        # Prevent divide by zero
        max_vals[max_vals == 0] = 1 
        data_normalized = data / max_vals
        
        data_reshaped = data_normalized.reshape((data.shape[0], 1, data.shape[1]))
        
        # Quick fit
        self.model.fit(data_reshaped, data_normalized, epochs=10, verbose=0)
        
        # Predict & Calculate MSE
        predictions = self.model.predict(data_reshaped)
        mse = np.mean(np.power(data_normalized - predictions, 2), axis=1)
        
        threshold = np.percentile(mse, threshold_percentile)
        
        return [1 if loss > threshold else 0 for loss in mse]

# ==========================================
# MODEL 5: Defensible Risk Scoring
# Supervised Learning: Linear Regression
# ==========================================
class MLRiskScorer:
    def __init__(self):
        # Using Linear Regression to keep the relationship extremely interpretable
        # It essentially learns the weights of CVSS, EPSS, and Exposure
        self.model = LinearRegression()
        self.is_trained = False
        self._train_synthetic()

    def _train_synthetic(self):
        """
        Synthetic data enforcing logical threat modeling.
        Features: [CVSS_Score, EPSS_Probability, Is_Exposed]
        """
        X_train = np.array([
            [9.8, 0.9, 1], # Critical, high prob, exposed -> High Risk
            [9.8, 0.9, 0], # Critical, high prob, internal -> Med-High
            [5.0, 0.1, 1], # Med, low prob, exposed -> Med
            [2.0, 0.0, 0], # Low, no prob, internal -> Low
            [7.5, 0.5, 1], # High, med prob, exposed -> High
        ])
        # Target Risk Scores (0-10 scale)
        y_train = np.array([9.5, 7.5, 4.0, 1.0, 8.0])
        
        self.model.fit(X_train, y_train)
        self.is_trained = True

    def predict_risk(self, cvss: float, epss: float, is_exposed: int) -> float:
        """Predicts the risk score. Clips output between 0.0 and 10.0"""
        if not self.is_trained: return cvss * epss # Fallback to standard math
        
        X = np.array([[cvss, epss, is_exposed]])
        pred_risk = self.model.predict(X)[0]
        
        # Constrain output bounds
        return round(max(0.0, min(10.0, pred_risk)), 2)

# ==========================================
# Integration Examples (Usage)
# ==========================================
if __name__ == "__main__":
    print("Testing Recon X ML Enhancements...")
    
    # Test Model 1
    subs = ["api.example.com", "dev.example.com", "www.example.com", "admin.example.com", "random123.example.com"]
    clustering_results = run_subdomain_clustering(subs)
    print(f"Model 1 Anomalies: {clustering_results['anomalies']}")
    
    # Test Model 2
    svc_classifier = ServiceClassifier()
    print(f"Model 2 Prediction (80): {svc_classifier.predict_service(80, 'apache httpd')}")
    
    # Test Model 3
    vuln_filter = MLHeuristicFilter()
    dummy_vuln = {"info": {"severity": "low"}, "matcher-name": "generic-detect"}
    print(f"Model 3 Prediction (Real=1, Noise=0): {vuln_filter.predict_validity(dummy_vuln)}")
    
    # Test Model 4
    lstm = LSTMAnomalyDetector()
    traffic = [(200, 1024), (200, 1048), (403, 500), (200, 1024), (500, 9999)]
    print(f"Model 4 Anomalies: {lstm.fit_predict(traffic)}")
    
    # Test Model 5
    risk_scorer = MLRiskScorer()
    print(f"Model 5 Risk (CVSS 9.8, EPSS 0.8, Exposed): {risk_scorer.predict_risk(9.8, 0.8, 1)}")
