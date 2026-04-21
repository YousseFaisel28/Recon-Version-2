import os
import joblib
from typing import List, Dict

# Configuration paths
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "saved_models", "ai_port_service")

class PortServicePredictor:
    """
    Loads trained models and predicts port service + version information based on fingerprints.
    """
    def __init__(self, model_type="rf"):
        """
        Initializes the predictor, loading the appropriate model from disk.
        Args:
            model_type: either 'rf' (Random Forest) or 'svm' (Support Vector Machine)
        """
        self.extractor_path = os.path.join(MODELS_DIR, "feature_extractor.pkl")
        
        if model_type == "svm":
            self.model_path = os.path.join(MODELS_DIR, "svm_model.pkl")
        else:
            self.model_path = os.path.join(MODELS_DIR, "rf_model.pkl")
            
        self.extractor = None
        self.model = None
        self._load_models()
        
    def _load_models(self):
        """Loads models if they exist."""
        if not os.path.exists(self.model_path) or not os.path.exists(self.extractor_path):
            raise FileNotFoundError(f"Model or extractor not found in {MODELS_DIR}. Please run model_training.py first.")
            
        self.extractor = joblib.load(self.extractor_path)
        self.model = joblib.load(self.model_path)
        
    def predict(self, fingerprints: List[Dict]) -> List[Dict]:
        """
        Predicts services for a list of port fingerprints.
        
        Args:
            fingerprints: List of dictionaries e.g. [{"port": 80, "protocol": "tcp", "state": "open", "banner": "Apache 2.4.41"}]
            
        Returns:
            List of structured dictionaries representing the AI predictions.
        """
        if not fingerprints:
            return []
            
        # Extract features using the loaded trained Tfidf extractor
        features = self.extractor.transform(fingerprints)
        
        # Predict class index and probabilities
        predicted_classes = self.model.predict(features)
        
        # Extract confidence scores
        # Returns probability for all classes, we take the max
        probabilities = self.model.predict_proba(features)
        confidences = probabilities.max(axis=1)
        
        results = []
        for i, fingerprint in enumerate(fingerprints):
            port = fingerprint.get("port")
            
            # The label is combined e.g., "Apache 2.4.41"
            predicted_label = predicted_classes[i]
            
            # Simple split by first space (Service Version)
            parts = predicted_label.split(" ", 1)
            service = parts[0]
            version = parts[1] if len(parts) > 1 else "Unknown"
            
            results.append({
                "port": int(port),
                "service": service,
                "version": version,
                "confidence": round(float(confidences[i]), 4)
            })
            
        return results

# Convenience singleton-like instance
_default_predictor = None

def get_predict_service(fingerprints: List[Dict], model_type="rf") -> List[Dict]:
    """Helper method to load predictor once or on-demand and perform prediction."""
    global _default_predictor
    if _default_predictor is None:
        try:
            _default_predictor = PortServicePredictor(model_type=model_type)
        except FileNotFoundError:
            # Fallback handling in case model is not trained yet (development/first run)
            return []
            
    return _default_predictor.predict(fingerprints)
