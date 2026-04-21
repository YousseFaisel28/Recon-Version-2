import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import List, Dict

class PortFeatureExtractor:
    """
    Transforms raw port fingerprints into numerical feature vectors.
    """
    def __init__(self, max_features=500):
        self.vectorizer = TfidfVectorizer(max_features=max_features, stop_words='english')
        self.is_fitted = False
        # Normalize scaling for port (e.g. max port is 65535)
        self.MAX_PORT = 65535.0

    def _preprocess_text(self, record: Dict) -> str:
        """
        Combines banner, protocol, and state into a single text representation
        for TF-IDF vectorization.
        """
        banner = str(record.get('banner', '')).lower()
        protocol = str(record.get('protocol', 'tcp')).lower()
        state = str(record.get('state', 'open')).lower()
        
        return f"{protocol} {state} {banner}"
        
    def fit(self, X: List[Dict]):
        """
        Fit the TF-IDF vectorizer on the training data.
        """
        texts = [self._preprocess_text(record) for record in X]
        self.vectorizer.fit(texts)
        self.is_fitted = True
        return self
        
    def transform(self, X: List[Dict]) -> np.ndarray:
        """
        Transform raw port data into feature vectors.
        Output shape: (n_samples, n_features)
        where n_features = 1 (port length) + len(tfidf_vocab)
        """
        if not self.is_fitted:
            raise ValueError("Feature extractor is not fitted yet.")
            
        texts = [self._preprocess_text(record) for record in X]
        tfidf_features = self.vectorizer.transform(texts).toarray()
        
        # Extract numerical features: normalize port
        numerical_features = []
        for record in X:
            port = float(record.get('port', 0)) / self.MAX_PORT
            numerical_features.append([port])
            
        numerical_features = np.array(numerical_features)
        
        # Combine numerical and tfidf features
        combined_features = np.hstack((numerical_features, tfidf_features))
        return combined_features

    def fit_transform(self, X: List[Dict]) -> np.ndarray:
        self.fit(X)
        return self.transform(X)
