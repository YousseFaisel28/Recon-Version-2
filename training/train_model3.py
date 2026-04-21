"""
Training Pipeline for Model 3 (Technology Vulnerability Detection)
===================================================================

Design:
- Features: TF-IDF (Name+Version) + Numeric (Max CVSS, CVE Count, Has Version)
- Label: 1 if Max CVSS >= 7.0 (High/Critical), else 0
- Models: LogisticRegression, DecisionTreeClassifier
- Ground Truth: Authoritative NVD Data

Output:
- models/artifacts/model3/model3_lr.pkl
- models/artifacts/model3/model3_dt.pkl
- models/artifacts/model3/model3_tfidf.pkl
- models/artifacts/model3/model3_metrics.json
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from scipy.sparse import hstack

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.nvd_api_tool import get_nvd_client

MODEL_DIR = os.path.join("models", "artifacts", "model3")
LR_MODEL_PATH = os.path.join(MODEL_DIR, "model3_lr.pkl")
DT_MODEL_PATH = os.path.join(MODEL_DIR, "model3_dt.pkl")
TFIDF_PATH = os.path.join(MODEL_DIR, "model3_tfidf.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "model3_metrics.json")

def create_fingerprint(tech_name, version):
    """Create text fingerprint for TF-IDF"""
    fingerprint = f"{tech_name.lower()} {version.lower()}"
    if version:
        version_parts = re.findall(r'\d+', version)
        fingerprint += " " + " ".join(version_parts)
    return fingerprint.strip()

def fetch_ground_truth_data():
    """
    Generate dataset using NVD API for ground truth labels.
    Returns DataFrame with features and labels.
    """
    print("[Data] Generating training dataset from NVD...")
    
    # List of technologies to build vocabulary and training examples
    tech_candidates = [
        # Vulnerable examples
        ("Apache", "2.4.49"), ("Apache", "2.4.50"), ("Log4j", "2.14.1"),
        ("WordPress", "5.8"), ("WordPress", "5.0"), ("PHP", "7.4.0"),
        ("OpenSSL", "1.0.1"), ("Struts", "2.3.5"), ("WebLogic", "10.3.6"),
        ("Tomcat", "9.0.0"), ("JBoss", "7.1.1"), ("Jenkins", "2.0"),
        ("Drupal", "7.0"), ("Joomla", "3.4.6"), ("Elasticsearch", "1.4.0"),
        ("Redis", "5.0.0"), ("MongoDB", "4.0.0"), ("PostgreSQL", "9.6.0"),
        ("MySQL", "5.6.20"), ("Exim", "4.92"),
        
        # Safe/Newer/Patched examples
        ("Apache", "2.4.52"), ("Log4j", "2.17.1"), ("WordPress", "6.4"),
        ("PHP", "8.2.0"), ("OpenSSL", "3.0.0"), ("Nginx", "1.24.0"),
        ("jQuery", "3.7.0"), ("React", "18.2.0"), ("Vue.js", "3.3.0"),
        ("Bootstrap", "5.3.0"), ("Django", "4.2"), ("Flask", "3.0"),
        ("Spring Boot", "3.1.0"), ("Node.js", "20.0.0"), ("Python", "3.12"),
        ("Go", "1.21"), ("Rust", "1.70"), ("Docker", "24.0.0"),
        ("Kubernetes", "1.27"), ("Terraform", "1.5.0")
    ]
    
    data = []
    client = get_nvd_client()
    
    print(f"[Data] Querying NVD for {len(tech_candidates)} technologies...")
    
    for name, ver in tech_candidates:
        try:
            df = client.lookup_technology_vulnerabilities(name, ver)
            max_cvss = 0.0
            cve_count = 0
            if df is not None and not df.empty:
                max_cvss = df["cvss_score"].max()
                cve_count = len(df)
            
            label = 1 if max_cvss >= 7.0 else 0
            data.append({
                "name": name,
                "version": ver,
                "fingerprint": create_fingerprint(name, ver),
                "max_cvss": max_cvss,
                "cve_count": cve_count,
                "has_version": 1 if ver else 0,
                "label": label
            })
        except Exception as e:
            print(f"  [X] Error fetching {name} {ver}: {e}")
            
    return pd.DataFrame(data)

def train_and_evaluate():
    """Train models and save artifacts"""
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    df = fetch_ground_truth_data()
    if df.empty:
        print("[Error] No training data generated.")
        return

    tfidf = TfidfVectorizer(max_features=100, ngram_range=(1, 2), stop_words='english')
    X_text = tfidf.fit_transform(df['fingerprint'])
    X_numeric = df[['max_cvss', 'cve_count', 'has_version']].values
    X = hstack([X_text, X_numeric])
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    lr_model = LogisticRegression(class_weight='balanced', max_iter=1000)
    lr_model.fit(X_train, y_train)
    
    dt_model = DecisionTreeClassifier(class_weight='balanced', max_depth=5, random_state=42)
    dt_model.fit(X_train, y_train)
    
    print("\n[Evaluation] Logistic Regression:")
    y_pred_lr = lr_model.predict(X_test)
    acc_lr = accuracy_score(y_test, y_pred_lr)
    print(f"  Accuracy: {acc_lr:.4f}")
    
    print("\n[Artifacts] Saving models...")
    joblib.dump(lr_model, LR_MODEL_PATH)
    joblib.dump(dt_model, DT_MODEL_PATH)
    joblib.dump(tfidf, TFIDF_PATH)
    
    metrics = {
        "dataset_size": len(df),
        "logistic_regression": {
            "accuracy": acc_lr,
            "f1": f1_score(y_test, y_pred_lr)
        }
    }
    
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"  Saved to {MODEL_DIR}")

if __name__ == "__main__":
    train_and_evaluate()
