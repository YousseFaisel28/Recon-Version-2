import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from models.ai_port_service.data_processing import generate_synthetic_data, prepare_data
from models.ai_port_service.feature_extraction import PortFeatureExtractor

# Configuration
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "saved_models", "ai_port_service")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
SVM_MODEL_PATH = os.path.join(MODELS_DIR, "svm_model.pkl")
EXTRACTOR_PATH = os.path.join(MODELS_DIR, "feature_extractor.pkl")

def evaluate_model(model_name: str, y_true, y_pred):
    """Prints evaluation metrics."""
    print(f"\n--- {model_name} Evaluation ---")
    acc = accuracy_score(y_true, y_pred)
    # Using weighted average for multiclass metrics
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    return acc, prec, rec, f1

def train_and_evaluate():
    """
    Main training pipeline to generate data, extract features, train models, and evaluate them.
    """
    print("[*] Generating simulated training data (10000 samples)...")
    df = generate_synthetic_data(10000)
    X_raw, y = prepare_data(df)
    
    # Split raw data
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(X_raw, y, test_size=0.2, random_state=42)
    
    print("[*] Extracting features (TF-IDF + Port normalizer)...")
    extractor = PortFeatureExtractor(max_features=500)
    X_train = extractor.fit_transform(X_train_raw)
    X_test = extractor.transform(X_test_raw)
    
    # Check directory exists
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR, exist_ok=True)
    
    # Train Random Forest
    print("[*] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)
    evaluate_model("Random Forest", y_test, y_pred_rf)
    
    # Train SVM
    print("[*] Training Support Vector Machine (SVM)...")
    svm_model = SVC(kernel='rbf', probability=True, random_state=42)
    svm_model.fit(X_train, y_train)
    y_pred_svm = svm_model.predict(X_test)
    evaluate_model("SVM", y_test, y_pred_svm)
    
    # Save the best models and extractor
    print("\n[*] Saving models and feature extractor to disk...")
    joblib.dump(rf_model, RF_MODEL_PATH)
    joblib.dump(svm_model, SVM_MODEL_PATH)
    joblib.dump(extractor, EXTRACTOR_PATH)
    
    print(f"[*] Models successfully exported to {MODELS_DIR}")

if __name__ == "__main__":
    train_and_evaluate()
