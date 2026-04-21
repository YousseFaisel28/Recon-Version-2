import pandas as pd
import numpy as np
import os
import sys

# Ensure project root is in path for imports
sys.path.append(os.getcwd())

from models.model6_vulnerability_risk import Model6RiskScorer

def generate_synthetic_data(file_path, n_samples=500):
    """
    Generates a synthetic vulnerability dataset for training Model 6.
    """
    np.random.seed(42)
    data = []
    
    services = ['Apache', 'Nginx', 'IIS', 'SSH', 'MySQL', 'Redis']
    tech_stacks = ['PHP', 'Python', 'NodeJS', 'Java', 'Go']
    
    for _ in range(n_samples):
        cvss = np.random.uniform(0, 10)
        exploit = 1 if cvss > 7 or np.random.random() > 0.8 else 0
        subdomains = np.random.randint(1, 100)
        exposed_services = np.random.randint(0, subdomains // 2 + 1)
        is_public = 1 if np.random.random() > 0.3 else 0
        anomaly = 1 if np.random.random() > 0.9 else 0
        traffic_score = np.random.uniform(0, 1)
        misconfig = 1 if np.random.random() > 0.85 else 0
        
        # Realistic severity mapping based on user requirements
        if cvss >= 9.0:
            label = 3 # Critical
        elif cvss >= 7.0:
            label = 2 # High
        elif cvss >= 4.0:
            label = 1 # Medium
        else:
            label = 0 # Low
            
        # Slightly nudge label based on other features (simulating ML features)
        if label < 3 and exploit == 1 and cvss > 6:
            label += 1 # Upgrade risk if exploit is available
        if label > 0 and cvss < 4 and exploit == 0:
            label -= 1 # Downgrade risk if no exploit and low CVSS
            
        data.append({
            'domain': 'example.com',
            'subdomain': f'sub{np.random.randint(1,100)}.example.com',
            'service_name': np.random.choice(services),
            'port_number': np.random.choice([80, 443, 22, 3306, 6379]),
            'cvss_score': cvss,
            'exploit_available': exploit,
            'cve_id': f'CVE-202{np.random.randint(0,5)}-{np.random.randint(1000,9999)}',
            'technology_stack': np.random.choice(tech_stacks),
            'is_public_port': is_public,
            'anomaly_flag': anomaly,
            'traffic_anomaly_score': traffic_score,
            'misconfiguration_flag': misconfig,
            'subdomain_count': subdomains,
            'exposed_service_count': exposed_services,
            'risk_label': label # Target variable
        })
        
    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    df.to_csv(file_path, index=False)
    print(f"Dataset generated at {file_path}")

def run_training():
    data_dir = "data"
    data_file = os.path.join(data_dir, "vulnerability_dataset.csv")
    
    # Check if data exists, if not generate it
    if not os.path.exists(data_file):
        print("Data directory or file not found. Generating synthetic data...")
        generate_synthetic_data(data_file)
    
    # Load dataset
    print(f"Loading dataset from {data_file}")
    df = pd.read_csv(data_file)
    
    # Initialize scorer
    scorer = Model6RiskScorer()
    
    # Train
    print("Starting Model 6 training (XGBoost)...")
    scorer.train(df)
    
    # Save model
    scorer.save_model()
    
    print("Training finished successfully.")

if __name__ == "__main__":
    run_training()
