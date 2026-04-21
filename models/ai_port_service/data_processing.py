import random
import pandas as pd
from typing import List, Dict

# Define common services, their standard ports, and typical banner fingerprints for generating synthetic data
SERVICE_PROFILES = [
    {"port": 80, "service": "Apache", "versions": ["2.4.41", "2.4.50", "2.2.0"], "keywords": ["http", "apache", "ubuntu", "debian", "html"]},
    {"port": 80, "service": "Nginx", "versions": ["1.18.0", "1.14.0", "1.21.0"], "keywords": ["http", "nginx", "welcome to nginx"]},
    {"port": 443, "service": "Apache", "versions": ["2.4.41", "2.4.50", "2.2.0"], "keywords": ["https", "apache", "ssl", "tls"]},
    {"port": 443, "service": "Nginx", "versions": ["1.18.0", "1.14.0"], "keywords": ["https", "nginx", "ssl"]},
    {"port": 21, "service": "vsftpd", "versions": ["3.0.3", "2.3.4"], "keywords": ["ftp", "vsftpd", "welcome to vsftpd"]},
    {"port": 21, "service": "ProFTPD", "versions": ["1.3.5", "1.3.1"], "keywords": ["ftp", "proftpd", "server ready"]},
    {"port": 22, "service": "OpenSSH", "versions": ["8.2p1", "7.6p1", "8.9p1"], "keywords": ["ssh", "openssh", "ubuntu", "protocol 2.0"]},
    {"port": 22, "service": "Dropbear", "versions": ["2019.78", "2020.81"], "keywords": ["ssh", "dropbear"]},
    {"port": 25, "service": "Postfix", "versions": ["3.4.13", "3.1.0"], "keywords": ["smtp", "postfix", "esmtp"]},
    {"port": 3306, "service": "MySQL", "versions": ["5.7.33", "8.0.23", "5.6.40"], "keywords": ["mysql", "mariadb", "caching_sha2_password", "mysql_native_password"]},
    {"port": 3306, "service": "MariaDB", "versions": ["10.5.15", "10.3.34"], "keywords": ["mysql", "mariadb", "ubuntu"]},
    {"port": 5432, "service": "PostgreSQL", "versions": ["12.6", "13.2", "10.15"], "keywords": ["postgresql", "psql", "fatal: password authentication failed"]},
    {"port": 27017, "service": "MongoDB", "versions": ["4.4.6", "5.0.0", "3.6.8"], "keywords": ["mongodb", "mongod", "requires authentication"]},
    {"port": 6379, "service": "Redis", "versions": ["6.0.9", "5.0.7"], "keywords": ["redis", "redis_version", "role:master"]},
    {"port": 8080, "service": "Tomcat", "versions": ["9.0.41", "8.5.61"], "keywords": ["http", "apache tomcat", "coyote"]},
    {"port": 3389, "service": "RDP", "versions": ["10.0", "6.1"], "keywords": ["rdp", "ms-wbt-server", "remote desktop"]},
    {"port": 53, "service": "BIND", "versions": ["9.11.3", "9.16.1"], "keywords": ["dns", "bind", "isc"]},
    {"port": 110, "service": "Dovecot", "versions": ["2.3.4", "2.2.33"], "keywords": ["pop3", "dovecot", "ready"]},
    {"port": 143, "service": "Dovecot", "versions": ["2.3.4", "2.2.33"], "keywords": ["imap", "dovecot", "imap4rev1"]}
]

def generate_synthetic_data(num_samples: int = 5000) -> pd.DataFrame:
    """
    Generate a synthetic dataset of port fingerprints for training the AI model.
    """
    data = []
    
    for _ in range(num_samples):
        # Pick a random template
        profile = random.choice(SERVICE_PROFILES)
        
        # 10% chance to simulate a non-standard port configuration
        actual_port = profile["port"]
        if random.random() < 0.1:
            actual_port = random.randint(1024, 65535)
            
        version = random.choice(profile["versions"])
        
        # Construct a synthetic banner
        num_keywords = random.randint(1, len(profile["keywords"]))
        selected_keywords = random.sample(profile["keywords"], num_keywords)
        
        # Add some noise to the banner
        noise = " "
        if random.random() < 0.3:
            noise = f" {random.randint(100, 999)} OK "
        
        banner = f"{profile['service']} {version} {noise} " + " ".join(selected_keywords)
        
        # Determine protocol
        protocol = "tcp"
        if profile["port"] == 53 and random.random() < 0.5:
            protocol = "udp"
            
        # Target Label
        label = f"{profile['service']} {version}"
        
        data.append({
            "port": actual_port,
            "banner": banner,
            "protocol": protocol,
            "state": "open",
            "label": label,
            "service": profile['service'],
            "version": version
        })
        
    return pd.DataFrame(data)

def prepare_data(df: pd.DataFrame):
    """
    Splits the data into features (X) and labels (y).
    """
    # Features dictionary representation so we can process it in feature extractor
    X = df[["port", "banner", "protocol", "state"]].to_dict(orient="records")
    y_full_label = df["label"].values
    
    return X, y_full_label

if __name__ == "__main__":
    # Test generation
    df = generate_synthetic_data(10)
    print(df.head())
