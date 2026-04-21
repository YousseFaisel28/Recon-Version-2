"""
Database configuration and connection management
"""

import os
import time
from pymongo import MongoClient
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/reconx_db")

MAX_RETRIES = 3
RETRY_DELAY = 2
CONNECTION_TIMEOUT = 10000

client: Optional[MongoClient] = None
db = None

users_collection = None
domains_collection = None
reports_collection = None
user_logs_collection = None
subdomains_collection = None
technologies_collection = None
vulnerabilities_collection = None
anomalies_collection = None   # 🔥 REQUIRED
recommendations_collection = None  # Model 7
audit_logs_collection = None  # Audit Logs (tamper-resistant)


def connect_mongodb():
    global client, db
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection, recommendations_collection
    global audit_logs_collection

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Connecting to MongoDB (attempt {attempt+1})")

            client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=CONNECTION_TIMEOUT,
                connectTimeoutMS=CONNECTION_TIMEOUT,
                socketTimeoutMS=CONNECTION_TIMEOUT
            )

            client.server_info()
            logger.info("MongoDB connected successfully")

            db = client["reconx_db"]

            users_collection = db["users"]
            domains_collection = db["domains"]
            reports_collection = db["reports"]
            user_logs_collection = db["user_logs"]
            subdomains_collection = db["subdomains"]
            technologies_collection = db["technologies"]
            vulnerabilities_collection = db["vulnerabilities"]
            anomalies_collection = db["anomalies"]  # Model 4
            recommendations_collection = db["recommendations"]  # Model 7
            audit_logs_collection = db["audit_logs"]  # Audit Logs

            # ── Create indexes for query performance ──
            try:
                users_collection.create_index("email", unique=True)
                reports_collection.create_index([("user_id", 1), ("scanned_at", -1)])
                reports_collection.create_index([("domain", 1), ("scanned_at", -1)])
                subdomains_collection.create_index([("domain", 1), ("subdomain", 1)])
                technologies_collection.create_index([("domain", 1), ("subdomain", 1)])
                anomalies_collection.create_index([("domain", 1), ("subdomain", 1)])
                audit_logs_collection.create_index([("timestamp", -1)])
                audit_logs_collection.create_index("action")
                logger.info("MongoDB indexes ensured")
            except Exception as e:
                logger.warning(f"Index creation error (non-fatal): {e}")

            return True

        except Exception as e:
            logger.error(f"MongoDB error: {e}")
            time.sleep(RETRY_DELAY)

    logger.warning("MongoDB OFFLINE — using dummy collections")
    _init_dummy_collections()
    return False


def _init_dummy_collections():
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection, recommendations_collection
    global audit_logs_collection

    class DummyCollection:
        def find_one(self, *a, **k): return None
        def find(self, *a, **k): return []
        def insert_one(self, *a, **k): return None
        def update_one(self, *a, **k): return None
        def delete_one(self, *a, **k): return None

    users_collection = DummyCollection()
    domains_collection = DummyCollection()
    reports_collection = DummyCollection()
    user_logs_collection = DummyCollection()
    subdomains_collection = DummyCollection()
    technologies_collection = DummyCollection()
    vulnerabilities_collection = DummyCollection()
    anomalies_collection = DummyCollection()   # 🔥 REQUIRED
    recommendations_collection = DummyCollection()
    audit_logs_collection = DummyCollection()


def is_mongodb_connected():
    if not client:
        return False
    try:
        client.server_info()
        return True
    except:
        return False
