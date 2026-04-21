"""
Utility script to (re)seed the admin account in MongoDB.

Usage (set environment variables before running):

    export ADMIN_EMAIL="reconx@gmail.com"
    export ADMIN_PASSWORD="reconx1234"
    python -m utils.seed_admin

This script:
  - Reads ADMIN_EMAIL and ADMIN_PASSWORD from environment variables.
  - Hashes the password using Werkzeug's generate_password_hash (PBKDF2).
  - Upserts a user with role "admin" into the users collection.
"""

import os
import datetime

from werkzeug.security import generate_password_hash

from config.database import connect_mongodb, users_collection


def seed_admin() -> None:
    # Connect to MongoDB (uses same settings as the app)
    connect_mongodb()

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        raise SystemExit(
            "ADMIN_EMAIL and ADMIN_PASSWORD environment variables must be set before running seed_admin."
        )

    password_hash = generate_password_hash(admin_password)

    result = users_collection.update_one(
        {"email": admin_email},
        {
            "$set": {
                "email": admin_email,
                "username": "Admin",
                "password": password_hash,
                "role": "admin",
                "status": "active",
                "updated_at": datetime.datetime.utcnow(),
            },
            "$setOnInsert": {
                "created_at": datetime.datetime.utcnow(),
            },
        },
        upsert=True,
    )

    if result.upserted_id:
        print(f"[seed_admin] Created new admin user with email {admin_email}")
    else:
        print(f"[seed_admin] Updated existing admin user with email {admin_email}")


if __name__ == "__main__":
    seed_admin()

