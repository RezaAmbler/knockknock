#!/usr/bin/env python3
"""Create admin user"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from web.database import SessionLocal
from web.models.user import User, UserRole
from web.auth.security import get_password_hash

def create_admin(email: str, password: str):
    """Create admin user"""
    db = SessionLocal()
    try:
        # Check if user exists
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"❌ User with email {email} already exists")
            return

        # Create admin
        admin = User(
            email=email,
            password_hash=get_password_hash(password),
            role=UserRole.ADMIN
        )
        db.add(admin)
        db.commit()
        print(f"✅ Admin user created: {email}")
    finally:
        db.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Create admin user")
    parser.add_argument("--email", required=True, help="Admin email")
    parser.add_argument("--password", required=True, help="Admin password")
    args = parser.parse_args()

    create_admin(args.email, args.password)
