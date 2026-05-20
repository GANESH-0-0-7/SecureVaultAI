"""
Database initialization script
Run this script to create database tables and seed initial data
"""

import os
import sys
from app import create_app, db
from models import User, EncryptedFile, PasswordAnalysis, SecurityLog
from datetime import datetime

def init_database():
    """Initialize database"""
    app = create_app('development')

    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("✓ Database tables created successfully!")

        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("\nCreating demo admin user...")
            admin = User(
                username='admin',
                email='admin@securevault.local',
                theme='dark',
                is_active=True
            )
            admin.set_password('Admin@123456')
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created!")
            print("  Username: admin")
            print("  Password: Admin@123456")
            print("  Email: admin@securevault.local")

        print("\n✓ Database initialization complete!")
        print("\nYou can now run: python app.py")

if __name__ == '__main__':
    try:
        init_database()
    except Exception as e:
        print(f"✗ Error initializing database: {e}")
        sys.exit(1)
