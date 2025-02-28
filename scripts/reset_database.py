#!/usr/bin/env python3
import os
import sys
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from easy_cspm.core.db_manager import DBManager

def reset_database():
    """Reset the database completely"""
    # Check if database file exists
    db_file = "easy_cspm.db"
    if os.path.exists(db_file):
        print(f"Removing existing database: {db_file}")
        os.remove(db_file)

    # Create a new database with the schema
    print("Creating new database schema...")
    db = DBManager()
    db.init_db()
    print("Database has been reset successfully.")

if __name__ == "__main__":
    reset_database() 