#!/usr/bin/env python3
"""
Database migration script for chat system
Adds file support fields to ChatMessage table
"""

import sqlite3
import os
from pathlib import Path

def migrate_chat_database():
    """Add file support fields to ChatMessage table"""
    
    # Database path
    db_path = Path(__file__).parent / 'instance' / 'eiki_tomobe.db'
    
    if not db_path.exists():
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check if file fields already exist
        cursor.execute("PRAGMA table_info(chat_message)")
        columns = [row[1] for row in cursor.fetchall()]
        
        migrations_needed = []
        
        if 'file_filename' not in columns:
            migrations_needed.append("ALTER TABLE chat_message ADD COLUMN file_filename VARCHAR(255)")
        
        if 'file_original_name' not in columns:
            migrations_needed.append("ALTER TABLE chat_message ADD COLUMN file_original_name VARCHAR(255)")
        
        if 'file_size' not in columns:
            migrations_needed.append("ALTER TABLE chat_message ADD COLUMN file_size INTEGER")
        
        if migrations_needed:
            print("Running database migrations...")
            for migration in migrations_needed:
                print(f"Executing: {migration}")
                cursor.execute(migration)
            
            conn.commit()
            print("Database migration completed successfully!")
        else:
            print("Database is already up to date.")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    migrate_chat_database()
