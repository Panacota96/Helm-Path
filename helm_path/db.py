import sqlite3
import hashlib
import os
from datetime import datetime
from rich.console import Console

console = Console()

DB_FILE = "audit_log.db"

def init_db():
    """Initializes the tamper-evident audit database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            start_timestamp TEXT NOT NULL,
            end_timestamp TEXT NOT NULL,
            log_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            metadata TEXT
        )
    ''')
    conn.commit()
    conn.close()
    
    # Secure the DB file (read-only for non-root users if possible, but we are running as user)
    # Ideally, this would be owned by root and only writable by a privileged helper.
    if os.path.exists(DB_FILE):
        try:
            os.chmod(DB_FILE, 0o600)
        except Exception:
            pass

def get_last_hash():
    """Retrieves the hash of the last entry in the chain."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT current_hash FROM (SELECT id, log_hash as current_hash FROM audit_log ORDER BY id DESC LIMIT 1)')
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return "0" * 64 # Genesis hash

def calculate_chain_hash(session_id, start, end, log_hash, prev_hash):
    """Calculates the hash for the current entry, linking it to the previous one."""
    data = f"{session_id}{start}{end}{log_hash}{prev_hash}"
    return hashlib.sha256(data.encode()).hexdigest()

def insert_session(session_id, start_time, end_time, log_hash, metadata_json="{}"):
    """Inserts a new session into the audit log with hash chaining."""
    prev_hash = get_last_hash()
    
    # In this design, the 'current_hash' isn't stored explicitly as a column in the schema I drafted?
    # Wait, the verification relies on re-calculating the hash of the row content + prev_hash.
    # Let's verify the schema again. 
    # Schema: id, session_id, start, end, log_hash, previous_hash.
    # To verify: Hash(session_id + start + end + log_hash + previous_hash) should match the 'previous_hash' of the NEXT row?
    # No, usually we store the 'current_hash' too, or the 'previous_hash' of the next row acts as the validator.
    # Let's stick to the plan: "previous_hash (SHA-256 of the previous row's data)".
    
    # Actually, a better chain stores the *current* row's hash which includes the previous hash.
    # Let's update the schema slightly in my mind to include 'chain_hash' for easier verification.
    
    # Revised Schema for this function:
    # id, session_id, start, end, log_hash, previous_hash, chain_hash
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Check if we need to migrate/add chain_hash column if I strictly followed the plan prompt which might have missed it.
    # The plan said: "previous_hash (SHA-256 of the previous row's data - creates the chain)". 
    # It implied we calculate the current hash to be the *next* row's previous hash.
    # But storing it makes verification easier. I will add 'chain_hash'.
    
    # Re-init for safety if table doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            start_timestamp TEXT NOT NULL,
            end_timestamp TEXT NOT NULL,
            log_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL
        )
    ''')
    
    # Get last chain hash
    cursor.execute('SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1')
    row = cursor.fetchone()
    prev_chain_hash = row[0] if row else "0" * 64
    
    # Calculate current chain hash
    # Hash(This Row Data + Previous Chain Hash)
    current_data = f"{session_id}{start_time}{end_time}{log_hash}{prev_chain_hash}"
    current_chain_hash = hashlib.sha256(current_data.encode()).hexdigest()
    
    cursor.execute('''
        INSERT INTO audit_log (session_id, start_timestamp, end_timestamp, log_hash, previous_hash, chain_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (session_id, start_time, end_time, log_hash, prev_chain_hash, current_chain_hash))
    
    conn.commit()
    conn.close()
    return current_chain_hash

def verify_chain():
    """
    Verifies the integrity of the entire audit log chain.
    Returns (True, None) or (False, ErrorMessage).
    """
    if not os.path.exists(DB_FILE):
        return True, "No database found."
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT session_id, start_timestamp, end_timestamp, log_hash, previous_hash, chain_hash FROM audit_log ORDER BY id ASC')
    rows = cursor.fetchall()
    conn.close()
    
    expected_prev_hash = "0" * 64
    
    for i, row in enumerate(rows):
        session_id, start, end, log_hash, stored_prev, stored_chain = row
        
        # 1. Check if the stored 'previous_hash' matches what we expect
        if stored_prev != expected_prev_hash:
            return False, f"Broken Chain at Row {i+1} (Session {session_id}): Previous hash mismatch."
            
        # 2. Recalculate the chain hash for this row
        recalc_data = f"{session_id}{start}{end}{log_hash}{expected_prev_hash}"
        recalc_hash = hashlib.sha256(recalc_data.encode()).hexdigest()
        
        if recalc_hash != stored_chain:
            return False, f"Tampered Row {i+1} (Session {session_id}): Content does not match hash."
            
        # Update expectation for next row
        expected_prev_hash = recalc_hash
        
    return True, "Chain Verified. Integrity Intact."
