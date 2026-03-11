import os
import shutil
import json
import hashlib
from helm_path.main import calculate_file_hash, clean_sensitive_data, load_metadata, save_metadata

def test_calculate_file_hash(tmp_path):
    # Setup: Create a temporary file with known content
    test_file = tmp_path / "test.log"
    content = b"The Watcher is Vigilant."
    test_file.write_bytes(content)
    
    # Calculate expected hash
    expected_hash = hashlib.sha256(content).hexdigest()
    
    # Test
    actual_hash = calculate_file_hash(str(test_file))
    assert actual_hash == expected_hash

def test_clean_sensitive_data():
    # Setup: Input string with secrets
    input_str = "Connecting with password=supersecret and --password secret123. API_KEY=abc-123"
    
    # Test
    cleaned = clean_sensitive_data(input_str)
    
    # Assert redactions
    assert "supersecret" not in cleaned
    assert "secret123" not in cleaned
    assert "abc-123" not in cleaned
    assert "[REDACTED]" in cleaned
    assert "password=[REDACTED]" in cleaned
    assert "--password [REDACTED]" in cleaned
    assert "API_KEY=[REDACTED]" in cleaned

def test_metadata_operations(tmp_path):
    # Setup: Create a temp session dir
    session_dir = tmp_path / "test_session"
    session_dir.mkdir()
    
    # Initial load (should return defaults)
    metadata = load_metadata(str(session_dir))
    assert metadata["session_id"] == "test_session"
    assert metadata["is_complete"] == False
    
    # Save modified metadata
    metadata["is_complete"] = True
    metadata["total_vigils"] = 1
    save_metadata(str(session_dir), metadata)
    
    # Reload and verify
    reloaded = load_metadata(str(session_dir))
    assert reloaded["is_complete"] == True
    assert reloaded["total_vigils"] == 1
