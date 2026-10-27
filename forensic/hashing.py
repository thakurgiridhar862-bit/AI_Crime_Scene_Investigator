import hashlib
import os
from datetime import datetime
from typing import Union, Dict, Any
import io

def calculate_sha256(data: Union[bytes, str, io.BytesIO]) -> str:
    """
    Computes a SHA-256 cryptographic hex digest.
    Accepts raw bytes, file path (str), or BytesIO stream.
    """
    hasher = hashlib.sha256()
    
    if isinstance(data, bytes):
        hasher.update(data)
    elif isinstance(data, io.BytesIO):
        data.seek(0)
        while chunk := data.read(65536):
            hasher.update(chunk)
        data.seek(0)
    elif isinstance(data, str):
        if os.path.exists(data):
            with open(data, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
        else:
            hasher.update(data.encode("utf-8"))
    else:
        raise ValueError(f"Unsupported data type for hashing: {type(data)}")

    return hasher.hexdigest()

def verify_integrity(original_hash: str, current_data: Union[bytes, str, io.BytesIO]) -> bool:
    """Verifies whether current evidence matches the recorded custody hash."""
    return calculate_sha256(current_data).lower() == original_hash.lower()

def generate_custody_stamp(file_name: str, sha256_hash: str, size_bytes: int = 0) -> Dict[str, Any]:
    """Creates a verifiable Chain of Custody manifest record."""
    return {
        "file_name": file_name,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "integrity_status": "VERIFIED_AUTHENTIC"
    }
