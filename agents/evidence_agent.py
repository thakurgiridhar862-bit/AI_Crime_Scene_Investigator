import importlib
from typing import Dict, Any, List
from forensic.hashing import calculate_sha256, generate_custody_stamp
import forensic.parser as parser_module

def evidence_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evidence Analyst Agent: Computes cryptographic SHA-256 hashes for all files,
    establishes Chain of Custody, and normalizes logs into DataFrames.
    """
    # Hot-reload parser to ensure latest schema rules are applied
    importlib.reload(parser_module)
    parser = parser_module.ForensicParser

    evidence_files: List[Dict[str, Any]] = []
    raw_dfs: Dict[str, Any] = {}
    audit_msgs: List[str] = list(state.get("audit_trail", []))

    input_files = state.get("input_files", {})

    for file_key, file_data in input_files.items():
        if file_data is None:
            continue

        # Extract bytes or path
        if hasattr(file_data, "getvalue"):  # Streamlit UploadedFile
            raw_bytes = file_data.getvalue()
            name = getattr(file_data, "name", f"{file_key}.csv")
            size = len(raw_bytes)
            sha256 = calculate_sha256(raw_bytes)
            parse_input = raw_bytes
        elif isinstance(file_data, str):  # File path
            name = file_data.split("/")[-1].split("\\")[-1]
            sha256 = calculate_sha256(file_data)
            size = 0
            parse_input = file_data
        elif isinstance(file_data, bytes):
            name = f"{file_key}.csv"
            sha256 = calculate_sha256(file_data)
            size = len(file_data)
            parse_input = file_data
        else:
            continue

        stamp = generate_custody_stamp(name, sha256, size)
        stamp["source_type"] = file_key
        evidence_files.append(stamp)
        audit_msgs.append(f"[Evidence Analyst] Cryptographically verified {name} (SHA-256: {sha256[:12]}...)")

        # Parse into DataFrame
        try:
            if file_key == "login":
                df_parsed = parser.parse_login_logs(parse_input)
                raw_dfs["login"] = df_parsed
                audit_msgs.append(f"[Evidence Analyst] Normalized {len(df_parsed)} authentication records.")
            elif file_key == "file":
                df_parsed = parser.parse_file_logs(parse_input)
                raw_dfs["file"] = df_parsed
                audit_msgs.append(f"[Evidence Analyst] Normalized {len(df_parsed)} file system audit records.")
            elif file_key == "network":
                df_parsed = parser.parse_network_logs(parse_input)
                raw_dfs["network"] = df_parsed
                audit_msgs.append(f"[Evidence Analyst] Normalized {len(df_parsed)} NetFlow connection records.")
        except Exception as e:
            audit_msgs.append(f"[Evidence Analyst] Warning: Failed parsing {file_key} - {str(e)}")

    return {
        "evidence_files": evidence_files,
        "raw_dataframes": raw_dfs,
        "audit_trail": audit_msgs
    }
