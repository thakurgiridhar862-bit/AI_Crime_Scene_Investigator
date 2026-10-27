import os
import sys

# Ensure root directory is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import pandas as pd
from forensic.hashing import calculate_sha256, verify_integrity
from forensic.parser import ForensicParser
from forensic.detection_rules import ForensicRulesEngine
from agents.orchestrator import run_investigation

def test_hashing():
    sample_text = "evidence_tamper_test_data"
    h1 = calculate_sha256(sample_text)
    assert len(h1) == 64
    assert verify_integrity(h1, sample_text) is True
    assert verify_integrity(h1, "modified_data") is False

def test_detection_engine():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    login_path = os.path.join(base_dir, "data", "demo_case", "login_logs.csv")
    file_path = os.path.join(base_dir, "data", "demo_case", "file_access.csv")
    net_path = os.path.join(base_dir, "data", "demo_case", "network_logs.csv")

    df_login = ForensicParser.parse_login_logs(login_path)
    df_file = ForensicParser.parse_file_logs(file_path)
    df_net = ForensicParser.parse_network_logs(net_path)

    dfs = {"login": df_login, "file": df_file, "network": df_net}
    anomalies = ForensicRulesEngine.run_all(dfs)

    assert len(anomalies) >= 3
    severities = [a["severity"] for a in anomalies]
    assert "CRITICAL" in severities
    assert "HIGH" in severities

def test_langgraph_swarm():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    login_path = os.path.join(base_dir, "data", "demo_case", "login_logs.csv")
    file_path = os.path.join(base_dir, "data", "demo_case", "file_access.csv")
    net_path = os.path.join(base_dir, "data", "demo_case", "network_logs.csv")

    files = {
        "login": login_path,
        "file": file_path,
        "network": net_path
    }

    state = run_investigation("TEST-CASE-001", files, "Integration Test Case")

    assert len(state["evidence_files"]) == 3
    assert len(state["anomalies"]) >= 3
    assert len(state["correlations"]) >= 1
    assert len(state["timeline"]) >= 5
    assert state["report"]["case_id"] == "TEST-CASE-001"
    assert "100% VERIFIED" in state["report"]["chain_of_custody_status"]

if __name__ == "__main__":
    test_hashing()
    test_detection_engine()
    test_langgraph_swarm()
    print("All forensic engine & LangGraph Swarm tests PASSED successfully!")
