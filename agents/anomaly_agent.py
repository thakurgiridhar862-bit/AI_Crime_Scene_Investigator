import importlib
from typing import Dict, Any, List
import forensic.detection_rules as rules_module

def anomaly_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Anomaly Detector Agent: Evaluates logs against heuristic intrusion rules
    and tags detections with standard MITRE ATT&CK techniques.
    """
    importlib.reload(rules_module)
    rules_engine = rules_module.ForensicRulesEngine

    raw_dfs = state.get("raw_dataframes", {})
    audit_msgs = list(state.get("audit_trail", []))

    anomalies = rules_engine.run_all(raw_dfs)

    crit_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in anomalies if a.get("severity") == "HIGH")

    audit_msgs.append(
        f"[Anomaly Detector] Analysis complete: {len(anomalies)} anomalies identified "
        f"({crit_count} Critical, {high_count} High)."
    )

    return {
        "anomalies": anomalies,
        "audit_trail": audit_msgs
    }
