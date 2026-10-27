import pandas as pd
from typing import Dict, Any, List

def timeline_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Timeline Analyst Agent: Normalizes multi-source events into an interleaved
    chronological sequence and highlights attack milestones.
    """
    raw_dfs = state.get("raw_dataframes", {})
    anomalies = state.get("anomalies", [])
    audit_msgs = list(state.get("audit_trail", []))

    timeline: List[Dict[str, Any]] = []

    # Map timestamps of anomalies to quickly flag them
    anomaly_timestamps = set()
    for anom in anomalies:
        if "timestamp" in anom:
            anomaly_timestamps.add(str(anom["timestamp"]).split(".")[0])

    # 1. Process Login events
    df_login = raw_dfs.get("login")
    if df_login is not None and not df_login.empty:
        for idx, row in df_login.iterrows():
            ts_str = str(row["timestamp"]).split(".")[0]
            is_anom = ts_str in anomaly_timestamps or row.get("status") == "FAILED"
            timeline.append({
                "timestamp": str(row["timestamp"]),
                "source": "AUTHENTICATION",
                "actor": str(row["user_id"]),
                "action": f"{row['event_type']} ({row['status']}) from IP {row['ip_address']}",
                "is_anomaly": is_anom,
                "severity": "HIGH" if is_anom else "NORMAL",
                "details": f"Device: {row.get('device_info', 'N/A')}, Country: {row.get('country', 'N/A')}"
            })

    # 2. Process File events
    df_file = raw_dfs.get("file")
    if df_file is not None and not df_file.empty:
        for idx, row in df_file.iterrows():
            sens = str(row.get("file_sensitivity", "")).upper()
            is_anom = sens in ["HIGH", "CRITICAL"] and str(row.get("action")).upper() == "DOWNLOAD"
            timeline.append({
                "timestamp": str(row["timestamp"]),
                "source": "FILE_SYSTEM",
                "actor": str(row["user_id"]),
                "action": f"{row['action']} on {row['file_path']}",
                "is_anomaly": is_anom,
                "severity": "CRITICAL" if is_anom else "NORMAL",
                "details": f"Sensitivity: {sens}, Bytes: {row.get('bytes_read', 0):,}"
            })

    # 3. Process Network events
    df_net = raw_dfs.get("network")
    if df_net is not None and not df_net.empty:
        for idx, row in df_net.iterrows():
            sent = int(row.get("bytes_sent", 0))
            is_anom = sent >= 50 * 1024 * 1024
            timeline.append({
                "timestamp": str(row["timestamp"]),
                "source": "NETWORK_FLOW",
                "actor": str(row["source_ip"]),
                "action": f"Outbound flow to {row['destination_ip']}:{row.get('dest_port', 443)}",
                "is_anomaly": is_anom,
                "severity": "CRITICAL" if is_anom else "NORMAL",
                "details": f"Transferred: {round(sent / (1024*1024), 2)} MB, Status: {row.get('connection_status', 'N/A')}"
            })

    # Sort chronological
    timeline = sorted(timeline, key=lambda x: str(x["timestamp"]))

    audit_msgs.append(f"[Timeline Analyst] Reconstructed chronological sequence of {len(timeline)} events.")

    return {
        "timeline": timeline,
        "audit_trail": audit_msgs
    }
