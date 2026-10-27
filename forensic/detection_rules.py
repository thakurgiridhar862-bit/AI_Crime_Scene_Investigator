import pandas as pd
from typing import List, Dict, Any

class ForensicRulesEngine:
    """Enterprise-grade heuristics and MITRE ATT&CK detection algorithms."""

    SENSITIVE_PATH_KEYWORDS = [
        "confidential", "restricted", "classified", "source_code", 
        "firmware", "unreleased", "sec_financial", "payroll", 
        "ssn", "vault", ".kdbx", ".tar.gz", ".bak"
    ]

    @classmethod
    def detect_suspicious_logins(cls, df_logins: pd.DataFrame) -> List[Dict[str, Any]]:
        anomalies = []
        if df_logins is None or df_logins.empty:
            return anomalies

        df = df_logins.copy()
        df["hour"] = df["timestamp"].dt.hour

        # Check for multiple failed logins (Brute Force)
        failed_counts = df[df["status"] == "FAILED"].groupby("ip_address").size()
        for ip, count in failed_counts.items():
            if count >= 2:
                row_match = df[df["ip_address"] == ip].iloc[0]
                anomalies.append({
                    "finding_id": f"ANOM-BRUTE-{ip.replace('.', '_')}",
                    "evidence_source": "login_logs.csv",
                    "timestamp": str(row_match["timestamp"]),
                    "severity": "HIGH",
                    "mitre_technique": "T1110 (Brute Force)",
                    "description": f"Repeated failed authentication attempts ({count} failures) detected from remote IP {ip}",
                    "entities_involved": {"ip": ip, "user": str(row_match.get("user_id", "Unknown"))},
                    "raw_row_index": int(df[df["ip_address"] == ip].index[0])
                })

        for idx, row in df.iterrows():
            hour = row.get("hour", 12)
            country = str(row.get("country", "")).lower()
            asn_info = str(row.get("asn_org", "")).lower()

            # Rule: Off-hours foreign login or Tor/Bulletproof ASN
            is_off_hours = (0 <= hour <= 5)
            is_foreign = country not in ["united states", "internal", "us", ""]
            is_tor_bulletproof = any(k in asn_info for k in ["tor", "bulletproof", "m247", "vps"])

            if (is_off_hours and is_foreign) or is_tor_bulletproof:
                if row["status"] == "SUCCESS":
                    loc = f" from {row.get('country', 'Unknown')}" if "country" in row else ""
                    extra_ctx = f" via {row.get('asn_org')}" if "asn_org" in row else ""
                    anomalies.append({
                        "finding_id": f"ANOM-LOG-{idx}",
                        "evidence_source": "login_logs.csv",
                        "timestamp": str(row["timestamp"]),
                        "severity": "HIGH",
                        "mitre_technique": "T1078 (Valid Accounts / Session Hijacking)",
                        "description": f"Anomalous off-hours authentication detected at {row['timestamp']}{loc} (IP: {row['ip_address']}{extra_ctx})",
                        "entities_involved": {"user": row["user_id"], "ip": row["ip_address"]},
                        "raw_row_index": int(idx)
                    })
        return anomalies

    @classmethod
    def detect_mass_file_downloads(cls, df_files: pd.DataFrame) -> List[Dict[str, Any]]:
        anomalies = []
        if df_files is None or df_files.empty:
            return anomalies

        for idx, row in df_files.iterrows():
            fpath = str(row.get("file_path", "")).lower()
            bytes_r = int(row.get("bytes_read", 0))
            action = str(row.get("action", "")).upper()
            sens = str(row.get("file_sensitivity", "")).upper()

            is_sensitive_path = any(kw in fpath for kw in cls.SENSITIVE_PATH_KEYWORDS)
            is_critical_declared = sens in ["HIGH", "CRITICAL"]

            # Flag if sensitive asset is accessed with large volume or explicit download
            if (is_sensitive_path or is_critical_declared) and (bytes_r >= 10_000_000 or action in ["DOWNLOAD", "WRITEDATA"]):
                anomalies.append({
                    "finding_id": f"ANOM-FILE-{idx}",
                    "evidence_source": "file_access.csv",
                    "timestamp": str(row["timestamp"]),
                    "severity": "CRITICAL",
                    "mitre_technique": "T1005 (Data from Local System / Exfiltration Staging)",
                    "description": f"Exfiltration staging: High-risk access to classified asset '{row['file_path']}' ({bytes_r:,} bytes)",
                    "entities_involved": {"user": str(row.get("user_id", "Unknown")), "file": row["file_path"]},
                    "raw_row_index": int(idx)
                })
        return anomalies

    @classmethod
    def detect_data_exfiltration(cls, df_network: pd.DataFrame) -> List[Dict[str, Any]]:
        anomalies = []
        if df_network is None or df_network.empty:
            return anomalies

        THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB threshold

        for idx, row in df_network.iterrows():
            sent = int(row.get("bytes_sent", 0))
            if sent >= THRESHOLD_BYTES:
                mb_sent = round(sent / (1024 * 1024), 2)
                asn = str(row.get("dest_asn_org", "External IP"))
                anomalies.append({
                    "finding_id": f"ANOM-NET-{idx}",
                    "evidence_source": "network_logs.csv",
                    "timestamp": str(row["timestamp"]),
                    "severity": "CRITICAL",
                    "mitre_technique": "T1048 (Exfiltration Over Alternative Protocol)",
                    "description": f"Mass outbound exfiltration: {mb_sent} MB sent to {row['destination_ip']}:{row.get('dest_port', 443)} ({asn})",
                    "entities_involved": {"source_ip": str(row.get("source_ip", "")), "dest_ip": row["destination_ip"]},
                    "raw_row_index": int(idx)
                })
        return anomalies

    @classmethod
    def run_all(cls, dataframes: Dict[str, pd.DataFrame]) -> List[Dict[str, Any]]:
        all_anomalies = []
        if "login" in dataframes and dataframes["login"] is not None:
            all_anomalies.extend(cls.detect_suspicious_logins(dataframes["login"]))
        if "file" in dataframes and dataframes["file"] is not None:
            all_anomalies.extend(cls.detect_mass_file_downloads(dataframes["file"]))
        if "network" in dataframes and dataframes["network"] is not None:
            all_anomalies.extend(cls.detect_data_exfiltration(dataframes["network"]))
        return all_anomalies
