import os
import json
from typing import Dict, Any

def answer_investigation_query(query: str, state: Dict[str, Any]) -> str:
    """
    Interactive AI Detective Copilot: Answers natural language questions
    about the active case with grounded evidence citations.
    """
    if not state:
        return "No investigation is currently loaded. Please create a case and run the investigation first."

    case_id = state.get("case_id", "CASE")
    anomalies = state.get("anomalies", [])
    correlations = state.get("correlations", [])
    timeline = state.get("timeline", [])
    evidence = state.get("evidence_files", [])

    q_lower = query.lower()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    # If Gemini API key is available, use LLM for natural dialogue
    if gemini_key:
        try:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            context = {
                "case_id": case_id,
                "anomalies": anomalies,
                "correlations": correlations,
                "timeline_highlights": [t for t in timeline if t.get("is_anomaly")],
                "evidence_sources": [e.get("file_name") for e in evidence]
            }
            prompt = f"""
            You are the Lead Cyber Forensic Detective Copilot.
            Answer the user's question about the incident based ONLY on the verified evidence below.
            Do not speculate or invent facts not present in the data. Cite exact IPs, users, and timestamps.

            VERIFIED INCIDENT CONTEXT:
            {json.dumps(context, indent=2)}

            USER QUESTION: {query}
            """
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            if resp and resp.text:
                return resp.text
        except Exception:
            pass  # Fall through to deterministic engine

    # High-speed deterministic fallback reasoning engine
    if any(k in q_lower for k in ["who", "user", "actor", "account", "attacker"]):
        users = set([str(a["entities_involved"].get("user")) for a in anomalies if a.get("entities_involved", {}).get("user")])
        ips = set([str(a["entities_involved"].get("ip")) for a in anomalies if a.get("entities_involved", {}).get("ip")])
        return (f"**Identified Actor:** Suspicious activity was traced to user account(s): `{', '.join(users) or 'Unknown'}`. "
                f"Authentication originated from remote IP address(es): `{', '.join(ips) or 'Unknown'}`.")

    if any(k in q_lower for k in ["ip", "address", "destination", "external"]):
        dest_ips = set([str(a["entities_involved"].get("dest_ip")) for a in anomalies if a.get("entities_involved", {}).get("dest_ip")])
        src_ips = set([str(a["entities_involved"].get("ip")) for a in anomalies if a.get("entities_involved", {}).get("ip")])
        return (f"**IP Network Forensics:**\n"
                f"- **Attacker Ingress IP:** `{', '.join(src_ips) or 'N/A'}`\n"
                f"- **Exfiltration Destination IP:** `{', '.join(dest_ips) or 'N/A'}`.")

    if any(k in q_lower for k in ["file", "stolen", "download", "sensitive", "data", "size"]):
        files = set([str(a["entities_involved"].get("file")) for a in anomalies if a.get("entities_involved", {}).get("file")])
        net_anoms = [a for a in anomalies if a.get("evidence_source") == "network_logs.csv"]
        desc = net_anoms[0]["description"] if net_anoms else "High-volume data transfer"
        return (f"**Data Exfiltration Analysis:**\n"
                f"- **Compromised Files/Assets:** `{', '.join(files) or 'Unknown'}`\n"
                f"- **Volume Staged/Transferred:** {desc}.")

    if any(k in q_lower for k in ["why", "critical", "severity", "suspicious", "flag"]):
        reasons = [f"• {a['mitre_technique']}: {a['description']}" for a in anomalies]
        return f"**Forensic Evidence Basis:**\nThe incident was flagged due to {len(anomalies)} validated indicators:\n" + "\n".join(reasons)

    if any(k in q_lower for k in ["contain", "mitigat", "block", "remediat", "action"]):
        return ("**Containment Protocol:**\n"
                "1. Apply automated firewall blocklists (iptables & PowerShell) for external threat IPs.\n"
                "2. Revoke active OAuth refresh tokens and terminate AD/Kerberos sessions for compromised users.\n"
                "3. Isolate internal host systems to prevent lateral movement.")

    # General overview response
    return (f"**Case {case_id} Overview:**\n"
            f"The swarm analyzed {len(evidence)} evidence files and identified {len(anomalies)} anomalies "
            f"with {len(correlations)} correlated links across authentication, file system, and network NetFlow logs.")
