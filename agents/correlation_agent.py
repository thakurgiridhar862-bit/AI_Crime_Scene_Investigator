from typing import Dict, Any, List

def correlation_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlation Analyst Agent: Connects disparate clues across silos
    (User accounts <-> IPs <-> Compromised Files <-> Outbound Sockets).
    """
    raw_dfs = state.get("raw_dataframes", {})
    anomalies = state.get("anomalies", [])
    audit_msgs = list(state.get("audit_trail", []))

    correlations: List[Dict[str, Any]] = []
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Track seen entities to avoid duplicate graph nodes
    seen_nodes = set()

    def add_node(node_id: str, label: str, group: str, title: str):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "label": label, "group": group, "title": title})

    df_login = raw_dfs.get("login")
    df_file = raw_dfs.get("file")
    df_net = raw_dfs.get("network")

    # 1. Correlate Anomalous Login IPs with Users
    suspicious_users = set()
    suspicious_ips = set()

    for anom in anomalies:
        ent = anom.get("entities_involved", {})
        if "user" in ent:
            suspicious_users.add(ent["user"])
        if "ip" in ent:
            suspicious_ips.add(ent["ip"])

    # Build graph from findings
    for anom in anomalies:
        ent = anom.get("entities_involved", {})
        if "user" in ent and "ip" in ent:
            u_node = f"user_{ent['user']}"
            ip_node = f"ip_{ent['ip']}"
            add_node(u_node, ent['user'], "USER", f"User Account: {ent['user']}")
            add_node(ip_node, ent['ip'], "MALICIOUS_IP", f"Attacker IP: {ent['ip']}")
            edges.append({
                "from": ip_node,
                "to": u_node,
                "label": "UNAUTHORIZED_LOGIN",
                "color": "#EF4444"
            })
            correlations.append({
                "source": ent['ip'],
                "target": ent['user'],
                "type": "ACCOUNT_COMPROMISE",
                "detail": f"IP {ent['ip']} logged into account {ent['user']}"
            })

        if "user" in ent and "file" in ent:
            u_node = f"user_{ent['user']}"
            f_node = f"file_{ent['file']}"
            add_node(u_node, ent['user'], "USER", f"User Account: {ent['user']}")
            add_node(f_node, ent['file'].split('/')[-1], "SENSITIVE_FILE", f"File: {ent['file']}")
            edges.append({
                "from": u_node,
                "to": f_node,
                "label": "DOWNLOADED_FILE",
                "color": "#F59E0B"
            })
            correlations.append({
                "source": ent['user'],
                "target": ent['file'],
                "type": "DATA_STAGE",
                "detail": f"User {ent['user']} staged/downloaded sensitive file {ent['file']}"
            })

        if "source_ip" in ent and "dest_ip" in ent:
            s_node = f"src_{ent['source_ip']}"
            d_node = f"dest_{ent['dest_ip']}"
            add_node(s_node, ent['source_ip'], "INTERNAL_HOST", f"Internal Host: {ent['source_ip']}")
            add_node(d_node, ent['dest_ip'], "EXFIL_DESTINATION", f"Exfil Destination: {ent['dest_ip']}")
            edges.append({
                "from": s_node,
                "to": d_node,
                "label": "EXFILTRATION_FLOW",
                "color": "#DC2626"
            })
            correlations.append({
                "source": ent['source_ip'],
                "target": ent['dest_ip'],
                "type": "OUTBOUND_EXFILTRATION",
                "detail": f"Exfiltrated payload from host {ent['source_ip']} to {ent['dest_ip']}"
            })

    audit_msgs.append(f"[Correlation Analyst] Correlated {len(correlations)} relational links across log sources.")

    return {
        "correlations": correlations,
        "graph_elements": {"nodes": nodes, "edges": edges},
        "audit_trail": audit_msgs
    }
