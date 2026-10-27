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

    # Track seen entities to avoid duplicate graph nodes and edges
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, group: str, title: str):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "label": label, "group": group, "title": title})

    def add_edge(src: str, dst: str, label: str, color: str):
        edge_key = (src, dst, label)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                "from": src,
                "to": dst,
                "label": label,
                "color": color
            })

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
            user_label = str(ent['user']).split("@")[0] if "@" in str(ent['user']) else str(ent['user'])
            add_node(u_node, f"User: {user_label}", "USER", f"Compromised Account: {ent['user']}")
            add_node(ip_node, f"Attacker: {ent['ip']}", "MALICIOUS_IP", f"Attacker Ingress IP: {ent['ip']}")
            add_edge(ip_node, u_node, "Unauthorized Login", "#EF4444")
            correlations.append({
                "source": ent['ip'],
                "target": ent['user'],
                "type": "ACCOUNT_COMPROMISE",
                "detail": f"IP {ent['ip']} logged into account {ent['user']}"
            })

        if "user" in ent and "file" in ent:
            u_node = f"user_{ent['user']}"
            raw_path = str(ent['file'])
            fname = raw_path.replace("\\", "/").split("/")[-1]
            short_fname = (fname[:18] + "...") if len(fname) > 21 else fname
            f_node = f"file_{fname}"
            
            user_label = str(ent['user']).split("@")[0] if "@" in str(ent['user']) else str(ent['user'])
            add_node(u_node, f"User: {user_label}", "USER", f"Compromised Account: {ent['user']}")
            add_node(f_node, f"File: {short_fname}", "SENSITIVE_FILE", f"Sensitive Asset: {raw_path}")
            add_edge(u_node, f_node, "Staged / Read", "#F59E0B")
            correlations.append({
                "source": ent['user'],
                "target": fname,
                "type": "DATA_STAGE",
                "detail": f"User {ent['user']} staged/downloaded sensitive file {fname}"
            })

        if "source_ip" in ent and "dest_ip" in ent:
            s_node = f"src_{ent['source_ip']}"
            d_node = f"dest_{ent['dest_ip']}"
            add_node(s_node, f"Host: {ent['source_ip']}", "INTERNAL_HOST", f"Internal Host: {ent['source_ip']}")
            add_node(d_node, f"C2 Dest: {ent['dest_ip']}", "EXFIL_DESTINATION", f"Exfil C2 Server: {ent['dest_ip']}")
            add_edge(s_node, d_node, "Exfiltration Flow", "#DC2626")
            correlations.append({
                "source": ent['source_ip'],
                "target": ent['dest_ip'],
                "type": "OUTBOUND_EXFILTRATION",
                "detail": f"Exfiltrated payload from host {ent['source_ip']} to {ent['dest_ip']}"
            })

    # Cross-link User to Internal Host if both exist in graph
    for anom in anomalies:
        ent = anom.get("entities_involved", {})
        if "user" in ent:
            u_node = f"user_{ent['user']}"
            for n in nodes:
                if n["group"] == "INTERNAL_HOST":
                    add_edge(u_node, n["id"], "Session Pivot", "#38BDF8")
                    break
            break

    audit_msgs.append(f"[Correlation Analyst] Correlated {len(correlations)} relational links across log sources.")

    return {
        "correlations": correlations,
        "graph_elements": {"nodes": nodes, "edges": edges},
        "audit_trail": audit_msgs
    }
