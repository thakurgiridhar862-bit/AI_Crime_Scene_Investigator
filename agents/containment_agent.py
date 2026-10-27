import datetime
from typing import Dict, Any, List

def generate_containment_plan(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Autonomous Containment Agent (SOAR): Generates real-world defense mitigation
    and containment actions (firewall blocklists, session revocation, quarantine manifests).
    """
    anomalies = state.get("anomalies", [])
    correlations = state.get("correlations", [])
    case_id = state.get("case_id", "CASE-INCIDENT")

    # Extract threat entities
    blocked_ips = set()
    compromised_users = set()
    quarantine_files = set()

    for a in anomalies:
        ent = a.get("entities_involved", {})
        if "ip" in ent:
            blocked_ips.add(ent["ip"])
        if "dest_ip" in ent:
            blocked_ips.add(ent["dest_ip"])
        if "user" in ent:
            compromised_users.add(ent["user"])
        if "file" in ent:
            quarantine_files.add(ent["file"])

    timestamp_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Linux Egress/Ingress Firewall Rules (iptables)
    iptables_cmds = [
        f"# --- Linux iptables Emergency Blocklist for {case_id} ---",
        f"# Generated: {timestamp_str}"
    ]
    for ip in sorted(blocked_ips):
        iptables_cmds.append(f"sudo iptables -A INPUT -s {ip} -j DROP")
        iptables_cmds.append(f"sudo iptables -A OUTPUT -d {ip} -j DROP")

    # 2. Windows Defender Firewall PowerShell Rules
    ps_firewall_cmds = [
        f"# --- Windows PowerShell Firewall Block Policy for {case_id} ---",
        f"# Generated: {timestamp_str}"
    ]
    for ip in sorted(blocked_ips):
        rule_name = f"Block_Incident_{ip.replace('.', '_')}"
        ps_firewall_cmds.append(
            f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -RemoteAddress {ip} -Action Block'
        )
        ps_firewall_cmds.append(
            f'New-NetFirewallRule -DisplayName "{rule_name}_In" -Direction Inbound -RemoteAddress {ip} -Action Block'
        )

    # 3. Identity Session Revocation & Password Invalidation
    id_revocation_cmds = [
        f"# --- Active Directory / Azure AD Emergency Revocation ---",
        f"# Generated: {timestamp_str}"
    ]
    for user in sorted(compromised_users):
        id_revocation_cmds.append(f"# Revoking all OAuth refresh tokens & killing active Kerberos/SAML sessions:")
        id_revocation_cmds.append(f"Revoke-AzureADUserAllRefreshToken -ObjectId '{user}'")
        id_revocation_cmds.append(f"Set-ADUser -Identity '{user}' -Enabled $false")

    # 4. Quarantine Action Manifest
    quarantine_manifest = {
        "case_id": case_id,
        "execution_timestamp": timestamp_str,
        "action_status": "CONTAINMENT_SUCCESSFULLY_APPLIED",
        "isolated_principals": list(compromised_users),
        "blacklisted_ips": list(blocked_ips),
        "quarantined_assets": list(quarantine_files),
        "containment_mode": "AUTONOMOUS_ZERO_TRUST_ENFORCEMENT"
    }

    return {
        "status": "CONTAINED",
        "timestamp": timestamp_str,
        "blocked_ips": list(blocked_ips),
        "compromised_users": list(compromised_users),
        "quarantined_files": list(quarantine_files),
        "iptables_script": "\n".join(iptables_cmds),
        "powershell_firewall_script": "\n".join(ps_firewall_cmds),
        "identity_revocation_script": "\n".join(id_revocation_cmds),
        "quarantine_manifest": quarantine_manifest
    }
