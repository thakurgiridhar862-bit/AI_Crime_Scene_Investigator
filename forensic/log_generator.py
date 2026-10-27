import os
import random
from datetime import datetime, timedelta
import pandas as pd

def generate_true_enterprise_dataset(base_dir):
    """
    Generates authentic, enterprise-grade SIEM / Splunk / CrowdStrike style telemetry.
    Contains real corporate user agents, authentic file paths, NetFlow ephemeral ports,
    and Tor/VPN bulletproof hosting ASNs.
    """
    scen_dir = os.path.join(base_dir, "data", "demo_case")
    live_dir = os.path.join(base_dir, "evidence_for_live_demo")
    os.makedirs(scen_dir, exist_ok=True)
    os.makedirs(live_dir, exist_ok=True)

    employees = [
        ("j.doe@synthex-defense.internal", "John Doe (Sr. Systems Architect)", "10.240.12.45", "CORP-WKS-0145"),
        ("a.smith@synthex-defense.internal", "Alice Smith (Lead DevOps Eng)", "10.240.12.52", "CORP-MBP-0052"),
        ("b.martin@synthex-defense.internal", "Bob Martin (Director of Finance)", "10.240.14.80", "CORP-WKS-0080"),
        ("c.clark@synthex-defense.internal", "Carol Clark (HR VP)", "10.240.16.12", "CORP-WKS-0012"),
        ("d.lee@synthex-defense.internal", "David Lee (Frontend Engineer)", "10.240.12.88", "CORP-MBP-0088"),
        ("e.white@synthex-defense.internal", "Emma White (Product Manager)", "10.240.18.91", "CORP-WKS-0091"),
        ("svc_backup@synthex-defense.internal", "Veeam Service Account", "10.240.2.10", "SRV-VEEAM-01"),
        ("svc_deploy@synthex-defense.internal", "Jenkins CI Automation", "10.240.2.25", "SRV-CI-JENKINS")
    ]

    legit_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17425; Pro)"
    ]

    base_time = datetime(2026, 10, 26, 8, 45, 0)

    # =========================================================================
    # 1. AUTHENTICATION LOGS (Okta / Azure Active Directory Unified Audit)
    # =========================================================================
    auth_rows = []
    for emp in employees:
        t = base_time + timedelta(minutes=random.randint(5, 75))
        auth_rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "user_email": emp[0],
            "workstation_id": emp[3],
            "src_ip": emp[2],
            "geo_country": "United States",
            "geo_city": "New York",
            "asn_org": "Synthex Enterprise Internal Subnet",
            "auth_status": "SUCCESS",
            "auth_protocol": "Kerberos_v5",
            "mfa_status": "MFA_SATISFIED",
            "user_agent": random.choice(legit_user_agents)
        })

    # Background enterprise activity (token refreshes, VPN reconnections)
    for i in range(120):
        emp = random.choice(employees)
        t = base_time + timedelta(minutes=random.randint(60, 580))
        auth_rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "user_email": emp[0],
            "workstation_id": emp[3],
            "src_ip": emp[2],
            "geo_country": "United States",
            "geo_city": "New York",
            "asn_org": "Synthex Enterprise Internal Subnet",
            "auth_status": "SUCCESS",
            "auth_protocol": "OAuth2.0_Bearer",
            "mfa_status": "MFA_SATISFIED",
            "user_agent": random.choice(legit_user_agents)
        })

    # STEALTHY ATTACK SEQUENCE (Bulgarian Tor / Bulletproof Hosting Exit Node)
    intrusion_t = datetime(2026, 10, 27, 3, 14, 22)
    auth_rows.append({
        "timestamp": intrusion_t.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user_email": "j.doe@synthex-defense.internal",
        "workstation_id": "EXTERNAL-UNKNOWN-CLI",
        "src_ip": "185.220.101.5",
        "geo_country": "Bulgaria",
        "geo_city": "Sofia",
        "asn_org": "M247 Ltd (Tor Exit Node / Bulletproof VPS)",
        "auth_status": "SUCCESS",
        "auth_protocol": "REST_SSO_API",
        "mfa_status": "MFA_BYPASSED_SESSION_COOKIE_HIJACK",
        "user_agent": "python-requests/2.31.0"
    })
    auth_rows.append({
        "timestamp": (intrusion_t + timedelta(seconds=28)).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user_email": "domain_admin@synthex-defense.internal",
        "workstation_id": "EXTERNAL-UNKNOWN-CLI",
        "src_ip": "185.220.101.5",
        "geo_country": "Bulgaria",
        "geo_city": "Sofia",
        "asn_org": "M247 Ltd (Tor Exit Node / Bulletproof VPS)",
        "auth_status": "FAILED",
        "auth_protocol": "REST_SSO_API",
        "mfa_status": "MFA_PROMPT_REJECTED",
        "user_agent": "curl/8.4.0"
    })
    auth_rows.append({
        "timestamp": (intrusion_t + timedelta(seconds=52)).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user_email": "domain_admin@synthex-defense.internal",
        "workstation_id": "EXTERNAL-UNKNOWN-CLI",
        "src_ip": "185.220.101.5",
        "geo_country": "Bulgaria",
        "geo_city": "Sofia",
        "asn_org": "M247 Ltd (Tor Exit Node / Bulletproof VPS)",
        "auth_status": "FAILED",
        "auth_protocol": "REST_SSO_API",
        "mfa_status": "MFA_PROMPT_REJECTED",
        "user_agent": "curl/8.4.0"
    })

    df_auth = pd.DataFrame(auth_rows).sort_values("timestamp").reset_index(drop=True)
    df_auth.to_csv(os.path.join(scen_dir, "login_logs.csv"), index=False)
    df_auth.to_csv(os.path.join(live_dir, "login_logs.csv"), index=False)

    # =========================================================================
    # 2. FILE ACCESS LOGS (Windows Security Event 4663 / CrowdStrike EDR)
    # =========================================================================
    file_rows = []
    normal_enterprise_shares = [
        (r"\\SYNTHEX-FS01\Engineering\Sprint_Backlogs\2026_Q4_Roadmap.xlsx", "excel.exe", 145000),
        (r"\\SYNTHEX-FS01\Marketing\Asset_Library\Brand_Guidelines_v3.pdf", "AcroRd32.exe", 4200000),
        (r"\\SYNTHEX-FS01\HR-General\Company_Handbook_Holiday_Schedule.docx", "winword.exe", 88000),
        (r"\\SYNTHEX-FS01\Development\repo\frontend\src\index.tsx", "code.exe", 12500),
        (r"\\SYNTHEX-FS01\Operations\Facilities\Cafeteria_Menu_Weekly.pdf", "msedge.exe", 320000),
        (r"\\SYNTHEX-FS01\Finance-Public\Expense_Report_Template.xltx", "excel.exe", 48000)
    ]

    for i in range(180):
        emp = random.choice(employees[:6])
        f = random.choice(normal_enterprise_shares)
        t = base_time + timedelta(minutes=random.randint(15, 600))
        file_rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "user_email": emp[0],
            "workstation_id": emp[3],
            "process_name": f[1],
            "access_type": random.choice(["FileRead", "FileOpen", "WriteData"]),
            "file_path": f[0],
            "file_size_bytes": f[2] + random.randint(-1000, 5000),
            "bytes_transferred": random.randint(4000, 45000)
        })

    # MALICIOUS DATA STAGING (03:18 AM - 03:21 AM)
    file_rows.append({
        "timestamp": "2026-10-27 03:18:10 UTC",
        "user_email": "j.doe@synthex-defense.internal",
        "workstation_id": "CORP-WKS-0145",
        "process_name": "powershell.exe",
        "access_type": "DOWNLOAD",
        "file_path": r"\\SYNTHEX-FS01\Finance-Confidential\Unreleased_2026_Q3_SEC_Financial_Audit.xlsx",
        "file_size_bytes": 14500000,
        "bytes_transferred": 14500000
    })
    file_rows.append({
        "timestamp": "2026-10-27 03:19:04 UTC",
        "user_email": "j.doe@synthex-defense.internal",
        "workstation_id": "CORP-WKS-0145",
        "process_name": "7z.exe",
        "access_type": "DOWNLOAD",
        "file_path": r"\\SYNTHEX-FS01\Classified-R&D\Project_Titan\core_firmware_source_code_v4.2.tar.gz",
        "file_size_bytes": 854000000,
        "bytes_transferred": 854000000
    })
    file_rows.append({
        "timestamp": "2026-10-27 03:21:30 UTC",
        "user_email": "j.doe@synthex-defense.internal",
        "workstation_id": "CORP-WKS-0145",
        "process_name": "powershell.exe",
        "access_type": "DOWNLOAD",
        "file_path": r"\\SYNTHEX-FS01\HR-Restricted\Executive_Compensation_SSN_Vault.kdbx",
        "file_size_bytes": 32000000,
        "bytes_transferred": 32000000
    })

    df_file = pd.DataFrame(file_rows).sort_values("timestamp").reset_index(drop=True)
    df_file.to_csv(os.path.join(scen_dir, "file_access.csv"), index=False)
    df_file.to_csv(os.path.join(live_dir, "file_access.csv"), index=False)

    # =========================================================================
    # 3. NETWORK NETFLOW / FIREWALL LOGS (Palo Alto Networks Next-Gen Flow)
    # =========================================================================
    net_rows = []
    normal_cloud_services = [
        ("142.250.190.46", 443, "Google Cloud Platform", "ssl/tls"),
        ("52.96.166.130", 443, "Microsoft 365 Exchange", "ssl/tls"),
        ("140.82.121.4", 443, "GitHub Enterprise Cloud", "ssh/git"),
        ("104.244.42.1", 443, "Cloudflare Edge CDN", "https"),
        ("10.240.0.1", 53, "Internal Active Directory DNS", "dns")
    ]

    for i in range(240):
        emp = random.choice(employees[:6])
        srv = random.choice(normal_cloud_services)
        t = base_time + timedelta(minutes=random.randint(10, 620))
        net_rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "src_ip": emp[2],
            "src_port": random.randint(49152, 65535),
            "dest_ip": srv[0],
            "dest_port": srv[1],
            "protocol": "UDP" if srv[1] == 53 else "TCP",
            "app_protocol": srv[3],
            "bytes_sent": random.randint(300, 85000),
            "bytes_received": random.randint(1200, 450000),
            "packets": random.randint(8, 120),
            "firewall_action": "ALLOW",
            "dest_asn_org": srv[2]
        })

    # MALICIOUS EXFILTRATION CHANNEL (03:22 AM - 03:25 AM)
    net_rows.append({
        "timestamp": "2026-10-27 03:22:15 UTC",
        "src_ip": "10.240.12.45",
        "src_port": 54128,
        "dest_ip": "198.51.100.99",
        "dest_port": 443,
        "protocol": "TCP",
        "app_protocol": "ssl/encrypted-tunnel",
        "bytes_sent": 902000000,
        "bytes_received": 14200,
        "packets": 612450,
        "firewall_action": "ALLOW",
        "dest_asn_org": "StarkHost VPS (Known Bulletproof Exfiltration Node)"
    })
    net_rows.append({
        "timestamp": "2026-10-27 03:25:00 UTC",
        "src_ip": "10.240.12.45",
        "src_port": 54130,
        "dest_ip": "198.51.100.99",
        "dest_port": 443,
        "protocol": "TCP",
        "app_protocol": "ssl/encrypted-tunnel",
        "bytes_sent": 45000,
        "bytes_received": 1200,
        "packets": 312,
        "firewall_action": "ALLOW",
        "dest_asn_org": "StarkHost VPS (Known Bulletproof Exfiltration Node)"
    })

    df_net = pd.DataFrame(net_rows).sort_values("timestamp").reset_index(drop=True)
    df_net.to_csv(os.path.join(scen_dir, "network_logs.csv"), index=False)
    df_net.to_csv(os.path.join(live_dir, "network_logs.csv"), index=False)

    print(f"Generated TRUE Enterprise-Grade Dataset:")
    print(f"  Auth records (Okta/AzureAD): {len(df_auth)}")
    print(f"  File audit records (WinSec/EDR): {len(df_file)}")
    print(f"  NetFlow records (PaloAlto): {len(df_net)}")
    print(f"  Total Enterprise Telemetry: {len(df_auth) + len(df_file) + len(df_net)} events")

if __name__ == "__main__":
    b = r"C:\Users\hp\.gemini\antigravity\scratch\ai-digital-crime-investigator"
    generate_true_enterprise_dataset(b)
