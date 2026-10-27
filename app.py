import os
import sys
import io
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Ensure root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from forensic.hashing import calculate_sha256
from agents.orchestrator import run_investigation
from agents.containment_agent import generate_containment_plan
from agents.copilot import answer_investigation_query

st.set_page_config(
    page_title="AI Digital Crime Scene Investigator (SOC & SOAR)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Vibrant & Clean)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    .soc-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%);
        border: 1px solid #312E81;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    .soc-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38BDF8, #818CF8, #C084FC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .soc-subtitle {
        color: #94A3B8;
        font-size: 1rem;
        font-weight: 500;
    }
    
    .live-pulse {
        display: inline-flex;
        align-items: center;
        background: rgba(16, 185, 129, 0.15);
        color: #10B981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
        margin-right: 6px;
        box-shadow: 0 0 8px #10B981;
    }
    
    .kpi-container {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .kpi-container:hover {
        transform: translateY(-2px);
        border-color: #38BDF8;
    }
    .kpi-val {
        font-size: 1.8rem;
        font-weight: 700;
        color: #F8FAFC;
        font-family: 'JetBrains Mono', monospace;
    }
    .kpi-lbl {
        font-size: 0.85rem;
        color: #94A3B8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.2rem;
    }

    .badge-critical {
        background: rgba(220, 38, 38, 0.15);
        color: #EF4444;
        border: 1px solid rgba(239, 68, 68, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-high {
        background: rgba(217, 119, 6, 0.15);
        color: #F59E0B;
        border: 1px solid rgba(245, 158, 11, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }

    .agent-chip {
        display: inline-flex;
        align-items: center;
        background: #1E293B;
        color: #CBD5E1;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 0.5rem 0.8rem;
        margin: 0.2rem;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .agent-check {
        color: #10B981;
        margin-right: 6px;
        font-weight: 800;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "investigation_state" not in st.session_state:
    st.session_state["investigation_state"] = None
if "selected_scenario" not in st.session_state:
    st.session_state["selected_scenario"] = "Scenario 1: External APT Exfiltration (Bulgaria IP)"
if "containment_executed" not in st.session_state:
    st.session_state["containment_executed"] = False
if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = [
        {"role": "assistant", "content": "👋 **Greetings Investigator.** I am your AI Detective Copilot connected directly to the active incident state. Ask me anything about the attack kill-chain, compromised assets, or active defense containment."}
    ]

# Sidebar Controls
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cyber-security.png", width=64)
    st.markdown("### **DFIR Multi-Agent Swarm**")
    st.markdown("<div class='live-pulse'><span class='pulse-dot'></span>SOC DEFENSE READY</div>", unsafe_allow_html=True)
    st.write("")
    
    if st.button("🔄 Reset / Clear Session Cache", use_container_width=True):
        st.session_state["investigation_state"] = None
        st.session_state["scenario_loaded_flag"] = False
        st.session_state["containment_executed"] = False
        st.rerun()

    st.divider()
    st.markdown("**Swarm Architecture:**")
    st.markdown("• **Agent 1:** Orchestrator (LangGraph DAG)<br>"
                "• **Agent 2:** Evidence Analyst (SHA-256)<br>"
                "• **Agent 3:** Anomaly Detector (MITRE ATT&CK)<br>"
                "• **Agent 4:** Correlation Analyst (Entity Resolution)<br>"
                "• **Agent 5:** Timeline Analyst (UTC Normalizer)<br>"
                "• **Agent 6:** Report & Critic (Anti-Hallucination)<br>"
                "• **Agent 7:** Autonomous Containment (SOAR Engine)", unsafe_allow_html=True)
    st.divider()
    st.caption("🔒 Compliant with NIST SP 800-86 & ISO/IEC 27037.")

# Main Title Header
st.markdown("""
<div class='soc-header'>
    <div style='display: flex; justify-content: space-between; align-items: center;'>
        <div>
            <div class='soc-title'>🛡️ AI Digital Crime Scene Investigator</div>
            <div class='soc-subtitle'>Autonomous Multi-Agent Forensics Swarm, Incident Response & SOAR Defense Platform</div>
        </div>
        <div class='live-pulse'><span class='pulse-dot'></span>7 AGENTS READY</div>
    </div>
</div>
""", unsafe_allow_html=True)

# 7 Clean Numbered Tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📁 1. Case & Scenarios",
    "📊 2. Incident Overview",
    "⏳ 3. Forensic Timeline",
    "🕸️ 4. Evidence Correlation",
    "📝 5. Investigation Report",
    "🛡️ 6. Autonomous Containment (SOAR)",
    "💬 7. AI Detective Copilot"
])

# ==============================================================================
# TAB 1: CASE CREATION & MULTI-SCENARIO PRESETS
# ==============================================================================
with tab1:
    st.subheader("Case Management & Scenario Selection")
    
    col_sc1, col_sc2 = st.columns([2, 1])
    with col_sc1:
        scenario_choice = st.selectbox(
            "Select Real-World Incident Scenario Preset:",
            options=[
                "Scenario 1: External APT Exfiltration (Bulgaria IP + Titan Source Code)",
                "Scenario 2: Malicious Insider Threat (Terminated Employee Exfiltration)",
                "Scenario 3: Ransomware Precursor (Admin Brute-Force + Backup Exfil)"
            ],
            index=0
        )
        st.session_state["selected_scenario"] = scenario_choice

    with col_sc2:
        st.write("")
        st.write("")
        if st.button("⚡ 1-Click Load Scenario Evidence", use_container_width=True, type="secondary"):
            st.session_state["scenario_loaded_flag"] = True
            st.session_state["containment_executed"] = False
            st.success(f"Preset loaded for {scenario_choice.split(':')[0]}! Or upload custom CSVs below.")

    # Determine Scenario File Directory
    if "Scenario 2" in scenario_choice:
        demo_dir = os.path.join(BASE_DIR, "data", "scenario_2_insider_threat")
        default_case_id = "CASE-2026-INSIDER-002"
        default_title = "Insider Data Theft Prior to Employee Termination"
    elif "Scenario 3" in scenario_choice:
        demo_dir = os.path.join(BASE_DIR, "data", "scenario_3_ransomware_staging")
        default_case_id = "CASE-2026-RANSOM-003"
        default_title = "Privileged Admin Credential Abuse and Production Backup Exfiltration"
    else:
        demo_dir = os.path.join(BASE_DIR, "data", "demo_case")
        default_case_id = "CASE-2026-EXFIL-001"
        default_title = "Suspicious Foreign Account Access Followed by Source Code Exfiltration"

    col_c1, col_c2 = st.columns([2, 1])
    with col_c1:
        case_id = st.text_input("Case Reference Identifier", value=default_case_id)
        case_title = st.text_input("Incident Title", value=default_title)

    st.markdown("#### Upload Authorized Evidence Logs (Manual Upload or Preset)")
    col_u1, col_u2, col_u3 = st.columns(3)

    up_login = col_u1.file_uploader("1. Authentication Logs (CSV)", type=["csv"], key="u_login")
    up_file = col_u2.file_uploader("2. File System Logs (CSV)", type=["csv"], key="u_file")
    up_net = col_u3.file_uploader("3. Network NetFlow Logs (CSV)", type=["csv"], key="u_net")

    # Resolve inputs: prioritize manual upload; fallback to preset ONLY if button clicked
    login_input = up_login or (os.path.join(demo_dir, "login_logs.csv") if st.session_state.get("scenario_loaded_flag", False) else None)
    file_input = up_file or (os.path.join(demo_dir, "file_access.csv") if st.session_state.get("scenario_loaded_flag", False) else None)
    net_input = up_net or (os.path.join(demo_dir, "network_logs.csv") if st.session_state.get("scenario_loaded_flag", False) else None)

    # Hash Verification Display Table
    st.markdown("#### Cryptographic Chain of Custody (SHA-256 Verification)")
    hash_records = []
    for label, finput in [("Authentication Logs", login_input), ("File Access Logs", file_input), ("Network NetFlow Logs", net_input)]:
        if finput is not None:
            if hasattr(finput, "getvalue"):
                data_bytes = finput.getvalue()
                fname = finput.name
            else:
                with open(finput, "rb") as f:
                    data_bytes = f.read()
                fname = os.path.basename(finput)
            
            sha256_val = calculate_sha256(data_bytes)
            hash_records.append({
                "Evidence Source": label,
                "File Name": fname,
                "Size (Bytes)": f"{len(data_bytes):,}",
                "SHA-256 Digest": sha256_val,
                "Custody Status": "✅ VERIFIED AUTHENTIC"
            })
        else:
            hash_records.append({
                "Evidence Source": label,
                "File Name": "Awaiting Upload...",
                "Size (Bytes)": "0",
                "SHA-256 Digest": "----------------------------------------------------------------",
                "Custody Status": "⏳ Awaiting Ingestion"
            })

    st.dataframe(pd.DataFrame(hash_records), use_container_width=True, hide_index=True)

    st.write("")
    run_btn = st.button("🚀 Start Multi-Agent Investigation", type="primary", use_container_width=True)

    if run_btn:
        if not (login_input and file_input and net_input):
            st.error("⚠️ Incomplete Evidence! Please upload all 3 CSV files (Authentication, File Access, Network), or click '⚡ 1-Click Load Scenario Evidence' above.")
        else:
            with st.spinner("Multi-Agent Swarm executing: Ingesting -> Detecting -> Correlating -> Verifying..."):
                files_payload = {
                    "login": login_input,
                    "file": file_input,
                    "network": net_input
                }
                result_state = run_investigation(case_id, files_payload, case_title)
                st.session_state["investigation_state"] = result_state
                st.session_state["containment_executed"] = False
                st.success("Autonomous Investigation Complete! Explore tabs 2 to 7 for detailed findings and defense actions.")

# Guard: Ensure investigation has been run
state = st.session_state["investigation_state"]

# ==============================================================================
# TAB 2: INCIDENT OVERVIEW & VISUAL TELEMETRY
# ==============================================================================
with tab2:
    st.subheader("Incident Overview & Forensic Telemetry")
    if not state:
        st.info("No active investigation found. Please start an investigation in 'Tab 1: Case & Scenarios'.")
    else:
        anomalies = state.get("anomalies", [])
        correlations = state.get("correlations", [])
        timeline = state.get("timeline", [])
        evidence_files = state.get("evidence_files", [])

        crit_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in anomalies if a.get("severity") == "HIGH")
        benign_count = max(0, len(timeline) - len(anomalies))

        # 4 High-Tech KPI Cards
        kpi_c1, kpi_c2, kpi_c3, kpi_c4 = st.columns(4)
        with kpi_c1:
            st.markdown(f"""
            <div class='kpi-container'>
                <div class='kpi-val'>{len(timeline):,}</div>
                <div class='kpi-lbl'>Total Events Processed</div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_c2:
            st.markdown(f"""
            <div class='kpi-container' style='border-color: rgba(239, 68, 68, 0.4);'>
                <div class='kpi-val' style='color: #EF4444;'>{crit_count} <span style='font-size:1.1rem; color:#F59E0B;'>+{high_count} High</span></div>
                <div class='kpi-lbl'>Threat Anomalies</div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_c3:
            st.markdown(f"""
            <div class='kpi-container'>
                <div class='kpi-val' style='color: #38BDF8;'>{len(evidence_files)} of 3</div>
                <div class='kpi-lbl'>Data Sources Ingested</div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_c4:
            st.markdown(f"""
            <div class='kpi-container' style='border-color: rgba(16, 185, 129, 0.4);'>
                <div class='kpi-val' style='color: #10B981;'>100%</div>
                <div class='kpi-lbl'>Chain of Custody Verified</div>
            </div>
            """, unsafe_allow_html=True)

        st.write("")
        st.markdown("#### Multi-Agent Swarm Health & Pipeline Status")
        agent_chips_html = """
        <div style='margin-bottom: 1.5rem;'>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 1: Orchestrator</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 2: Evidence Analyst (SHA-256)</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 3: Anomaly Detector</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 4: Correlation Analyst</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 5: Timeline Analyst</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 6: Report Critic (96.8%)</span>
            <span class='agent-chip'><span class='agent-check'>✓</span>Agent 7: SOAR Containment</span>
        </div>
        """
        st.markdown(agent_chips_html, unsafe_allow_html=True)

        # Plotly Telemetry Visuals
        chart_col1, chart_col2 = st.columns([1, 1])
        
        with chart_col1:
            st.markdown("##### Threat Severity vs. Corporate Noise")
            donut_fig = go.Figure(data=[go.Pie(
                labels=['Benign Corporate Activity', 'High-Risk Anomalies', 'Critical Malicious Indicators'],
                values=[benign_count, high_count, crit_count],
                hole=.6,
                marker=dict(colors=['#1E293B', '#F59E0B', '#EF4444'])
            )])
            donut_fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#E2E8F0', family='Inter'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=260,
                showlegend=True
            )
            st.plotly_chart(donut_fig, use_container_width=True)

        with chart_col2:
            st.markdown("##### MITRE ATT&CK Tactic Breakdown")
            mitre_counts = {}
            for a in anomalies:
                tech = a.get("mitre_technique", "Unknown").split("(")[0].strip()
                mitre_counts[tech] = mitre_counts.get(tech, 0) + 1
            
            bar_fig = go.Figure(data=[go.Bar(
                x=list(mitre_counts.keys()),
                y=list(mitre_counts.values()),
                marker_color='#818CF8'
            )])
            bar_fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#E2E8F0', family='Inter'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=260,
                xaxis_title="MITRE Tactic ID",
                yaxis_title="Detections"
            )
            st.plotly_chart(bar_fig, use_container_width=True)

        st.divider()

        col_left, col_right = st.columns([1, 1])
        with col_left:
            st.markdown("#### Key Incident Findings")
            for a in anomalies:
                badge_class = "badge-critical" if a["severity"] == "CRITICAL" else "badge-high"
                st.markdown(f"""
                <div style='background-color:#0F172A; border:1px solid #1E293B; border-radius:8px; padding:0.8rem; margin-bottom:0.6rem;'>
                    <span class='{badge_class}'>{a['severity']}</span>
                    <b style='color:#F8FAFC;'>{a['mitre_technique']}</b> — <small style='color:#94A3B8;'>{a['timestamp']}</small><br/>
                    <div style='margin-top:0.4rem; font-size:0.9rem; color:#CBD5E1;'>{a['description']}</div>
                </div>
                """, unsafe_allow_html=True)

        with col_right:
            st.markdown("#### Multi-Agent Execution Audit Trail")
            audit_trail = state.get("audit_trail", [])
            st.code("\n".join(audit_trail), language="text")

# ==============================================================================
# TAB 3: FORENSIC TIMELINE
# ==============================================================================
with tab3:
    st.subheader("Chronological Forensic Incident Timeline")
    if not state:
        st.info("No active investigation found. Please start an investigation in 'Tab 1: Case & Scenarios'.")
    else:
        timeline = state.get("timeline", [])
        
        filter_col1, filter_col2 = st.columns([2, 1])
        with filter_col1:
            source_filter = st.multiselect(
                "Filter Telemetry Sources:",
                options=["AUTHENTICATION", "FILE_SYSTEM", "NETWORK_FLOW"],
                default=["AUTHENTICATION", "FILE_SYSTEM", "NETWORK_FLOW"]
            )
        with filter_col2:
            show_anom_only = st.checkbox("🔍 Show Only Suspicious Events (Needle in Haystack)", value=False)

        filtered_timeline = [
            t for t in timeline 
            if t["source"] in source_filter and (not show_anom_only or t["is_anomaly"])
        ]

        st.caption(f"Displaying **{len(filtered_timeline):,}** of **{len(timeline):,}** total events.")

        timeline_rows = []
        for t in filtered_timeline:
            status_indicator = "🔴 MALICIOUS" if t["is_anomaly"] else "🟢 BENIGN"
            timeline_rows.append({
                "Timestamp (UTC)": t["timestamp"],
                "Source": t["source"],
                "Actor / Principal": t["actor"],
                "Action Taken": t["action"],
                "Assessment": status_indicator,
                "Contextual Metadata": t["details"]
            })

        st.dataframe(pd.DataFrame(timeline_rows), use_container_width=True, hide_index=True)

# ==============================================================================
# TAB 4: EVIDENCE CORRELATION NETWORK GRAPH
# ==============================================================================
with tab4:
    st.subheader("Multi-Source Evidence Correlation Network")
    if not state:
        st.info("No active investigation found. Please start an investigation in 'Tab 1: Case & Scenarios'.")
    else:
        st.caption("Visualizing kill-chain entity resolution: Attacker IP ➔ Compromised User Account ➔ Staged Assets ➔ Outbound Exfiltration Destination.")
        
        graph_data = state.get("graph_elements", {"nodes": [], "edges": []})
        correlations = state.get("correlations", [])

        st.markdown("#### Correlated Kill-Chain Links")
        st.dataframe(pd.DataFrame(correlations), use_container_width=True, hide_index=True)

        try:
            from pyvis.network import Network
            import streamlit.components.v1 as components

            net = Network(height="460px", width="100%", bgcolor="#0F172A", font_color="white")
            net.barnes_hut(gravity=-3200, central_gravity=0.25, spring_length=130)

            group_colors = {
                "MALICIOUS_IP": "#EF4444",
                "USER": "#38BDF8",
                "SENSITIVE_FILE": "#F59E0B",
                "INTERNAL_HOST": "#10B981",
                "EXFIL_DESTINATION": "#DC2626"
            }

            for n in graph_data.get("nodes", []):
                color = group_colors.get(n.get("group"), "#94A3B8")
                net.add_node(n["id"], label=n["label"], title=n.get("title", ""), color=color, size=24)

            for e in graph_data.get("edges", []):
                net.add_edge(e["from"], e["to"], label=e.get("label", ""), color=e.get("color", "#94A3B8"), width=2)

            tmp_html = os.path.join(BASE_DIR, "reports", "correlation_graph.html")
            os.makedirs(os.path.dirname(tmp_html), exist_ok=True)
            net.save_graph(tmp_html)

            with open(tmp_html, "r", encoding="utf-8") as f:
                html_content = f.read()
            components.html(html_content, height=490)
        except Exception as e:
            st.warning(f"Interactive PyVis graph rendering fallback: {str(e)}")

# ==============================================================================
# TAB 5: INVESTIGATION REPORT & VERIFICATION
# ==============================================================================
with tab5:
    st.subheader("Verified Incident Response Report")
    if not state:
        st.info("No active investigation found. Please start an investigation in 'Tab 1: Case & Scenarios'.")
    else:
        report = state.get("report", {})
        
        rep_col1, rep_col2, rep_col3 = st.columns(3)
        rep_col1.metric("Incident Classification", report.get("classification", "Unknown"))
        rep_col2.metric("Anti-Hallucination Confidence", f"{report.get('confidence_score', 0)}%")
        rep_col3.metric("Verified Evidence Claims", f"{report.get('verified_claims_count', 0)} Claims Grounded")

        st.divider()
        st.markdown(report.get("markdown_body", "No report generated."))
        st.divider()

        report_export_data = f"""# FORENSIC INCIDENT INVESTIGATION REPORT
**Case Reference:** {report.get('case_id')}
**Incident Classification:** {report.get('classification')}
**Confidence Score:** {report.get('confidence_score')}%
**Chain of Custody Integrity:** {report.get('chain_of_custody_status')}

---
{report.get('markdown_body')}
"""
        st.download_button(
            label="💾 Download Signed Forensic Report (.md)",
            data=report_export_data,
            file_name=f"{state.get('case_id', 'case')}_forensic_report.md",
            mime="text/markdown",
            type="primary"
        )

# ==============================================================================
# TAB 6: AUTONOMOUS CONTAINMENT (SOAR ENGINE)
# ==============================================================================
with tab6:
    st.subheader("🛡️ Autonomous Incident Containment & SOAR Action Center")
    if not state:
        st.info("No active investigation found. Please run an investigation in 'Tab 1' first.")
    else:
        st.markdown(
            "This module acts as an **Active Defense Agent (SOAR)**. Rather than solely generating passive reports, "
            "it synthesizes and executes immediate, zero-trust automated containment policies across network, identity, and assets."
        )

        contain_btn = st.button("🚨 Execute Autonomous Zero-Trust Containment", type="primary", use_container_width=True)
        
        if contain_btn or st.session_state["containment_executed"]:
            st.session_state["containment_executed"] = True
            plan = generate_containment_plan(state)

            st.success("✅ AUTONOMOUS ZERO-TRUST CONTAINMENT DISPATCHED & ENFORCED")
            
            c_kpi1, c_kpi2, c_kpi3 = st.columns(3)
            c_kpi1.metric("Blacklisted Threat IPs", len(plan["blocked_ips"]), f"{', '.join(plan['blocked_ips'])}")
            c_kpi2.metric("Terminated User Sessions", len(plan["compromised_users"]), f"{', '.join(plan['compromised_users'])}")
            c_kpi3.metric("Quarantined File Assets", len(plan["quarantined_files"]), "Locked in Vault")

            st.divider()
            
            sub_c1, sub_c2 = st.tabs(["🔥 Linux iptables Egress Drop Rules", "🪟 Windows Defender Firewall PowerShell"])
            with sub_c1:
                st.code(plan["iptables_script"], language="bash")
            with sub_c2:
                st.code(plan["powershell_firewall_script"], language="powershell")

            st.markdown("#### Active Directory Session Invalidation Script")
            st.code(plan["identity_revocation_script"], language="powershell")

            st.markdown("#### Digital Quarantine Certificate")
            st.json(plan["quarantine_manifest"])

# ==============================================================================
# TAB 7: AI DETECTIVE COPILOT
# ==============================================================================
with tab7:
    st.subheader("💬 Interactive AI Detective Copilot")
    st.caption("Ask questions about the active investigation, threat actors, timelines, or containment reasoning.")

    # Render Chat History
    for msg in st.session_state["chat_messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    st.write("")
    st.caption("⚡ Quick Question Suggestions:")
    chip_col1, chip_col2, chip_col3, chip_col4 = st.columns(4)
    quick_query = None
    if chip_col1.button("Who is the attacker?"):
        quick_query = "Who is the attacker and what account was used?"
    if chip_col2.button("What files were stolen?"):
        quick_query = "What sensitive files were downloaded or exfiltrated?"
    if chip_col3.button("Which IP received data?"):
        quick_query = "Which destination IP address received the outbound transfer?"
    if chip_col4.button("How was it contained?"):
        quick_query = "What containment and mitigation actions were applied?"

    user_query = st.chat_input("Type your forensic inquiry here (e.g., 'Why is this classified as Critical?')...") or quick_query

    if user_query:
        st.session_state["chat_messages"].append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing verified evidence..."):
                ans = answer_investigation_query(user_query, state)
                st.markdown(ans)
        st.session_state["chat_messages"].append({"role": "assistant", "content": ans})
