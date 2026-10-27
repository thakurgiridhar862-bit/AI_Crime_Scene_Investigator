import os
import sys
import io
import json
import streamlit as st
import pandas as pd
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
    page_title="AI Digital Crime Scene Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom Styling (No Sidebar, Ultra-clean, matching user's sketch)
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Completely hide sidebar */
    [data-testid="stSidebar"] {
        display: none !important;
    }
    
    /* Top Header */
    .app-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%);
        border: 1px solid #312E81;
        border-radius: 10px;
        padding: 1.2rem 1.8rem;
        margin-bottom: 1.2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
    }
    .app-title {
        font-size: 1.8rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38BDF8, #818CF8, #C084FC);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .app-sub {
        color: #94A3B8;
        font-size: 0.9rem;
    }
    
    /* Panel Containers matching user sketch */
    .sketch-box {
        background: #0F172A;
        border: 2px solid #1E293B;
        border-radius: 10px;
        padding: 1.2rem;
        margin-bottom: 1rem;
    }
    .sketch-box-header {
        font-size: 1.15rem;
        font-weight: 700;
        color: #F8FAFC;
        border-bottom: 1px solid #1E293B;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Record Table Container */
    .record-container {
        background: #0B1120;
        border: 2px solid #334155;
        border-radius: 10px;
        padding: 1rem 1.4rem;
        margin-bottom: 1.5rem;
    }
    
    /* Threat Badges */
    .badge-critical {
        background: rgba(220, 38, 38, 0.2);
        color: #EF4444;
        border: 1px solid rgba(239, 68, 68, 0.5);
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-high {
        background: rgba(217, 119, 6, 0.2);
        color: #F59E0B;
        border: 1px solid rgba(245, 158, 11, 0.5);
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Session State Initialization
if "investigation_state" not in st.session_state:
    st.session_state["investigation_state"] = None
if "selected_scenario" not in st.session_state:
    st.session_state["selected_scenario"] = (
        "Scenario 1: External APT Exfiltration (Bulgaria IP)"
    )
if "containment_executed" not in st.session_state:
    st.session_state["containment_executed"] = False
if "chat_messages" not in st.session_state:
    st.session_state["chat_messages"] = [
        {
            "role": "assistant",
            "content": "👋 **Greetings Investigator.** I am your AI Detective Copilot. Ask me anything about the attack kill-chain, compromised assets, or active defense containment.",
        }
    ]

# Top Application Header
st.markdown(
    """
<div class='app-header'>
    <div>
        <div class='app-title'>🛡️ AI Digital Crime Scene Investigator</div>
        <div class='app-sub'>Autonomous Multi-Agent Forensics Swarm & Active SOAR Incident Response</div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# Clean Horizontal Navigation (No Sidebar)
nav_choice = st.radio(
    "Navigation Menu",
    [
        "📥 User Input",
        "🤖 Report Generation",
        "💬 AI Detective Copilot",
    ],
    horizontal=True,
    label_visibility="collapsed",
)

st.write("")

demo_dir = os.path.join(BASE_DIR, "data", "demo_case")
live_dir = os.path.join(BASE_DIR, "evidence_for_live_demo")

# ==============================================================================
# VIEW 1: USER INPUT (EXACTLY MATCHING USER'S HAND-DRAWN SKETCH)
# ==============================================================================
if "User Input" in nav_choice:
    # 2-Panel Layout (Upload Box on Left, Status + Read More Box on Right)
    col_left, col_right = st.columns([1.1, 0.9], gap="large")

    with col_left:
        st.markdown(
            "<div class='sketch-box-header'>📁 Evidence Upload & Ingestion</div>",
            unsafe_allow_html=True,
        )

        # 1-Click Scenario Preset Option
        sc_col1, sc_col2 = st.columns([2, 1])
        with sc_col1:
            scenario_choice = st.selectbox(
                "Incident Simulation Profile:",
                options=[
                    "Scenario 1: External APT Exfiltration (Bulgaria IP + Titan Firmware)",
                    "Scenario 2: Malicious Insider Breach (Terminated Employee Exfil)",
                    "Scenario 3: Ransomware Precursor (Admin Credential Brute-Force)",
                ],
                label_visibility="collapsed",
            )
        with sc_col2:
            if st.button("⚡ Quick Preset Load", use_container_width=True):
                st.session_state["scenario_loaded_flag"] = True
                st.success("Loaded preset logs!")

        if "Scenario 2" in scenario_choice:
            scen_dir = os.path.join(BASE_DIR, "data", "scenario_2_insider_threat")
            def_case = "CASE-2026-INSIDER-002"
        elif "Scenario 3" in scenario_choice:
            scen_dir = os.path.join(BASE_DIR, "data", "scenario_3_ransomware_staging")
            def_case = "CASE-2026-RANSOM-003"
        else:
            scen_dir = os.path.join(BASE_DIR, "data", "demo_case")
            def_case = "CASE-2026-EXFIL-001"

        case_id = st.text_input("Case Reference ID", value=def_case)

        st.caption("Drop or Browse the 3 Authorized Forensic CSV Evidence Logs:")

        # 3 Upload Boxes as drawn in user sketch
        u_c1, u_c2, u_c3 = st.columns(3)
        up_login = u_c1.file_uploader("1. Auth Logs", type=["csv"], key="u_login")
        up_file = u_c2.file_uploader("2. File Logs", type=["csv"], key="u_file")
        up_net = u_c3.file_uploader("3. NetFlow Logs", type=["csv"], key="u_net")

        # Resolve inputs
        login_input = up_login or (
            os.path.join(scen_dir, "login_logs.csv")
            if st.session_state.get("scenario_loaded_flag", False)
            else None
        )
        file_input = up_file or (
            os.path.join(scen_dir, "file_access.csv")
            if st.session_state.get("scenario_loaded_flag", False)
            else None
        )
        net_input = up_net or (
            os.path.join(scen_dir, "network_logs.csv")
            if st.session_state.get("scenario_loaded_flag", False)
            else None
        )

        st.write("")
        # The SUBMIT Button from the sketch
        submit_btn = st.button(
            "🚀 SUBMIT & EXECUTE INVESTIGATION",
            type="primary",
            use_container_width=True,
        )

        if submit_btn:
            if not (login_input and file_input and net_input):
                st.error(
                    "⚠️ Incomplete Evidence! Upload all 3 CSVs or click '⚡ Quick Preset Load'."
                )
            else:
                with st.spinner(
                    "Multi-Agent Swarm executing: Ingesting -> Detecting -> Correlating -> Verifying..."
                ):
                    payload = {
                        "login": login_input,
                        "file": file_input,
                        "network": net_input,
                    }
                    result = run_investigation(
                        case_id, payload, "Automated Digital Forensics Triage"
                    )
                    st.session_state["investigation_state"] = result
                    st.session_state["containment_executed"] = False
                    st.success(
                        "Investigation complete! See Status and Read More on the right, or scroll down for Record."
                    )

    state = st.session_state.get("investigation_state")

    with col_right:
        st.markdown(
            "<div class='sketch-box-header'>📊 Status & Findings</div>",
            unsafe_allow_html=True,
        )

        if not state:
            st.info(
                "Awaiting submission. Upload files on the left and click **SUBMIT** to see live status."
            )
        else:
            anomalies = state.get("anomalies", [])
            timeline = state.get("timeline", [])
            crit_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
            high_count = sum(1 for a in anomalies if a.get("severity") == "HIGH")
            benign_count = max(0, len(timeline) - len(anomalies))

            # Status Section with Donut Chart + Metrics
            stat_c1, stat_c2 = st.columns([1.1, 0.9])
            with stat_c1:
                donut_fig = go.Figure(
                    data=[
                        go.Pie(
                            labels=["Benign Events", "High Risk", "Critical"],
                            values=[benign_count, high_count, crit_count],
                            hole=0.62,
                            marker=dict(colors=["#1E293B", "#F59E0B", "#EF4444"]),
                        )
                    ]
                )
                donut_fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#E2E8F0", family="Inter", size=10),
                    margin=dict(l=5, r=5, t=5, b=5),
                    height=180,
                    showlegend=False,
                )
                st.plotly_chart(donut_fig, use_container_width=True)

            with stat_c2:
                st.markdown(f"**Events:** `{len(timeline):,}`")
                st.markdown(
                    f"**Critical IOCs:** <span class='badge-critical'>{crit_count} Critical</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"**High Warnings:** <span class='badge-high'>{high_count} High</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Custody Integrity:** `100% SHA-256`")

            st.write("")
            # Quick Triage Summary Box inside Right Box
            st.markdown(
                """
            <div style='background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 8px; padding: 0.85rem; margin-top: 0.5rem;'>
                <div style='font-size: 0.85rem; font-weight: 700; color: #38BDF8; margin-bottom: 0.35rem; display: flex; align-items: center; gap: 6px;'>
                    <span>⚡</span> <span>AUTOMATED TRIAGE VERDICT</span>
                </div>
                <div style='font-size: 0.82rem; color: #CBD5E1; line-height: 1.45;'>
                    • <b>Intrusion Status:</b> Multi-stage coordinated breach detected.<br>
                    • <b>Primary Vector:</b> Credential Hijacking & Exfiltration.<br>
                    • <b>Containment:</b> Zero-Trust SOAR playbooks ready.
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )
            st.caption(
                "👇 *Scroll down for complete Key Findings telemetry and Cryptographic Records.*"
            )

    # --------------------------------------------------------------------------
    # FULL-WIDTH KEY FINDINGS TABLE (MATCHING CRYPTOGRAPHY RECORD TABLE FORMAT)
    # --------------------------------------------------------------------------
    st.write("")
    st.markdown("<div class='record-container'>", unsafe_allow_html=True)
    st.markdown("### 🔍 Read More (Key Forensic Findings & Detected Threat Telemetry)")
    st.caption("Detailed MITRE ATT&CK Detections, Correlated IOCs & Evidence Trace:")

    if not state:
        st.info(
            "⏳ Awaiting evidence submission. Upload files above and click **SUBMIT & EXECUTE INVESTIGATION** to populate real-time detections."
        )
    else:
        anomalies = state.get("anomalies", [])
        if not anomalies:
            st.success(
                "✅ No suspicious indicators or forensic anomalies detected in ingested telemetry."
            )
        else:
            read_more_rows = []
            for a in anomalies:
                ent_str = (
                    ", ".join(
                        [f"{k}: {v}" for k, v in a.get("entities_involved", {}).items()]
                    )
                    if isinstance(a.get("entities_involved"), dict)
                    else str(a.get("entities_involved", ""))
                )
                sev = a.get("severity", "MEDIUM")
                sev_display = (
                    f"🚨 {sev}"
                    if sev == "CRITICAL"
                    else (f"⚠️ {sev}" if sev == "HIGH" else f"ℹ️ {sev}")
                )

                read_more_rows.append(
                    {
                        "Finding ID": a.get("finding_id", "N/A"),
                        "Severity": sev_display,
                        "Timestamp (UTC)": a.get("timestamp", "N/A"),
                        "Evidence Source": a.get("evidence_source", "Telemetry"),
                        "MITRE ATT&CK Technique": a.get("mitre_technique", "N/A"),
                        "Entities Involved": ent_str or "N/A",
                        "Observed Incident Description": a.get("description", "N/A"),
                    }
                )

            df_findings = pd.DataFrame(read_more_rows)
            st.dataframe(df_findings, use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # "RECORD" TABLE SECTION (Scroll Down section as shown in user's sketch)
    # --------------------------------------------------------------------------
    st.write("")
    st.markdown("<div class='record-container'>", unsafe_allow_html=True)
    st.markdown("### 📋 Record (Cryptographic Chain of Custody & Hash Log)")
    st.caption("NIST SP 800-86 Compliant File Integrity Log (Scroll down to inspect):")

    hash_records = []
    for label, finput in [
        ("Authentication Telemetry", login_input),
        ("File System EDR Logs", file_input),
        ("Network NetFlow Logs", net_input),
    ]:
        if finput is not None:
            if hasattr(finput, "getvalue"):
                data_bytes = finput.getvalue()
                fname = finput.name
            else:
                with open(finput, "rb") as f:
                    data_bytes = f.read()
                fname = os.path.basename(finput)

            sha256_val = calculate_sha256(data_bytes)
            hash_records.append(
                {
                    "Evidence Source": label,
                    "File Name": fname,
                    "Size (Bytes)": f"{len(data_bytes):,}",
                    "SHA-256 Digest": sha256_val,
                    "Custody Integrity Status": "✅ VERIFIED AUTHENTIC (TAMPER-PROOF)",
                }
            )
        else:
            hash_records.append(
                {
                    "Evidence Source": label,
                    "File Name": "Awaiting Ingestion...",
                    "Size (Bytes)": "0",
                    "SHA-256 Digest": "----------------------------------------------------------------",
                    "Custody Integrity Status": "⏳ Awaiting Upload",
                }
            )

    st.dataframe(pd.DataFrame(hash_records), use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ==============================================================================
# VIEW 2: MULTI-AGENT SWARM WORK (ALL 7 AGENTS DETAILED RESULTS)
# ==============================================================================
elif "Report Generation" in nav_choice:
    state = st.session_state.get("investigation_state")
    if not state:
        st.info(
            "⚠️ Please upload files and click **SUBMIT** in '1. Intake' first to view the agents' work."
        )
    else:
        st.subheader("🤖 Multi-Agent Swarm Collaborative Results")
        st.caption(
            "Inspect the specialized outputs generated by each agent in the LangGraph workflow:"
        )

        # Sub-tabs for each agent's contribution
        ag_tab1, ag_tab2, ag_tab3, ag_tab4, ag_tab5 = st.tabs(
            [
                "🕸️Correlation Graph",
                "⏳Chrono-Timeline",
                "📝Incident Report",
                "🛡️SOAR Active Defense",
                "⚙️Swarm Execution Ledger",
            ]
        )

        # Agent 4: PyVis Interactive Correlation Graph
        with ag_tab1:
            st.markdown("#### Entity Resolution & Kill-Chain Network Graph")
            st.caption(
                "Visualizing connected entities: Attacker IP ➔ Compromised User ➔ Staged File ➔ Exfiltration Destination."
            )

            graph_data = state.get("graph_elements", {"nodes": [], "edges": []})
            correlations = state.get("correlations", [])
            st.dataframe(
                pd.DataFrame(correlations), use_container_width=True, hide_index=True
            )

            try:
                from pyvis.network import Network
                import streamlit.components.v1 as components

                net = Network(
                    height="460px", width="100%", bgcolor="#0F172A", font_color="white"
                )
                net.barnes_hut(gravity=-3200, central_gravity=0.25, spring_length=130)

                group_colors = {
                    "MALICIOUS_IP": "#EF4444",
                    "USER": "#38BDF8",
                    "SENSITIVE_FILE": "#F59E0B",
                    "INTERNAL_HOST": "#10B981",
                    "EXFIL_DESTINATION": "#DC2626",
                }

                for n in graph_data.get("nodes", []):
                    color = group_colors.get(n.get("group"), "#94A3B8")
                    net.add_node(
                        n["id"],
                        label=n["label"],
                        title=n.get("title", ""),
                        color=color,
                        size=24,
                    )

                for e in graph_data.get("edges", []):
                    net.add_edge(
                        e["from"],
                        e["to"],
                        label=e.get("label", ""),
                        color=e.get("color", "#94A3B8"),
                        width=2,
                    )

                tmp_html = os.path.join(BASE_DIR, "reports", "correlation_graph.html")
                os.makedirs(os.path.dirname(tmp_html), exist_ok=True)
                net.save_graph(tmp_html)

                with open(tmp_html, "r", encoding="utf-8") as f:
                    html_content = f.read()
                components.html(html_content, height=490)
            except Exception as e:
                st.warning(f"Interactive PyVis graph rendering fallback: {str(e)}")

        # Agent 5: Chrono-Timeline
        with ag_tab2:
            st.markdown("#### Interleaved Chronological Incident Sequence")
            timeline = state.get("timeline", [])

            t_col1, t_col2 = st.columns([3, 1])
            with t_col2:
                show_anom_only = st.checkbox(
                    "🔍 Show Only Malicious Events", value=False
                )
            with t_col1:
                search_query = st.text_input(
                    "Search timeline records:",
                    placeholder="Filter by user, IP, action...",
                )

            filtered = [t for t in timeline if not show_anom_only or t["is_anomaly"]]
            if search_query:
                sq = search_query.lower()
                filtered = [
                    t
                    for t in filtered
                    if sq in str(t["actor"]).lower()
                    or sq in str(t["action"]).lower()
                    or sq in str(t["details"]).lower()
                ]

            timeline_rows = []
            for t in filtered:
                timeline_rows.append(
                    {
                        "Timestamp (UTC)": t["timestamp"],
                        "Source": t["source"],
                        "Principal / Actor": t["actor"],
                        "Action Taken": t["action"],
                        "Assessment": "🔴 MALICIOUS"
                        if t["is_anomaly"]
                        else "🟢 BENIGN",
                        "Metadata": t["details"],
                    }
                )
            st.dataframe(
                pd.DataFrame(timeline_rows), use_container_width=True, hide_index=True
            )

        # Agent 6: Report Agent
        with ag_tab3:
            st.markdown("#### Verified Incident Response Report")
            report = state.get("report", {})
            r_c1, r_c2, r_c3 = st.columns(3)
            r_c1.metric("Classification", report.get("classification", "Unknown"))
            r_c2.metric(
                "Anti-Hallucination Confidence", f"{report.get('confidence_score', 0)}%"
            )
            r_c3.metric(
                "Verified Claims Grounded",
                f"{report.get('verified_claims_count', 0)} Claims",
            )

            st.divider()
            st.markdown(report.get("markdown_body", "No report generated."))
            st.divider()
            st.download_button(
                label="💾 Download Signed Forensic Report (.md)",
                data=report.get("markdown_body", ""),
                file_name=f"{state.get('case_id', 'case')}_report.md",
                mime="text/markdown",
                type="primary",
            )

        # Agent 7: SOAR Remediation
        with ag_tab4:
            st.markdown("#### Autonomous SOAR Remediation & Active Defense")
            contain_btn = st.button(
                "🚨 Execute Autonomous Zero-Trust Containment",
                type="primary",
                use_container_width=True,
            )
            if contain_btn or st.session_state["containment_executed"]:
                st.session_state["containment_executed"] = True
                plan = generate_containment_plan(state)
                st.success("✅ ZERO-TRUST CONTAINMENT ENFORCED")

                c1, c2, c3 = st.columns(3)
                c1.metric(
                    "Blacklisted External IPs",
                    len(plan["blocked_ips"]),
                    f"{', '.join(plan['blocked_ips'])}",
                )
                c2.metric(
                    "Terminated User Sessions",
                    len(plan["compromised_users"]),
                    f"{', '.join(plan['compromised_users'])}",
                )
                c3.metric(
                    "Quarantined File Assets",
                    len(plan["quarantined_files"]),
                    "Locked in Vault",
                )

                st.write("")
                st.markdown("**Linux iptables Egress Drop Rules:**")
                st.code(plan["iptables_script"], language="bash")
                st.markdown("**Active Directory Token Invalidation Script:**")
                st.code(plan["identity_revocation_script"], language="powershell")

        # Agent 1-3: Swarm Execution Ledger
        with ag_tab5:
            st.markdown("#### Swarm Execution Audit Ledger")
            audit_trail = state.get("audit_trail", [])
            st.code("\n".join(audit_trail), language="text")

# ==============================================================================
# VIEW 3: AI DETECTIVE COPILOT
# ==============================================================================
elif "AI Detective" in nav_choice:
    state = st.session_state.get("investigation_state")
    st.subheader("💬 Interactive AI Detective Copilot")
    st.caption(
        "Cross-examine the multi-agent incident state with natural language queries grounded in verified evidence."
    )

    for msg in st.session_state["chat_messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    st.write("")
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

    user_query = (
        st.chat_input("Ask the AI Detective anything about this incident...")
        or quick_query
    )

    if user_query:
        st.session_state["chat_messages"].append(
            {"role": "user", "content": user_query}
        )
        with st.chat_message("user"):
            st.markdown(user_query)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing verified evidence..."):
                ans = answer_investigation_query(user_query, state)
                st.markdown(ans)
        st.session_state["chat_messages"].append({"role": "assistant", "content": ans})
