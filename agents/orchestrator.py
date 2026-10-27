import importlib
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, START, END

from . import evidence_agent
from . import anomaly_agent
from . import correlation_agent
from . import timeline_agent
from . import report_agent

class InvestigationState(TypedDict, total=False):
    case_id: str
    case_title: str
    input_files: Dict[str, Any]
    evidence_files: List[Dict[str, Any]]
    raw_dataframes: Dict[str, Any]
    anomalies: List[Dict[str, Any]]
    correlations: List[Dict[str, Any]]
    graph_elements: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    report: Dict[str, Any]
    audit_trail: List[str]

def build_investigation_graph():
    """Constructs the LangGraph Multi-Agent Forensic Investigation Workflow."""
    importlib.reload(evidence_agent)
    importlib.reload(anomaly_agent)
    importlib.reload(correlation_agent)
    importlib.reload(timeline_agent)
    importlib.reload(report_agent)

    workflow = StateGraph(InvestigationState)

    # Register Nodes
    workflow.add_node("evidence_agent", evidence_agent.evidence_node)
    workflow.add_node("anomaly_agent", anomaly_agent.anomaly_node)
    workflow.add_node("correlation_agent", correlation_agent.correlation_node)
    workflow.add_node("timeline_agent", timeline_agent.timeline_node)
    workflow.add_node("report_agent", report_agent.report_node)

    # Define Workflow Edges
    workflow.add_edge(START, "evidence_agent")
    workflow.add_edge("evidence_agent", "anomaly_agent")
    workflow.add_edge("anomaly_agent", "correlation_agent")
    workflow.add_edge("correlation_agent", "timeline_agent")
    workflow.add_edge("timeline_agent", "report_agent")
    workflow.add_edge("report_agent", END)

    return workflow.compile()

def run_investigation(case_id: str, input_files: Dict[str, Any], case_title: str = "") -> Dict[str, Any]:
    """
    Main entrypoint called by the Streamlit application.
    Executes the multi-agent investigation swarm and returns the complete state.
    """
    investigation_app = build_investigation_graph()
    initial_state: InvestigationState = {
        "case_id": case_id,
        "case_title": case_title or case_id,
        "input_files": input_files,
        "evidence_files": [],
        "raw_dataframes": {},
        "anomalies": [],
        "correlations": [],
        "graph_elements": {"nodes": [], "edges": []},
        "timeline": [],
        "report": {},
        "audit_trail": [f"[Orchestrator] Initiated autonomous investigation for {case_id}."]
    }

    final_state = investigation_app.invoke(initial_state)
    return final_state
