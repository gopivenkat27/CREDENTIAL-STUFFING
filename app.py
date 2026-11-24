"""AI-Powered Credential-Stuffing Detection System - Streamlit Dashboard.

Interactive Cybersecurity Threat Hunting and Advisory Console.
"""

import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Local Modules
from src.database import (
    get_summary_stats,
    get_all_events,
    get_recent_predictions,
    save_prediction,
    DEFAULT_DB_PATH
)
from src.predict import CredentialStuffingAdvisor
from src.feature_engineering import FEATURE_COLUMNS, UA_RISK_MAP

# Page Configuration
st.set_page_config(
    page_title="AI Credential-Stuffing Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cybersecurity Dark Theme CSS
st.markdown("""
<style>
    /* Dark Theme Cyber Aesthetics */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .main-header {
        background: linear-gradient(90deg, #1f242d 0%, #161b22 100%);
        border-left: 5px solid #00d2ff;
        padding: 1.2rem 1.8rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 15px rgba(0, 210, 255, 0.1);
    }
    .main-title {
        color: #ffffff;
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: 0.5px;
        margin: 0;
    }
    .main-subtitle {
        color: #58a6ff;
        font-size: 1.05rem;
        margin-top: 0.3rem;
        font-weight: 500;
    }
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin: 0.2rem 0;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8b949e;
    }
    .badge-normal {
        background-color: rgba(46, 160, 67, 0.2);
        color: #3fb950;
        border: 1px solid #2ea043;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 600;
    }
    .badge-suspicious {
        background-color: rgba(210, 153, 34, 0.2);
        color: #d29922;
        border: 1px solid #bb8009;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 600;
    }
    .badge-attack {
        background-color: rgba(248, 81, 73, 0.2);
        color: #f85149;
        border: 1px solid #da3633;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 600;
    }
    .advisory-box {
        background-color: #161b22;
        border: 1px solid #00d2ff;
        border-radius: 8px;
        padding: 1.2rem;
        margin-top: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Advisor in Session State
@st.cache_resource
def load_advisor():
    return CredentialStuffingAdvisor()

advisor = load_advisor()


# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/fluency/96/cyber-security.png", width=70)
st.sidebar.title("🛡️ SOC Threat Console")
st.sidebar.markdown("**Credential-Stuffing Detection**")
st.sidebar.markdown("---")

nav_choice = st.sidebar.radio(
    "Navigation Menu",
    [
        "🏠 Home Dashboard",
        "🔍 Login Event Analysis",
        "🤖 AI Threat Detection",
        "📊 Data Visualizations",
        "🛡️ Security Recommendations",
        "📈 Model Performance"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown(f"**System Engine:** Active")
st.sidebar.markdown(f"**Architecture:** Sequential ML")
st.sidebar.markdown(f"**Database:** SQLite3 Connected")
st.sidebar.info("College B.Tech Mini Project Demo\nThreat Detection & Advisory Console")


# ==============================================================================
# SECTION A: HOME DASHBOARD
# ==============================================================================
if nav_choice == "🏠 Home Dashboard":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">AI-POWERED CREDENTIAL-STUFFING DETECTION SYSTEM</h1>
        <div class="main-subtitle">A Sequential Machine Learning Classifier & Rate-Limiting Advisory Service</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Project Introduction
    st.markdown("""
    ### 🎯 Executive Abstract
    **Credential-stuffing attacks** occur when automated adversaries weaponize vast databases of leaked username/password combos,
    submitting them against an authentication portal in rapid automated streams. Unlike single-account brute-force attacks, 
    credential stuffing scatters attempts across hundreds of accounts from distributed or rotating IPs, rendering traditional threshold-based rate limiters blind.
    
    This system implements a **Sequential ML Classifier** that models temporal transitions, inter-arrival time jitter, burst rates,
    and sliding-window account diversity to detect stealthy attacks before accounts are compromised.
    """)
    
    # Fetch DB Statistics
    stats = get_summary_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Login Events</div>
            <div class="metric-value" style="color: #58a6ff;">{stats['total_events']:,}</div>
            <div style="color: #8b949e; font-size: 0.8rem;">Logged Server Stream</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Normal Logins</div>
            <div class="metric-value" style="color: #3fb950;">{stats['normal_count']:,}</div>
            <div style="color: #8b949e; font-size: 0.8rem;">Legitimate Users</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Suspicious Logins</div>
            <div class="metric-value" style="color: #d29922;">{stats['suspicious_count']:,}</div>
            <div style="color: #8b949e; font-size: 0.8rem;">Anomalous Patterns</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Credential Stuffing</div>
            <div class="metric-value" style="color: #f85149;">{stats['attack_count']:,}</div>
            <div style="color: #8b949e; font-size: 0.8rem;">High-Risk Bot Activity</div>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("---")
    
    # Quick Architecture Overview
    st.subheader("⚙️ System Pipeline Overview")
    cols = st.columns(3)
    with cols[0]:
        st.markdown("""
        #### 1. Event Telemetry
        - Captures real-time server authentication streams
        - Tracks IP, user ID, client user-agents, and timestamp deltas
        - Fully documentation-safe synthetic test logs
        """)
    with cols[1]:
        st.markdown("""
        #### 2. Sequential Analysis
        - Multi-step sliding window ($W=3$)
        - Account diversity ratio per IP window
        - Inter-arrival jitter and velocity modeling
        """)
    with cols[2]:
        st.markdown("""
        #### 3. Defensive Advisory
        - Real-time threat classification (3 tiers)
        - Dynamic IP rate-limiting advisories
        - Multi-factor step-up challenge triggers
        """)


# ==============================================================================
# SECTION B: LOGIN EVENT ANALYSIS
# ==============================================================================
elif nav_choice == "🔍 Login Event Analysis":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">LOGIN EVENT TELEMETRY & ANALYSIS</h1>
        <div class="main-subtitle">Search, inspect, and filter historical authentication records</div>
    </div>
    """, unsafe_allow_html=True)
    
    col_filter1, col_filter2, col_filter3 = st.columns([2, 1, 1])
    with col_filter1:
        search_query = st.text_input("🔍 Search by User ID, IP Address, or Event ID", "")
    with col_filter2:
        risk_filter = st.selectbox("Filter Risk Classification", ["All", "Normal", "Suspicious", "Credential Stuffing"])
    with col_filter3:
        record_limit = st.slider("Display Limit", min_value=50, max_value=2000, value=200, step=50)
        
    events = get_all_events(limit=record_limit, search_query=search_query, filter_risk=risk_filter)
    
    if events:
        df_events = pd.DataFrame(events)
        
        # Color-coded display table
        display_cols = [
            "event_id", "timestamp", "user_id", "source_ip",
            "login_status", "attempts_in_time_window",
            "unique_accounts_in_window", "time_between_attempts",
            "user_agent_category", "risk_label"
        ]
        
        st.dataframe(
            df_events[display_cols],
            use_container_width=True,
            height=450
        )
        
        st.markdown(f"**Showing {len(df_events)} matched login records.**")
        
        # Download Option
        csv_data = df_events.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Filtered Events to CSV",
            data=csv_data,
            file_name="login_events_export.csv",
            mime="text/csv"
        )
    else:
        st.warning("No records matched your search filter.")


# ==============================================================================
# SECTION C: AI THREAT DETECTION (INTERACTIVE LAB)
# ==============================================================================
elif nav_choice == "🤖 AI Threat Detection":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">AI REAL-TIME THREAT DETECTION</h1>
        <div class="main-subtitle">Interactive evaluation lab: simulate login streams and test sequential ML classification</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("Adjust the event parameters below to observe how the **Sequential Classifier** classifies authentication behavior:")
    
    # Preset scenarios for quick demo
    preset = st.selectbox(
        "⚡ Choose a Quick Scenario Preset:",
        [
            "Custom Parameters",
            "Scenario 1: Legitimate User Login (Normal)",
            "Scenario 2: Forgotten Password / Typo (Suspicious)",
            "Scenario 3: Distributed Credential Stuffing Attack (High Risk)"
        ]
    )
    
    # Defaults
    def_user = "USER_0142"
    def_ip = "192.168.1.45"
    def_status = "SUCCESS"
    def_failed = 0
    def_success = 1
    def_attempts_win = 1
    def_unique_acc = 1
    def_delta = 120.0
    def_ua = "Standard Browser"
    
    if preset == "Scenario 1: Legitimate User Login (Normal)":
        def_user = "USER_0088"
        def_ip = "192.168.1.12"
        def_status = "SUCCESS"
        def_failed = 0
        def_success = 3
        def_attempts_win = 1
        def_unique_acc = 1
        def_delta = 350.0
        def_ua = "Standard Browser"
    elif preset == "Scenario 2: Forgotten Password / Typo (Suspicious)":
        def_user = "USER_0210"
        def_ip = "192.168.1.75"
        def_status = "FAILED"
        def_failed = 4
        def_success = 0
        def_attempts_win = 5
        def_unique_acc = 1
        def_delta = 12.0
        def_ua = "Standard Browser"
    elif preset == "Scenario 3: Distributed Credential Stuffing Attack (High Risk)":
        def_user = "USER_0944"
        def_ip = "198.51.100.18"
        def_status = "FAILED"
        def_failed = 28
        def_success = 0
        def_attempts_win = 45
        def_unique_acc = 24
        def_delta = 0.45
        def_ua = "Automated Script/Bot"
        
    with st.form("threat_sim_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            in_user = st.text_input("User ID", def_user)
            in_ip = st.text_input("Source IP Address", def_ip)
            in_status = st.selectbox("Login Status", ["SUCCESS", "FAILED"], index=0 if def_status == "SUCCESS" else 1)
        with col2:
            in_failed = st.number_input("Failed Attempts Count", min_value=0, max_value=200, value=def_failed)
            in_success = st.number_input("Successful Attempts Count", min_value=0, max_value=50, value=def_success)
            in_delta = st.number_input("Time Between Attempts (seconds)", min_value=0.01, max_value=3600.0, value=float(def_delta), step=0.5)
        with col3:
            in_attempts_win = st.number_input("Attempts in Sliding Window (5m)", min_value=1, max_value=500, value=def_attempts_win)
            in_unique_acc = st.number_input("Unique Accounts in Window", min_value=1, max_value=200, value=def_unique_acc)
            ua_options = ["Standard Browser", "Mobile App", "Outdated Browser", "Automated Script/Bot", "Headless Chrome"]
            in_ua = st.selectbox("User Agent Category", ua_options, index=ua_options.index(def_ua) if def_ua in ua_options else 0)
            
        submit_btn = st.form_submit_button("🛡️ Execute AI Threat Analysis", use_container_width=True)
        
    if submit_btn:
        test_payload = {
            "user_id": in_user,
            "source_ip": in_ip,
            "login_status": in_status,
            "failed_attempts": in_failed,
            "successful_attempts": in_success,
            "attempts_in_time_window": in_attempts_win,
            "unique_accounts_in_window": in_unique_acc,
            "time_between_attempts": in_delta,
            "user_agent_category": in_ua
        }
        
        try:
            result = advisor.analyze_event(test_payload, persist=True)
            
            st.markdown("---")
            st.subheader("🎯 AI Inference Results")
            
            pcol1, pcol2, pcol3 = st.columns([1, 1, 2])
            with pcol1:
                p_class = result["predicted_class"]
                if p_class == 0:
                    badge_html = '<span class="badge-normal" style="font-size: 1.3rem;">NORMAL LOGIN</span>'
                elif p_class == 1:
                    badge_html = '<span class="badge-suspicious" style="font-size: 1.3rem;">SUSPICIOUS ACTIVITY</span>'
                else:
                    badge_html = '<span class="badge-attack" style="font-size: 1.3rem;">CREDENTIAL STUFFING</span>'
                st.markdown(f"**Classification:**")
                st.markdown(badge_html, unsafe_allow_html=True)
                
            with pcol2:
                r_score = result["risk_score"]
                st.metric("Threat Risk Score", f"{r_score * 100:.1f}%")
                st.progress(r_score)
                
            with pcol3:
                st.markdown(f"**Threat Severity:** `{result['risk_category']}`")
                st.write(result["explanation"])
                
            # Class Probabilities Breakdown
            probs = result["class_probabilities"]
            prob_df = pd.DataFrame({
                "Threat Class": list(probs.keys()),
                "Model Confidence": [v * 100 for v in probs.values()]
            })
            
            fig = px.bar(
                prob_df,
                x="Model Confidence",
                y="Threat Class",
                orientation='h',
                color="Threat Class",
                color_discrete_map={
                    "Normal": "#2ea043",
                    "Suspicious": "#d29922",
                    "Credential Stuffing": "#f85149"
                },
                text_auto='.1f'
            )
            fig.update_layout(
                paper_bgcolor="#161b22",
                plot_bgcolor="#161b22",
                font_color="#c9d1d9",
                height=220,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Advisory Box
            st.markdown(f"""
            <div class="advisory-box">
                <h4 style="color: #00d2ff; margin-top: 0;">🛡️ Defensive Advisory Service Action:</h4>
                <p style="font-size: 1.1rem; color: #ffffff;">{result['advisory_action']}</p>
            </div>
            """, unsafe_allow_html=True)
            
        except Exception as e:
            st.error(f"Inference failed: {e}. Please ensure the model has finished training.")


# ==============================================================================
# SECTION D: DATA VISUALIZATIONS
# ==============================================================================
elif nav_choice == "📊 Data Visualizations":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">THREAT INTELLIGENCE & DATA VISUALIZATIONS</h1>
        <div class="main-subtitle">Statistical exploration of authentication dynamics and attack vectors</div>
    </div>
    """, unsafe_allow_html=True)
    
    events = get_all_events(limit=1500)
    if events:
        df = pd.DataFrame(events)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        
        # 1. Timeline Chart
        st.subheader("📈 Login Velocity & Threat Distribution Over Time")
        df_time = df.set_index("timestamp").resample("1h")["event_id"].count().reset_index()
        fig_time = px.line(
            df_time,
            x="timestamp",
            y="event_id",
            title="Hourly Authentication Request Volume",
            labels={"event_id": "Number of Attempts", "timestamp": "Timestamp"},
            color_discrete_sequence=["#00d2ff"]
        )
        fig_time.update_layout(paper_bgcolor="#161b22", plot_bgcolor="#161b22", font_color="#c9d1d9")
        st.plotly_chart(fig_time, use_container_width=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🍩 Overall Threat Classification Proportion")
            risk_counts = df["risk_label"].value_counts().reset_index()
            risk_counts.columns = ["Risk Classification", "Count"]
            fig_pie = px.pie(
                risk_counts,
                values="Count",
                names="Risk Classification",
                hole=0.45,
                color="Risk Classification",
                color_discrete_map={
                    "Normal": "#2ea043",
                    "Suspicious": "#d29922",
                    "Credential Stuffing": "#f85149"
                }
            )
            fig_pie.update_layout(paper_bgcolor="#161b22", font_color="#c9d1d9")
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col2:
            st.subheader("📊 Failed vs Successful Attempts by Category")
            status_summary = df.groupby(["risk_label", "login_status"])["event_id"].count().reset_index()
            fig_bar = px.bar(
                status_summary,
                x="risk_label",
                y="event_id",
                color="login_status",
                barmode="group",
                labels={"event_id": "Event Count", "risk_label": "Threat Level"},
                color_discrete_map={"SUCCESS": "#2ea043", "FAILED": "#f85149"}
            )
            fig_bar.update_layout(paper_bgcolor="#161b22", plot_bgcolor="#161b22", font_color="#c9d1d9")
            st.plotly_chart(fig_bar, use_container_width=True)
            
        # 2. Scatter: Credential Stuffing Signature Cluster
        st.subheader("🎯 Attack Signature: Account Diversity vs Inter-Arrival Time")
        st.markdown(
            "Notice how **Credential Stuffing** forms a distinct cluster at the top-left: "
            "sub-second request deltas with extreme numbers of unique target accounts!"
        )
        fig_scatter = px.scatter(
            df.sample(min(800, len(df))),
            x="time_between_attempts",
            y="unique_accounts_in_window",
            color="risk_label",
            size="attempts_in_time_window",
            hover_data=["source_ip", "user_id"],
            labels={
                "time_between_attempts": "Inter-Arrival Interval (Seconds)",
                "unique_accounts_in_window": "Distinct Accounts Tested in Window"
            },
            color_discrete_map={
                "Normal": "#2ea043",
                "Suspicious": "#d29922",
                "Credential Stuffing": "#f85149"
            }
        )
        fig_scatter.update_layout(paper_bgcolor="#161b22", plot_bgcolor="#161b22", font_color="#c9d1d9")
        st.plotly_chart(fig_scatter, use_container_width=True)


# ==============================================================================
# SECTION E: SECURITY RECOMMENDATIONS
# ==============================================================================
elif nav_choice == "🛡️ Security Recommendations":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">DEFENSIVE RATE-LIMITING & LOCKOUT ADVISORY</h1>
        <div class="main-subtitle">Policy recommendations to mitigate automated authentication threats</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    ### 🛡️ Layered Mitigation Playbook
    To safely block automated credential stuffing without locking out legitimate users who mistype their passwords,
    the advisory service recommends a **progressive risk-based defense architecture**:
    """)
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        #### Tier 1: Normal Activity
        - **Threat Level:** Class 0 (Low Risk)
        - **Policy:** Allow seamless authentication session.
        - **Monitoring:** Standard access logging.
        - **User Friction:** Zero friction.
        """)
    with c2:
        st.markdown("""
        #### Tier 2: Suspicious Activity
        - **Threat Level:** Class 1 (Medium Risk)
        - **Policy:** Step-up Authentication.
        - **Mitigation:**
          - Require Multi-Factor (MFA / OTP)
          - Inject invisible reCAPTCHA v3
          - Transient per-user velocity throttling
        """)
    with c3:
        st.markdown("""
        #### Tier 3: Credential Stuffing
        - **Threat Level:** Class 2 (High / Critical)
        - **Policy:** Dynamic Rate Limiting & Lockout Advisory.
        - **Mitigation:**
          - Temporary IP bucket throttle (15-min ban)
          - Enforce hard challenge (Cloudflare Turnstile)
          - Alert SecOps SOC team
          - Advise account security review
        """)
        
    st.markdown("---")
    st.subheader("📋 Recent Predictive Advisories Issued")
    preds = get_recent_predictions(limit=15)
    if preds:
        st.dataframe(pd.DataFrame(preds)[["timestamp", "source_ip", "user_id", "predicted_label", "risk_score", "advisory_action"]])
    else:
        st.info("No predictive advisories issued yet. Test an event in 'AI Threat Detection' to populate.")


# ==============================================================================
# SECTION F: MODEL PERFORMANCE
# ==============================================================================
elif nav_choice == "📈 Model Performance":
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">MACHINE LEARNING PERFORMANCE BENCHMARKS</h1>
        <div class="main-subtitle">Detailed evaluation metrics, confusion matrices, and feature importance analysis</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Load evaluation JSON report
    metrics_path = Path("reports/evaluation_metrics.json")
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)
            
        seq_m = metrics["sequential_model"]
        base_m = metrics["baseline_model"]
        
        st.subheader("🎯 Primary Evaluation Metrics (Sequential Classifier)")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Accuracy", f"{seq_m['accuracy'] * 100:.2f}%", f"+{(seq_m['accuracy'] - base_m['accuracy']) * 100:.2f}% vs Base")
        m2.metric("Precision (Weighted)", f"{seq_m['precision'] * 100:.2f}%")
        m3.metric("Recall (Weighted)", f"{seq_m['recall'] * 100:.2f}%")
        m4.metric("F1-Score (Weighted)", f"{seq_m['f1_score'] * 100:.2f}%")
        
        st.markdown("---")
        
        col_cm, col_comp = st.columns(2)
        with col_cm:
            st.subheader("🔲 Confusion Matrix Heatmap")
            cm_img_path = Path("reports/confusion_matrix.png")
            if cm_img_path.exists():
                st.image(str(cm_img_path), use_container_width=True)
            else:
                st.info("Run evaluation script to generate confusion matrix image.")
                
        with col_comp:
            st.subheader("📊 Model Comparison: Sequential vs Baseline")
            comp_img_path = Path("reports/model_comparison.png")
            if comp_img_path.exists():
                st.image(str(comp_img_path), use_container_width=True)
            else:
                st.info("Run evaluation script to generate comparison chart.")
                
        st.subheader("🌟 Most Influential Features in Attack Classification")
        fi_img_path = Path("reports/feature_importance.png")
        if fi_img_path.exists():
            st.image(str(fi_img_path), use_container_width=True)
            
        st.markdown("---")
        st.subheader("💡 Metric Definitions for Viva & Review")
        for k, v in metrics["metrics_explanation"].items():
            st.markdown(f"- **{k}:** {v}")
    else:
        st.warning("Performance report not yet generated. Please execute model training and evaluation first.")
