"""Master Application Launcher for Credential-Stuffing Attack Detection System.

Orchestrates the entire college mini project pipeline:
1. Verifies/Generates synthetic login dataset (6,000 events)
2. Initializes SQLite database and loads events
3. Trains the Sequential ML Classifier and Baseline Model (if not already cached)
4. Generates evaluation reports and visualizations
5. Launches the interactive Streamlit Cybersecurity Dashboard

Usage:
    python run.py
"""

import os
import sys
import subprocess
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def print_banner():
    banner = r"""
================================================================================
    CREDENTIAL-STUFFING ATTACK DETECTION: SEQUENTIAL ML CLASSIFIER
           Cybersecurity & AI-Driven Threat Mitigation System
================================================================================
    """
    print(banner)


def check_and_bootstrap_pipeline():
    """Ensure data, database, and models exist before starting UI."""
    data_raw_path = PROJECT_ROOT / "data" / "raw" / "synthetic_login_events.csv"
    model_path = PROJECT_ROOT / "models" / "sequential_classifier.joblib"
    eval_report = PROJECT_ROOT / "reports" / "evaluation_metrics.json"
    
    # 1. Dataset Generation
    if not data_raw_path.exists():
        print("[*] Stage 1: Generating 6,000 synthetic login event streams...")
        from src.data_generator import generate_synthetic_data
        generate_synthetic_data(num_events=6000, output_path=str(data_raw_path))
    else:
        print(f"[+] Stage 1: Dataset already present at {data_raw_path}")

    # 2. Database Population
    print("[*] Stage 2: Synchronizing SQLite database...")
    from src.database import init_db, insert_batch_events, get_summary_stats
    import pandas as pd
    init_db()
    stats = get_summary_stats()
    if stats["total_events"] == 0:
        print("[*] Loading raw events into SQLite database...")
        df_raw = pd.read_csv(data_raw_path)
        insert_batch_events(df_raw.to_dict(orient="records"))
        stats = get_summary_stats()
    print(f"[+] Stage 2: Database contains {stats['total_events']:,} logged authentication events.")

    # 3. Model Training
    if not model_path.exists():
        print("[*] Stage 3: Training Sequential ML Classifier & Baseline Model...")
        from src.train_model import train_models
        train_models(raw_csv_path=str(data_raw_path))
    else:
        print(f"[+] Stage 3: Trained ML model loaded from {model_path}")

    # 4. Evaluation and Visualizations
    if not eval_report.exists():
        print("[*] Stage 4: Computing evaluation metrics and generating report figures...")
        from src.evaluate_model import evaluate_system
        evaluate_system()
    else:
        print(f"[+] Stage 4: Evaluation metrics verified at {eval_report}")


def launch_dashboard():
    """Launch Streamlit frontend application."""
    app_path = PROJECT_ROOT / "dashboard" / "app.py"
    print("\n" + "=" * 80)
    print("LAUNCHING STREAMLIT CYBERSECURITY DASHBOARD")
    print(f"Target: {app_path}")
    print("=" * 80)
    print("[+] Dashboard starting... Press Ctrl+C in terminal to stop.")
    
    # Run streamlit executable from the same python environment
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.headless", "true",
        "--server.port", "8501"
    ]
    
    subprocess.run(cmd)


def main():
    print_banner()
    check_and_bootstrap_pipeline()
    launch_dashboard()


if __name__ == "__main__":
    main()
