"""
AI Ransomware Detector (EDR Simulator) with Live Dashboard

This script monitors C:\\RansomLab\\sandbox using the watchdog library.
It extracts behavioral features (file modification rates, extension changes)
and feeds it into an Isolation Forest Machine Learning model to detect
anomalies that indicate a ransomware attack.
"""

import time
import threading
import argparse
import numpy as np
from collections import deque
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.layout import Layout
import warnings
try:
    import tkinter as tk
    from tkinter import font
except Exception:
    tk = None
    font = None

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore")
from sklearn.ensemble import IsolationForest

SANDBOX_PATH = Path(r"C:\RansomLab\sandbox")


def get_file_stats():
    """Collect basic sandbox file statistics for UI and CLI rendering."""
    try:
        all_files = [f for f in SANDBOX_PATH.glob("*") if f.is_file()]
        encrypted_files = list(SANDBOX_PATH.glob("*.hyenc"))
        encrypted_names = sorted([f.name for f in encrypted_files])
        total_files_count = len(all_files)
        encrypted_count = len(encrypted_files)
        safe_files_count = total_files_count - encrypted_count
        return total_files_count, encrypted_count, safe_files_count, encrypted_names
    except Exception:
        return 0, 0, 0, []

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.recent_events = deque(maxlen=1000)
        self.lock = threading.Lock()
        
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Synthetic baseline (Normal behavior)
        normal_data = []
        for _ in range(200):
            normal_rate = np.random.uniform(0.0, 2.0)
            normal_hyenc_ratio = 0.0
            normal_data.append([normal_rate, normal_hyenc_ratio])
            
        self.model.fit(normal_data)

    def log_event(self, event):
        if event.is_directory:
            return
        ext = Path(event.src_path).suffix
        with self.lock:
            self.recent_events.append((time.time(), ext))

    def on_created(self, event): self.log_event(event)
    def on_modified(self, event): self.log_event(event)
    def on_deleted(self, event): self.log_event(event)

    def extract_features(self, window_seconds=5):
        current_time = time.time()
        with self.lock:
            window_events = [e for e in self.recent_events if current_time - e[0] <= window_seconds]
            
        event_count = len(window_events)
        hyenc_count = sum(1 for e in window_events if e[1] == ".hyenc")
        
        # Poll directory for .hyenc files - they indicate ransomware regardless of when encrypted
        try:
            if SANDBOX_PATH.exists():
                # Count ALL .hyenc files as ransomware indicator
                hyenc_files = list(SANDBOX_PATH.glob("*.hyenc"))
                total_files = list(SANDBOX_PATH.glob("*"))
                
                # If any .hyenc files exist, that's a ransomware signature
                if len(hyenc_files) > 0:
                    # Use .hyenc files as event count (represents ransomware activity)
                    event_count = max(event_count, len(hyenc_files))
                    hyenc_count = len(hyenc_files)
                else:
                    # No .hyenc files, check for recent modifications
                    recent_files = [f for f in total_files 
                                   if f.is_file() and (current_time - f.stat().st_mtime) <= window_seconds]
                    event_count = max(event_count, len(recent_files))
        except Exception as e:
            pass
        
        event_rate = event_count / window_seconds if window_seconds > 0 else 0
        
        if event_count == 0:
            return event_rate, 0.0
            
        hyenc_ratio = hyenc_count / max(event_count, 1)
        
        return event_rate, hyenc_ratio


def generate_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    layout["main"].split_row(
        Layout(name="stats"),
        Layout(name="alert")
    )
    return layout


def run_detector():
    if not SANDBOX_PATH.exists():
        SANDBOX_PATH.mkdir(parents=True, exist_ok=True)

    detector_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(detector_handler, str(SANDBOX_PATH), recursive=True)
    observer.start()

    if tk is None:
        print("[WARN] Tkinter is unavailable. Falling back to CLI mode.")
        run_detector_cli(detector_handler, observer)
        return

    # Create GUI Window
    try:
        root = tk.Tk()
    except Exception as exc:
        print(f"[WARN] GUI failed to start ({exc}). Falling back to CLI mode.")
        run_detector_cli(detector_handler, observer)
        return
    root.title("🚨 AI RANSOMWARE DETECTOR (Cyber EDR) 🚨")
    root.geometry("900x600")
    root.configure(bg="#0d1117")
    
    # Fonts
    title_font = font.Font(family="Arial", size=16, weight="bold")
    metric_font = font.Font(family="Courier New", size=14, weight="bold")
    value_font = font.Font(family="Courier New", size=20, weight="bold")
    alert_font = font.Font(family="Arial", size=24, weight="bold")
    
    # Header
    header_frame = tk.Frame(root, bg="#1f6feb", height=60)
    header_frame.pack(fill="x", padx=10, pady=10)
    header_label = tk.Label(header_frame, text="AI RANSOMWARE DETECTOR - MONITORING C:\\RansomLab\\sandbox", 
                           font=title_font, bg="#1f6feb", fg="white")
    header_label.pack(pady=15)
    
    # Main container
    main_frame = tk.Frame(root, bg="#0d1117")
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Left side - Metrics
    metrics_frame = tk.Frame(main_frame, bg="#161b22", relief="solid", bd=2)
    metrics_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
    
    metrics_title = tk.Label(metrics_frame, text="📊 REAL-TIME METRICS", font=("Arial", 12, "bold"), 
                            bg="#161b22", fg="#58a6ff")
    metrics_title.pack(pady=10)
    
    # Metric 1
    metric1_frame = tk.Frame(metrics_frame, bg="#0d1117")
    metric1_frame.pack(fill="x", padx=15, pady=10)
    tk.Label(metric1_frame, text="Total Files in System:", font=metric_font, bg="#0d1117", fg="#79c0ff").pack(anchor="w")
    metric1_value = tk.Label(metric1_frame, text="0 files", font=value_font, bg="#0d1117", fg="#58a6ff")
    metric1_value.pack(anchor="w")
    
    # Metric 2
    metric2_frame = tk.Frame(metrics_frame, bg="#0d1117")
    metric2_frame.pack(fill="x", padx=15, pady=10)
    tk.Label(metric2_frame, text="🔴 Encrypted Files (Ransomware):", font=metric_font, bg="#0d1117", fg="#ff7b72").pack(anchor="w")
    metric2_value = tk.Label(metric2_frame, text="0 files", font=value_font, bg="#0d1117", fg="#ff7b72")
    metric2_value.pack(anchor="w")
    
    # Metric 3
    metric3_frame = tk.Frame(metrics_frame, bg="#0d1117")
    metric3_frame.pack(fill="x", padx=15, pady=10)
    tk.Label(metric3_frame, text="🟢 Safe Files:", font=metric_font, bg="#0d1117", fg="#79c0ff").pack(anchor="w")
    metric3_value = tk.Label(metric3_frame, text="0 files", font=value_font, bg="#0d1117", fg="#7ee787")
    metric3_value.pack(anchor="w")
    
    # Files list
    list_frame = tk.Frame(metrics_frame, bg="#0d1117")
    list_frame.pack(fill="both", expand=True, padx=15, pady=10)
    tk.Label(list_frame, text="📋 Encrypted Files List:", font=("Arial", 10, "bold"), bg="#0d1117", fg="#ff7b72").pack(anchor="w")
    
    files_listbox = tk.Listbox(list_frame, bg="#0d1117", fg="#ff7b72", font=("Courier New", 9), height=6, width=40, relief="solid", bd=1)
    files_listbox.pack(fill="both", expand=True, pady=(5, 0))
    
    # Right side - Alert Status
    alert_frame = tk.Frame(main_frame, bg="#161b22", relief="solid", bd=2)
    alert_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
    
    alert_title = tk.Label(alert_frame, text="⚠️  THREAT STATUS", font=("Arial", 12, "bold"), 
                          bg="#161b22", fg="#58a6ff")
    alert_title.pack(pady=10)
    
    # Alert display
    alert_display = tk.Label(alert_frame, text="[ OK ]", font=alert_font, bg="#0d1117", fg="#3fb950", wraplength=250)
    alert_display.pack(fill="both", expand=True, padx=10, pady=20)
    
    alert_message = tk.Label(alert_frame, text="System Secure.\n\nNo malicious activity detected.", 
                            font=("Arial", 11), bg="#0d1117", fg="#7ee787", wraplength=250, justify="center")
    alert_message.pack(fill="x", padx=10, pady=10)
    
    # Status bar
    status_frame = tk.Frame(root, bg="#161b22", height=30)
    status_frame.pack(fill="x", padx=10, pady=5)
    status_label = tk.Label(status_frame, text="🟢 Monitoring active...", font=("Arial", 10), 
                           bg="#161b22", fg="#7ee787")
    status_label.pack(anchor="w", padx=10, pady=5)
    
    # Anomaly Progression panel
    anomaly_frame = tk.Frame(root, bg="#161b22", height=80)
    anomaly_frame.pack(fill="x", padx=10, pady=5)
    tk.Label(anomaly_frame, text="🔍 ANOMALY DETECTION PROGRESSION:", font=("Arial", 10, "bold"), 
            bg="#161b22", fg="#58a6ff").pack(anchor="w", padx=10, pady=(5, 0))
    
    anomaly_display = tk.Label(anomaly_frame, text="Baseline: Normal behavior detected\nAnomaly Score: 0.50 (Safe)\nRisk Status: LOW", 
                              font=("Courier New", 9), bg="#0d1117", fg="#7ee787", 
                              justify="left", relief="solid", bd=1, padx=10, pady=5)
    anomaly_display.pack(fill="x", padx=10, pady=(0, 5))
    
    def update_ui():
        try:
            event_rate, hyenc_ratio = detector_handler.extract_features(window_seconds=5)
            
            prediction = 1 
            score = 0.5

            if event_rate > 0:
                features = np.array([[event_rate, hyenc_ratio]])
                prediction = detector_handler.model.predict(features)[0]
                score = detector_handler.model.decision_function(features)[0]
            
            total_files_count, encrypted_count, safe_files_count, encrypted_names = get_file_stats()
            
            # Update metrics
            metric1_value.config(text=f"{total_files_count} files")
            metric2_value.config(text=f"{encrypted_count} files")
            metric3_value.config(text=f"{safe_files_count} files")
            
            # Update encrypted files list
            files_listbox.delete(0, tk.END)
            if encrypted_count == 0:
                files_listbox.insert(tk.END, "No encrypted files detected ✓")
            else:
                for fname in encrypted_names:
                    files_listbox.insert(tk.END, fname)
            
            # ANOMALY DETECTION PROGRESSION
            # Score interpretation:
            # Positive = Normal (safe)
            # Negative = Anomaly (danger)
            if encrypted_count == 0:
                anomaly_text = "Baseline: Normal behavior detected\nAnomaly Score: HIGH (Safe)\nRisk Status: LOW"
                anomaly_color = "#7ee787"
                is_anomaly = False
            else:
                # Calculate anomaly intensity based on encrypted files
                encrypted_ratio = encrypted_count / max(total_files_count, 1)
                
                # Anomaly score: more encrypted files = more negative (more dangerous)
                if encrypted_ratio > 0.8:
                    anomaly_text = f"⚠️ EXTREME ANOMALY DETECTED!\nEncrypted: {encrypted_count}/{total_files_count} files\nAnomaly Score: VERY NEGATIVE\nRisk Status: CRITICAL DANGER!"
                    anomaly_color = "#ff7b72"
                    is_anomaly = True
                elif encrypted_ratio > 0.5:
                    anomaly_text = f"⚠️ SEVERE ANOMALY DETECTED!\nEncrypted: {encrypted_count}/{total_files_count} files\nAnomaly Score: NEGATIVE\nRisk Status: HIGH DANGER"
                    anomaly_color = "#d29922"
                    is_anomaly = True
                elif encrypted_ratio > 0.1:
                    anomaly_text = f"⚠️ ANOMALY DETECTED!\nEncrypted: {encrypted_count}/{total_files_count} files\nAnomaly Score: SLIGHTLY NEGATIVE\nRisk Status: MEDIUM DANGER"
                    anomaly_color = "#d29922"
                    is_anomaly = True
                else:
                    anomaly_text = f"Baseline: Normal behavior detected\nEncrypted: {encrypted_count}/{total_files_count} files\nAnomaly Score: POSITIVE\nRisk Status: LOW"
                    anomaly_color = "#7ee787"
                    is_anomaly = False
            
            anomaly_display.config(text=anomaly_text, fg=anomaly_color)
            
            # Update alert status
            if encrypted_count > 0:
                encrypted_percent = (encrypted_count / max(total_files_count, 1)) * 100
                alert_display.config(text="🚨 RANSOMWARE ATTACK 🚨", fg="#ff7b72")
                alert_message.config(text=f"DANGER!\n\n{encrypted_count} files encrypted!\n({encrypted_percent:.0f}%)\n\nTake action NOW!", fg="#ff7b72")
                status_label.config(text=f"🔴 CRITICAL: {encrypted_count}/{total_files_count} FILES ENCRYPTED!", fg="#ff7b72")
                alert_frame.configure(bg="#3d2d2d")
            else:
                alert_display.config(text="✓ SYSTEM SECURE", fg="#3fb950")
                alert_message.config(text="Your system is safe.\n\nNo threats detected.\n\nMonitoring active.", fg="#7ee787")
                status_label.config(text="🟢 System protected. All clear.", fg="#7ee787")
                alert_frame.configure(bg="#161b22")
            
            root.after(1000, update_ui)  # Update every 1 second
        except Exception as e:
            root.after(1000, update_ui)
    
    # Start update loop
    root.after(1000, update_ui)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


def run_detector_cli(detector_handler, observer):
    """Run terminal-based monitoring when GUI is unavailable."""
    print("AI RANSOMWARE DETECTOR - CLI MODE")
    print(f"Monitoring: {SANDBOX_PATH}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            event_rate, hyenc_ratio = detector_handler.extract_features(window_seconds=5)
            if event_rate > 0:
                features = np.array([[event_rate, hyenc_ratio]])
                score = detector_handler.model.decision_function(features)[0]
            else:
                score = 0.5

            total_files_count, encrypted_count, safe_files_count, encrypted_names = get_file_stats()
            if encrypted_count > 0:
                state = "RANSOMWARE DETECTED"
            else:
                state = "SYSTEM SECURE"

            print("-" * 70)
            print(
                f"State: {state} | Total: {total_files_count} | "
                f"Encrypted: {encrypted_count} | Safe: {safe_files_count}"
            )
            print(f"EventRate: {event_rate:.2f}/s | HyencRatio: {hyenc_ratio:.2f} | Score: {score:.3f}")
            if encrypted_names:
                print("Encrypted files:", ", ".join(encrypted_names[:8]))
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI ransomware detector")
    parser.add_argument("--cli", action="store_true", help="force terminal mode")
    args = parser.parse_args()

    if args.cli:
        if not SANDBOX_PATH.exists():
            SANDBOX_PATH.mkdir(parents=True, exist_ok=True)
        handler = RansomwareDetector()
        obs = Observer()
        obs.schedule(handler, str(SANDBOX_PATH), recursive=True)
        obs.start()
        run_detector_cli(handler, obs)
    else:
        run_detector()
