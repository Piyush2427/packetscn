#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import joblib
import numpy as np
import os
from datetime import datetime
import threading

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class UnifiedIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeNet - IDS - Manual + Real-Time Detection")
        self.root.geometry("1400x800")
        self.root.configure(bg="#f0f0f0")
        
        try:
            self.rf_model = joblib.load('ids_random_forest_model.pkl')
            self.le_protocol = joblib.load('protocol_encoder.pkl')
            self.feature_columns = joblib.load('feature_columns.pkl')
            self.model_loaded = True
        except Exception as e:
            messagebox.showerror("Error", f"Model not found: {e}")
            self.model_loaded = False
            return
        
        self.monitoring = False
        self.attack_count = 0
        self.normal_count = 0
        self.batch_data = None
        self.setup_ui()
    
    def setup_ui(self):
        banner = ttk.Frame(self.root)
        banner.pack(fill=tk.X, padx=10, pady=5)
        title = ttk.Label(banner, text="SAFENET-INTRUSION DETECTION SYSTEM", font=("Arial", 14, "bold"))
        title.pack()
        subtitle = ttk.Label(banner, text="Manual Analysis + Real-Time Monitoring - Powered by Random-Forest", font=("Arial", 10, "italic"), foreground="blue")
        subtitle.pack()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.manual_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.manual_tab, text="📊 Manual Analysis")
        self.setup_manual_tab()
        
        self.batch_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.batch_tab, text="📁 Batch Processing")
        self.setup_batch_tab()
        
        self.realtime_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.realtime_tab, text="⚡ Real-Time Monitor")
        self.setup_realtime_tab()
        
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="⚠️ Results & Alerts")
        self.setup_results_tab()
        
        self.status = ttk.Label(self.root, text="✓ Ready", relief=tk.SUNKEN)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_manual_tab(self):
        frame = ttk.LabelFrame(self.manual_tab, text="Enter Network Traffic Parameters", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.manual_inputs = {}
        fields = [("Source Port", "src_port", "35650"), ("Destination Port", "dst_port", "443"),
                  ("Protocol", "protocol", "TCP"), ("Duration (sec)", "duration_sec", "0.443"),
                  ("Packet Count", "packet_count", "12"), ("Total Bytes", "total_bytes", "6115"),
                  ("Source Bytes", "src_bytes", "1720"), ("Dest Bytes", "dst_bytes", "4095"),
                  ("Avg Packet Size", "avg_pkt_size", "470.0"), ("Packets/Sec", "packets_per_sec", "37.2"),
                  ("Flags Count", "flags_count", "3"), ("TTL", "ttl", "255"), ("Payload Entropy", "payload_entropy", "2.27")]
        
        for label, key, default in fields:
            row = ttk.Frame(frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, width=25).pack(side=tk.LEFT)
            entry = ttk.Entry(row, width=30)
            entry.insert(0, default)
            entry.pack(side=tk.LEFT, padx=5)
            self.manual_inputs[key] = entry
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔍 Predict", command=self.predict_manual).pack(side=tk.LEFT, padx=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.manual_result = scrolledtext.ScrolledText(result_frame, height=6, bg="#e8f4f8")
        self.manual_result.pack(fill=tk.BOTH, expand=True)
    
    def setup_batch_tab(self):
        frame = ttk.LabelFrame(self.batch_tab, text="Batch Processing", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        file_frame = ttk.Frame(frame)
        file_frame.pack(fill=tk.X, pady=10)
        ttk.Label(file_frame, text="CSV File:").pack(side=tk.LEFT)
        self.batch_file_label = ttk.Label(file_frame, text="No file", foreground="red")
        self.batch_file_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="📁 Browse", command=self.browse_batch).pack(side=tk.LEFT)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="⚡ Process", command=self.process_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Export", command=self.export_batch).pack(side=tk.LEFT, padx=5)
        
        result_frame = ttk.LabelFrame(frame, text="Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        self.batch_result = scrolledtext.ScrolledText(result_frame, height=12, bg="#fff9e6")
        self.batch_result.pack(fill=tk.BOTH, expand=True)
        self.batch_file = None
    
    def setup_realtime_tab(self):
        frame = ttk.LabelFrame(self.realtime_tab, text="Real-Time Monitoring", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        if not SCAPY_AVAILABLE:
            warning = ttk.Label(frame, text="⚠️ Scapy not installed: pip install scapy", foreground="red")
            warning.pack(pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        self.monitor_start = ttk.Button(btn_frame, text="▶️ Start", command=self.start_realtime)
        self.monitor_start.pack(side=tk.LEFT, padx=5)
        self.monitor_stop = ttk.Button(btn_frame, text="⏹️ Stop", command=self.stop_realtime, state=tk.DISABLED)
        self.monitor_stop.pack(side=tk.LEFT, padx=5)
        
        stats_frame = ttk.LabelFrame(frame, text="Stats", padding=10)
        stats_frame.pack(fill=tk.X, pady=10)
        self.realtime_stats = ttk.Label(stats_frame, text="Ready")
        self.realtime_stats.pack()
        
        traffic_frame = ttk.LabelFrame(frame, text="Traffic", padding=10)
        traffic_frame.pack(fill=tk.BOTH, expand=True)
        self.realtime_traffic = scrolledtext.ScrolledText(traffic_frame, height=10, bg="#f0f0f0")
        self.realtime_traffic.pack(fill=tk.BOTH, expand=True)
    
    def setup_results_tab(self):
        frame = ttk.Frame(self.results_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_frame = ttk.LabelFrame(frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=10)
        self.overall_stats = ttk.Label(stats_frame, text="Total: 0 | Attacks: 0 | Normal: 0")
        self.overall_stats.pack()
        
        alerts_frame = ttk.LabelFrame(frame, text="Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True)
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=12, bg="#ffebee")
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
    
    def predict_manual(self):
        try:
            protocol_encoded = self.le_protocol.transform([self.manual_inputs['protocol'].get().upper()])[0]
            features = np.array([[int(self.manual_inputs['src_port'].get()),
                                int(self.manual_inputs['dst_port'].get()),
                                protocol_encoded,
                                float(self.manual_inputs['duration_sec'].get()),
                                int(self.manual_inputs['packet_count'].get()),
                                int(self.manual_inputs['total_bytes'].get()),
                                int(self.manual_inputs['src_bytes'].get()),
                                int(self.manual_inputs['dst_bytes'].get()),
                                float(self.manual_inputs['avg_pkt_size'].get()),
                                float(self.manual_inputs['packets_per_sec'].get()),
                                int(self.manual_inputs['flags_count'].get()),
                                int(self.manual_inputs['ttl'].get()),
                                float(self.manual_inputs['payload_entropy'].get())]])
            
            pred = self.rf_model.predict(features)[0]
            prob = self.rf_model.predict_proba(features)[0]
            conf = max(prob) * 100
            
            result = f"PREDICTION: {pred.upper()}\nConfidence: {conf:.2f}%"
            self.manual_result.delete(1.0, tk.END)
            self.manual_result.insert(1.0, result)
            
            if pred == 'attack':
                self.attack_count += 1
                self.log_alert(f"[Manual] ATTACK: {conf:.1f}%")
                messagebox.showwarning("🚨 ATTACK", f"Attack detected!\nConfidence: {conf:.2f}%")
            else:
                self.normal_count += 1
            
            self.update_overall_stats()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def browse_batch(self):
        file = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if file:
            self.batch_file = file
            self.batch_file_label.config(text=os.path.basename(file), foreground="green")
    
    def process_batch(self):
        if not self.batch_file:
            messagebox.showwarning("Warning", "Select CSV file!")
            return
        try:
            data = pd.read_csv(self.batch_file)
            data['protocol_encoded'] = self.le_protocol.transform(data['protocol'])
            X = data[self.feature_columns]
            preds = self.rf_model.predict(X)
            probs = self.rf_model.predict_proba(X)
            
            text = f"Total: {len(data)}\nAttacks: {(preds == 'attack').sum()}\nNormal: {(preds == 'normal').sum()}\n\n"
            
            for i, (idx, row) in enumerate(data[preds == 'attack'].iterrows(), 1):
                conf = max(probs[idx]) * 100
                text += f"[{i}] {row.get('src_ip', 'N/A')}:{row.get('src_port', 'N/A')} -> {row.get('dst_ip', 'N/A')}:{row.get('dst_port', 'N/A')}\n"
                text += f"    Packets: {row.get('packet_count', 'N/A')} | Bytes: {row.get('total_bytes', 'N/A')} | Conf: {conf:.1f}%\n\n"
                self.attack_count += 1
            
            self.normal_count += (preds == 'normal').sum()
            self.batch_data = data
            self.batch_result.delete(1.0, tk.END)
            self.batch_result.insert(1.0, text)
            self.update_overall_stats()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def export_batch(self):
        if self.batch_data is None:
            messagebox.showwarning("Warning", "No data!")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv")
        if file:
            self.batch_data.to_csv(file, index=False)
            messagebox.showinfo("Success", "Saved!")
    
    def start_realtime(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy not installed")
            return
        self.monitoring = True
        self.monitor_start.config(state=tk.DISABLED)
        self.monitor_stop.config(state=tk.NORMAL)
        thread = threading.Thread(target=self.capture_packets, daemon=True)
        thread.start()
    
    def stop_realtime(self):
        self.monitoring = False
        self.monitor_start.config(state=tk.NORMAL)
        self.monitor_stop.config(state=tk.DISABLED)
    
    def capture_packets(self):
        try:
            sniff(prn=self.analyze_packet, store=False, iface="Wi-Fi", stop_filter=lambda x: not self.monitoring)
        except Exception as e:
            self.log_traffic(f"Error: {e}\n")
    
    def analyze_packet(self, packet):
        if not (IP in packet):
            return
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else ("UDP" if UDP in packet else "ICMP")
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                src_port = 0
                dst_port = 0
            
            packet_size = len(packet)
            ttl = packet[IP].ttl
            protocol_encoded = self.le_protocol.transform([protocol])[0]
            features = np.array([[src_port, dst_port, protocol_encoded, 0.1, 1, packet_size, packet_size//2, packet_size//2, packet_size, 10.0, 0, ttl, 2.0]])
            pred = self.rf_model.predict(features)[0]
            prob = self.rf_model.predict_proba(features)[0]
            conf = max(prob) * 100
            
            if pred == 'attack':
                self.attack_count += 1
                self.log_alert(f"[Real-Time] {src_ip}:{src_port} - {conf:.1f}%")
                self.log_traffic(f"\n🚨 ATTACK: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol}) {conf:.1f}%\n")
                self.root.after(0, lambda: messagebox.showwarning("🚨 ATTACK", f"Attack: {src_ip}:{src_port}"))
            else:
                self.normal_count += 1
                msg = f"✓ {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})\n"
                self.log_traffic(msg)
            self.update_overall_stats()
        except Exception as e:
            self.log_traffic(f"Analyze error: {e}\n")
    
    def log_alert(self, message):
        self.alerts_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.alerts_text.see(tk.END)
    
    def log_traffic(self, message):
        self.realtime_traffic.insert(tk.END, message)
        self.realtime_traffic.see(tk.END)
    
    def update_overall_stats(self):
        total = self.attack_count + self.normal_count
        self.overall_stats.config(text=f"Total: {total} | Attacks: {self.attack_count} | Normal: {self.normal_count}")

root = tk.Tk()
app = UnifiedIDS(root)
if app.model_loaded:
    root.mainloop()
