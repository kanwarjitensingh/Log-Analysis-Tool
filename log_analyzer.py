#!/usr/bin/env python3
"""
Log Analysis Tool for Cybersecurity
Simple log analyzer with GUI interface
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import json
from datetime import datetime
from collections import Counter, defaultdict
import os
import sys

class LogAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer - Cybersecurity Tool")
        self.root.geometry("1000x700")
        
        # Variables
        self.log_data = []
        self.analysis_results = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="Log File Selection", padding="5")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=60).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Load Log", command=self.load_log).grid(row=0, column=2, padx=5)
        
        # Analysis options frame
        options_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="5")
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(options_frame, text="Analyze IPs", command=self.analyze_ips).grid(row=0, column=0, padx=5)
        ttk.Button(options_frame, text="Find Errors", command=self.find_errors).grid(row=0, column=1, padx=5)
        ttk.Button(options_frame, text="HTTP Status", command=self.analyze_http_status).grid(row=0, column=2, padx=5)
        ttk.Button(options_frame, text="Time Analysis", command=self.analyze_time).grid(row=0, column=3, padx=5)
        ttk.Button(options_frame, text="Export Results", command=self.export_results).grid(row=0, column=4, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Text widget for results
        self.results_text = scrolledtext.ScrolledText(results_frame, width=100, height=30)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.file_path.set(filename)
    
    def load_log(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a log file")
            return
        
        try:
            self.status_var.set("Loading log file...")
            self.root.update()
            
            with open(self.file_path.get(), 'r', encoding='utf-8', errors='ignore') as f:
                self.log_data = f.readlines()
            
            self.status_var.set(f"Loaded {len(self.log_data)} log entries")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Log file loaded successfully!\n")
            self.results_text.insert(tk.END, f"Total lines: {len(self.log_data)}\n")
            self.results_text.insert(tk.END, f"File: {os.path.basename(self.file_path.get())}\n\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {str(e)}")
            self.status_var.set("Error loading file")
    
    def analyze_ips(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing IP addresses...")
        self.root.update()
        
        # IP regex pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_counter = Counter()
        
        for line in self.log_data:
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                ip_counter[ip] += 1
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== IP ADDRESS ANALYSIS ===\n\n")
        self.results_text.insert(tk.END, f"Total unique IPs found: {len(ip_counter)}\n\n")
        
        self.results_text.insert(tk.END, "Top 20 IP addresses:\n")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        for ip, count in ip_counter.most_common(20):
            self.results_text.insert(tk.END, f"{ip:<15} : {count:>6} requests\n")
        
        # Suspicious IP analysis (high request count)
        suspicious_threshold = max(10, len(self.log_data) // 100)
        suspicious_ips = [(ip, count) for ip, count in ip_counter.items() if count > suspicious_threshold]
        
        if suspicious_ips:
            self.results_text.insert(tk.END, f"\n\nSuspicious IPs (>{suspicious_threshold} requests):\n")
            self.results_text.insert(tk.END, "-" * 40 + "\n")
            for ip, count in sorted(suspicious_ips, key=lambda x: x[1], reverse=True):
                self.results_text.insert(tk.END, f"{ip:<15} : {count:>6} requests\n")
        
        self.analysis_results['ips'] = dict(ip_counter)
        self.status_var.set("IP analysis completed")
    
    def find_errors(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Finding errors...")
        self.root.update()
        
        error_patterns = {
            'HTTP 4xx': r' 4\d{2} ',
            'HTTP 5xx': r' 5\d{2} ',
            'Error': r'error|ERROR|Error',
            'Failed': r'failed|FAILED|Failed',
            'Exception': r'exception|Exception|EXCEPTION',
            'Warning': r'warning|Warning|WARNING'
        }
        
        error_counts = defaultdict(int)
        error_lines = defaultdict(list)
        
        for i, line in enumerate(self.log_data, 1):
            for error_type, pattern in error_patterns.items():
                if re.search(pattern, line):
                    error_counts[error_type] += 1
                    if len(error_lines[error_type]) < 10:  # Store first 10 examples
                        error_lines[error_type].append(f"Line {i}: {line.strip()}")
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== ERROR ANALYSIS ===\n\n")
        
        total_errors = sum(error_counts.values())
        self.results_text.insert(tk.END, f"Total errors found: {total_errors}\n\n")
        
        for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True):
            self.results_text.insert(tk.END, f"{error_type}: {count} occurrences\n")
            
            if error_lines[error_type]:
                self.results_text.insert(tk.END, "  Examples:\n")
                for example in error_lines[error_type][:5]:
                    self.results_text.insert(tk.END, f"    {example}\n")
            self.results_text.insert(tk.END, "\n")
        
        self.analysis_results['errors'] = dict(error_counts)
        self.status_var.set("Error analysis completed")
    
    def analyze_http_status(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing HTTP status codes...")
        self.root.update()
        
        status_pattern = r' (\d{3}) '
        status_counter = Counter()
        
        for line in self.log_data:
            matches = re.findall(status_pattern, line)
            for status in matches:
                status_counter[status] += 1
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== HTTP STATUS CODE ANALYSIS ===\n\n")
        
        if status_counter:
            total_requests = sum(status_counter.values())
            self.results_text.insert(tk.END, f"Total HTTP requests: {total_requests}\n\n")
            
            # Group by status code categories
            categories = {
                '2xx Success': [code for code in status_counter if code.startswith('2')],
                '3xx Redirection': [code for code in status_counter if code.startswith('3')],
                '4xx Client Error': [code for code in status_counter if code.startswith('4')],
                '5xx Server Error': [code for code in status_counter if code.startswith('5')]
            }
            
            for category, codes in categories.items():
                if codes:
                    category_total = sum(status_counter[code] for code in codes)
                    percentage = (category_total / total_requests) * 100
                    self.results_text.insert(tk.END, f"{category}: {category_total} ({percentage:.1f}%)\n")
                    
                    for code in sorted(codes):
                        count = status_counter[code]
                        code_percentage = (count / total_requests) * 100
                        self.results_text.insert(tk.END, f"  {code}: {count:>6} ({code_percentage:.1f}%)\n")
                    self.results_text.insert(tk.END, "\n")
        else:
            self.results_text.insert(tk.END, "No HTTP status codes found in the log file.\n")
        
        self.analysis_results['http_status'] = dict(status_counter)
        self.status_var.set("HTTP status analysis completed")
    
    def analyze_time(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing time patterns...")
        self.root.update()
        
        # Common timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # 2024-01-01 12:00:00
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',  # 01/Jan/2024:12:00:00
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',        # Jan 01 12:00:00
        ]
        
        hour_counter = Counter()
        date_counter = Counter()
        timestamps_found = []
        
        for line in self.log_data:
            for pattern in timestamp_patterns:
                matches = re.findall(pattern, line)
                if matches:
                    timestamps_found.extend(matches)
                    break
        
        # Parse timestamps and extract hours/dates
        for timestamp in timestamps_found:
            try:
                # Extract hour from various formats
                hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp)
                if hour_match:
                    hour = int(hour_match.group(1))
                    hour_counter[hour] += 1
                
                # Extract date
                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', timestamp)
                if date_match:
                    date_counter[date_match.group(1)] += 1
                else:
                    date_match = re.search(r'(\d{2}/\w{3}/\d{4})', timestamp)
                    if date_match:
                        date_counter[date_match.group(1)] += 1
            except:
                continue
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== TIME PATTERN ANALYSIS ===\n\n")
        
        if timestamps_found:
            self.results_text.insert(tk.END, f"Total timestamps analyzed: {len(timestamps_found)}\n\n")
            
            if hour_counter:
                self.results_text.insert(tk.END, "Activity by Hour:\n")
                self.results_text.insert(tk.END, "-" * 30 + "\n")
                for hour in range(24):
                    count = hour_counter.get(hour, 0)
                    bar = "█" * (count // max(1, max(hour_counter.values()) // 20))
                    self.results_text.insert(tk.END, f"{hour:02d}:00 {count:>6} {bar}\n")
                
                # Find peak hours
                peak_hours = hour_counter.most_common(3)
                if peak_hours:
                    self.results_text.insert(tk.END, f"\nPeak activity hours:\n")
                    for hour, count in peak_hours:
                        self.results_text.insert(tk.END, f"  {hour:02d}:00 - {count} events\n")
            
            if date_counter:
                self.results_text.insert(tk.END, f"\n\nActivity by Date (Top 10):\n")
                self.results_text.insert(tk.END, "-" * 30 + "\n")
                for date, count in date_counter.most_common(10):
                    self.results_text.insert(tk.END, f"{date}: {count} events\n")
        else:
            self.results_text.insert(tk.END, "No recognizable timestamps found in the log file.\n")
        
        self.analysis_results['time'] = {'hours': dict(hour_counter), 'dates': dict(date_counter)}
        self.status_var.set("Time analysis completed")
    
    def export_results(self):
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'log_file': self.file_path.get(),
                    'total_lines': len(self.log_data),
                    'analysis_results': self.analysis_results
                }
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(export_data, f, indent=2)
                else:
                    with open(filename, 'w') as f:
                        f.write(f"Log Analysis Report\n")
                        f.write(f"Generated: {export_data['timestamp']}\n")
                        f.write(f"Log file: {export_data['log_file']}\n")
                        f.write(f"Total lines: {export_data['total_lines']}\n\n")
                        f.write(json.dumps(export_data['analysis_results'], indent=2))
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
                self.status_var.set("Results exported successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")

def main():
    root = tk.Tk()
    app = LogAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()