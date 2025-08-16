#!/usr/bin/env python3
"""
LogSentinel - Advanced Log Analysis Tool for Cybersecurity
Your vigilant guardian for log security analysis
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import json
from datetime import datetime
from collections import Counter, defaultdict
import os
import sys

class LogSentinel:
    def __init__(self, root):
        self.root = root
        self.root.title("LogSentinel - Advanced Log Analysis Tool")
        self.root.geometry("1200x800")
        
        # Variables
        self.log_data = []
        self.analysis_results = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        title_label = ttk.Label(header_frame, text="LogSentinel", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        subtitle_label = ttk.Label(header_frame, text="Advanced Log Analysis for Cybersecurity", font=("Arial", 10))
        subtitle_label.grid(row=1, column=0, sticky=tk.W)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="Log File Selection", padding="5")
        file_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=70).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Load Log", command=self.load_log).grid(row=0, column=2, padx=5)
        
        # Analysis options frame
        options_frame = ttk.LabelFrame(main_frame, text="Security Analysis Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(options_frame, text="IP Threat Analysis", command=self.analyze_ips).grid(row=0, column=0, padx=5, pady=2)
        ttk.Button(options_frame, text="Error Intelligence", command=self.find_errors).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(options_frame, text="HTTP Traffic Analysis", command=self.analyze_http_status).grid(row=0, column=2, padx=5, pady=2)
        ttk.Button(options_frame, text="Temporal Patterns", command=self.analyze_time).grid(row=0, column=3, padx=5, pady=2)
        ttk.Button(options_frame, text="Generate Report", command=self.export_results).grid(row=0, column=4, padx=5, pady=2)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Text widget for results with custom styling
        self.results_text = scrolledtext.ScrolledText(results_frame, width=120, height=35, font=("Courier", 10))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("LogSentinel Ready - Load a log file to begin analysis")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select Log File for Analysis",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.file_path.set(filename)
    
    def load_log(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a log file for analysis")
            return
        
        try:
            self.status_var.set("Loading and parsing log file...")
            self.root.update()
            
            with open(self.file_path.get(), 'r', encoding='utf-8', errors='ignore') as f:
                self.log_data = f.readlines()
            
            self.status_var.set(f"Loaded {len(self.log_data)} log entries - Ready for analysis")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "╔" + "═" * 80 + "╗\n")
            self.results_text.insert(tk.END, "║" + " " * 25 + "LOGSENTINEL ANALYSIS" + " " * 35 + "║\n")
            self.results_text.insert(tk.END, "╚" + "═" * 80 + "╝\n\n")
            self.results_text.insert(tk.END, f"✓ Log file loaded successfully!\n")
            self.results_text.insert(tk.END, f"✓ Total lines processed: {len(self.log_data)}\n")
            self.results_text.insert(tk.END, f"✓ Source file: {os.path.basename(self.file_path.get())}\n")
            self.results_text.insert(tk.END, f"✓ Analysis timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            self.results_text.insert(tk.END, "Select an analysis option above to begin security assessment.\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {str(e)}")
            self.status_var.set("Error loading file")
    
    def analyze_ips(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing IP addresses for threats...")
        self.root.update()
        
        # Enhanced IP regex pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_counter = Counter()
        ip_lines = defaultdict(list)
        
        for i, line in enumerate(self.log_data, 1):
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                ip_counter[ip] += 1
                if len(ip_lines[ip]) < 5:  # Store sample lines for analysis
                    ip_lines[ip].append(i)
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "╔" + "═" * 60 + "╗\n")
        self.results_text.insert(tk.END, "║" + " " * 15 + "IP THREAT ANALYSIS" + " " * 27 + "║\n")
        self.results_text.insert(tk.END, "╚" + "═" * 60 + "╝\n\n")
        
        total_requests = sum(ip_counter.values())
        self.results_text.insert(tk.END, f"📊 Analysis Summary:\n")
        self.results_text.insert(tk.END, f"   • Unique IP addresses: {len(ip_counter)}\n")
        self.results_text.insert(tk.END, f"   • Total requests processed: {total_requests}\n\n")
        
        self.results_text.insert(tk.END, "🔝 Top 20 Most Active IP Addresses:\n")
        self.results_text.insert(tk.END, "─" * 50 + "\n")
        
        for i, (ip, count) in enumerate(ip_counter.most_common(20), 1):
            percentage = (count / total_requests) * 100
            self.results_text.insert(tk.END, f"{i:2d}. {ip:<15} │ {count:>6} requests ({percentage:.1f}%)\n")
        
        # Enhanced suspicious IP analysis
        avg_requests = total_requests / len(ip_counter) if len(ip_counter) > 0 else 0
        suspicious_threshold = max(10, avg_requests * 3)
        suspicious_ips = [(ip, count) for ip, count in ip_counter.items() if count > suspicious_threshold]
        
        if suspicious_ips:
            self.results_text.insert(tk.END, f"\n🚨 THREAT ALERT - Suspicious IP Activity:\n")
            self.results_text.insert(tk.END, f"   Threshold: >{suspicious_threshold:.0f} requests\n")
            self.results_text.insert(tk.END, "─" * 50 + "\n")
            
            for ip, count in sorted(suspicious_ips, key=lambda x: x[1], reverse=True):
                threat_level = "HIGH" if count > avg_requests * 10 else "MEDIUM"
                self.results_text.insert(tk.END, f"⚠️  {ip:<15} │ {count:>6} requests │ {threat_level} RISK\n")
                
                # Show sample line numbers for investigation
                sample_lines = ip_lines.get(ip, [])[:3]
                if sample_lines:
                    self.results_text.insert(tk.END, f"    Sample lines: {', '.join(map(str, sample_lines))}\n")
        else:
            self.results_text.insert(tk.END, f"\n✅ No suspicious IP activity detected\n")
        
        self.analysis_results['ip_analysis'] = {
            'total_ips': len(ip_counter),
            'total_requests': total_requests,
            'suspicious_count': len(suspicious_ips),
            'top_ips': dict(ip_counter.most_common(20))
        }
        self.status_var.set("IP threat analysis completed")
    
    def find_errors(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing errors and security events...")
        self.root.update()
        
        # Enhanced error patterns
        error_patterns = {
            'HTTP 4xx Errors': r' 4\d{2} ',
            'HTTP 5xx Errors': r' 5\d{2} ',
            'Authentication Failures': r'auth.*fail|login.*fail|invalid.*credential',
            'Access Denied': r'access.*denied|permission.*denied|unauthorized',
            'System Errors': r'error|ERROR|Error',
            'Application Failures': r'failed|FAILED|Failed|exception|Exception',
            'Security Warnings': r'warning|Warning|WARNING|alert|Alert',
            'Critical Events': r'critical|Critical|CRITICAL|fatal|Fatal'
        }
        
        error_counts = defaultdict(int)
        error_lines = defaultdict(list)
        total_lines = len(self.log_data)
        
        for i, line in enumerate(self.log_data, 1):
            for error_type, pattern in error_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    error_counts[error_type] += 1
                    if len(error_lines[error_type]) < 5:  # Store examples
                        error_lines[error_type].append(f"Line {i}: {line.strip()[:80]}...")
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "╔" + "═" * 65 + "╗\n")
        self.results_text.insert(tk.END, "║" + " " * 20 + "ERROR INTELLIGENCE REPORT" + " " * 20 + "║\n")
        self.results_text.insert(tk.END, "╚" + "═" * 65 + "╝\n\n")
        
        total_errors = sum(error_counts.values())
        error_rate = (total_errors / total_lines) * 100 if total_lines > 0 else 0
        
        self.results_text.insert(tk.END, f"📊 Error Analysis Summary:\n")
        self.results_text.insert(tk.END, f"   • Total errors detected: {total_errors}\n")
        self.results_text.insert(tk.END, f"   • Error rate: {error_rate:.2f}%\n")
        self.results_text.insert(tk.END, f"   • Lines analyzed: {total_lines}\n\n")
        
        if total_errors > 0:
            # Determine severity level
            if error_rate > 10:
                severity = "🔴 HIGH"
            elif error_rate > 5:
                severity = "🟡 MEDIUM"
            else:
                severity = "🟢 LOW"
            
            self.results_text.insert(tk.END, f"🎯 Severity Assessment: {severity}\n\n")
            
            self.results_text.insert(tk.END, "📋 Error Categories (sorted by frequency):\n")
            self.results_text.insert(tk.END, "─" * 70 + "\n")
            
            for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    percentage = (count / total_errors) * 100
                    self.results_text.insert(tk.END, f"{error_type:<25} │ {count:>5} occurrences ({percentage:.1f}%)\n")
                    
                    # Show sample error lines
                    if error_lines[error_type]:
                        self.results_text.insert(tk.END, "   Sample entries:\n")
                        for sample in error_lines[error_type][:3]:
                            self.results_text.insert(tk.END, f"   • {sample}\n")
                        self.results_text.insert(tk.END, "\n")
        else:
            self.results_text.insert(tk.END, "✅ No errors detected in the log file\n")
        
        self.analysis_results['error_analysis'] = {
            'total_errors': total_errors,
            'error_rate': error_rate,
            'categories': dict(error_counts)
        }
        self.status_var.set("Error intelligence analysis completed")
    
    def analyze_http_status(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing HTTP traffic patterns...")
        self.root.update()
        
        status_pattern = r' (\d{3}) '
        method_pattern = r'"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)'
        
        status_counter = Counter()
        method_counter = Counter()
        
        for line in self.log_data:
            # Extract status codes
            status_matches = re.findall(status_pattern, line)
            for status in status_matches:
                status_counter[status] += 1
            
            # Extract HTTP methods
            method_matches = re.findall(method_pattern, line)
            for method in method_matches:
                method_counter[method] += 1
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "╔" + "═" * 70 + "╗\n")
        self.results_text.insert(tk.END, "║" + " " * 20 + "HTTP TRAFFIC ANALYSIS" + " " * 29 + "║\n")
        self.results_text.insert(tk.END, "╚" + "═" * 70 + "╝\n\n")
        
        if status_counter:
            total_requests = sum(status_counter.values())
            self.results_text.insert(tk.END, f"📊 Traffic Summary:\n")
            self.results_text.insert(tk.END, f"   • Total HTTP requests: {total_requests}\n")
            self.results_text.insert(tk.END, f"   • Unique status codes: {len(status_counter)}\n\n")
            
            # Analyze by categories
            categories = {
                '🟢 Success (2xx)': [code for code in status_counter if code.startswith('2')],
                '🔄 Redirection (3xx)': [code for code in status_counter if code.startswith('3')],
                '🟡 Client Errors (4xx)': [code for code in status_counter if code.startswith('4')],
                '🔴 Server Errors (5xx)': [code for code in status_counter if code.startswith('5')]
            }
            
            self.results_text.insert(tk.END, "📈 Status Code Categories:\n")
            self.results_text.insert(tk.END, "─" * 60 + "\n")
            
            for category, codes in categories.items():
                if codes:
                    category_total = sum(status_counter[code] for code in codes)
                    percentage = (category_total / total_requests) * 100
                    self.results_text.insert(tk.END, f"{category:<25} │ {category_total:>6} ({percentage:.1f}%)\n")
                    
                    # Show individual codes in category
                    for code in sorted(codes, key=lambda x: status_counter[x], reverse=True)[:5]:
                        count = status_counter[code]
                        code_percentage = (count / total_requests) * 100
                        self.results_text.insert(tk.END, f"   └─ {code}: {count:>6} ({code_percentage:.1f}%)\n")
                    self.results_text.insert(tk.END, "\n")
            
            # HTTP Methods analysis
            if method_counter:
                self.results_text.insert(tk.END, "🔧 HTTP Methods Distribution:\n")
                self.results_text.insert(tk.END, "─" * 40 + "\n")
                total_methods = sum(method_counter.values())
                for method, count in method_counter.most_common():
                    percentage = (count / total_methods) * 100
                    self.results_text.insert(tk.END, f"{method:<8} │ {count:>6} requests ({percentage:.1f}%)\n")
        else:
            self.results_text.insert(tk.END, "ℹ️  No HTTP status codes found in the log file\n")
        
        self.analysis_results['http_analysis'] = {
            'total_requests': sum(status_counter.values()) if status_counter else 0,
            'status_codes': dict(status_counter),
            'methods': dict(method_counter)
        }
        self.status_var.set("HTTP traffic analysis completed")
    
    def analyze_time(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing temporal patterns...")
        self.root.update()
        
        # Enhanced timestamp patterns
        timestamp_patterns = [
            (r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '%Y-%m-%d %H:%M:%S'),
            (r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', '%d/%b/%Y:%H:%M:%S'),
            (r'\w{3} \d{2} \d{2}:\d{2}:\d{2}', '%b %d %H:%M:%S')
        ]
        
        hour_counter = Counter()
        date_counter = Counter()
        day_of_week_counter = Counter()
        timestamps_found = []
        
        for line in self.log_data:
            for pattern, fmt in timestamp_patterns:
                matches = re.findall(pattern, line)
                if matches:
                    for timestamp in matches:
                        try:
                            if fmt == '%b %d %H:%M:%S':
                                # Add current year for syslog format
                                timestamp = f"{datetime.now().year} {timestamp}"
                                fmt = '%Y %b %d %H:%M:%S'
                            
                            dt = datetime.strptime(timestamp, fmt)
                            timestamps_found.append(dt)
                            hour_counter[dt.hour] += 1
                            date_counter[dt.date().isoformat()] += 1
                            day_of_week_counter[dt.strftime('%A')] += 1
                        except ValueError:
                            continue
                    break
        
        # Display results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "╔" + "═" * 70 + "╗\n")
        self.results_text.insert(tk.END, "║" + " " * 22 + "TEMPORAL PATTERN ANALYSIS" + " " * 23 + "║\n")
        self.results_text.insert(tk.END, "╚" + "═" * 70 + "╝\n\n")
        
        if timestamps_found:
            self.results_text.insert(tk.END, f"📊 Temporal Analysis Summary:\n")
            self.results_text.insert(tk.END, f"   • Timestamps analyzed: {len(timestamps_found)}\n")
            
            if len(timestamps_found) > 1:
                time_span = max(timestamps_found) - min(timestamps_found)
                self.results_text.insert(tk.END, f"   • Time span: {time_span.days} days, {time_span.seconds//3600} hours\n")
                self.results_text.insert(tk.END, f"   • Date range: {min(timestamps_found).date()} to {max(timestamps_found).date()}\n\n")
            
            # Hourly activity analysis
            if hour_counter:
                self.results_text.insert(tk.END, "🕐 Activity by Hour of Day:\n")
                self.results_text.insert(tk.END, "─" * 50 + "\n")
                
                max_hour_activity = max(hour_counter.values())
                for hour in range(24):
                    count = hour_counter.get(hour, 0)
                    bar_length = int((count / max_hour_activity) * 30) if max_hour_activity > 0 else 0
                    bar = "█" * bar_length
                    self.results_text.insert(tk.END, f"{hour:02d}:00 │{count:>5} │{bar}\n")
                
                # Peak activity analysis
                peak_hours = hour_counter.most_common(5)
                self.results_text.insert(tk.END, f"\n🎯 Peak Activity Hours:\n")
                for i, (hour, count) in enumerate(peak_hours, 1):
                    self.results_text.insert(tk.END, f"   {i}. {hour:02d}:00 - {count} events\n")
            
            # Weekly pattern analysis
            if day_of_week_counter:
                self.results_text.insert(tk.END, f"\n📅 Activity by Day of Week:\n")
                self.results_text.insert(tk.END, "─" * 40 + "\n")
                
                days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                for day in days_order:
                    count = day_of_week_counter.get(day, 0)
                    if count > 0:
                        percentage = (count / len(timestamps_found)) * 100
                        self.results_text.insert(tk.END, f"{day:<10} │ {count:>5} events ({percentage:.1f}%)\n")
        else:
            self.results_text.insert(tk.END, "ℹ️  No recognizable timestamps found in the log file\n")
        
        self.analysis_results['temporal_analysis'] = {
            'total_timestamps': len(timestamps_found),
            'hourly_distribution': dict(hour_counter),
            'daily_distribution': dict(day_of_week_counter)
        }
        self.status_var.set("Temporal pattern analysis completed")
    
    def export_results(self):
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("Text Report", "*.txt")],
            title="Save LogSentinel Analysis Report"
        )
        
        if filename:
            try:
                export_data = {
                    'logsentinel_version': '1.0',
                    'analysis_timestamp': datetime.now().isoformat(),
                    'source_log_file': self.file_path.get(),
                    'total_lines_processed': len(self.log_data),
                    'analysis_results': self.analysis_results,
                    'summary': self.generate_summary_stats()
                }
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(export_data, f, indent=2, default=str)
                else:
                    with open(filename, 'w') as f:
                        f.write("=" * 80 + "\n")
                        f.write("LOGSENTINEL - COMPREHENSIVE SECURITY ANALYSIS REPORT\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(f"Generated: {export_data['analysis_timestamp']}\n")
                        f.write(f"Source: {export_data['source_log_file']}\n")
                        f.write(f"Lines Processed: {export_data['total_lines_processed']}\n\n")
                        
                        # Write summary
                        f.write("EXECUTIVE SUMMARY:\n")
                        f.write("-" * 40 + "\n")
                        for key, value in export_data['summary'].items():
                            f.write(f"{key}: {value}\n")
                        
                        f.write(f"\nDETAILED RESULTS:\n")
                        f.write("-" * 40 + "\n")
                        f.write(json.dumps(export_data['analysis_results'], indent=2, default=str))
                
                messagebox.showinfo("Success", f"LogSentinel report exported to:\n{filename}")
                self.status_var.set("Analysis report exported successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def generate_summary_stats(self):
        """Generate executive summary statistics"""
        summary = {}
        
        if 'ip_analysis' in self.analysis_results:
            ip_data = self.analysis_results['ip_analysis']
            summary['Total Unique IPs'] = ip_data.get('total_ips', 0)
            summary['Suspicious IP Count'] = ip_data.get('suspicious_count', 0)
        
        if 'error_analysis' in self.analysis_results:
            error_data = self.analysis_results['error_analysis']
            summary['Total Errors'] = error_data.get('total_errors', 0)
            summary['Error Rate (%)'] = f"{error_data.get('error_rate', 0):.2f}"
        
        if 'http_analysis' in self.analysis_results:
            http_data = self.analysis_results['http_analysis']
            summary['HTTP Requests Processed'] = http_data.get('total_requests', 0)
        
        if 'temporal_analysis' in self.analysis_results:
            temporal_data = self.analysis_results['temporal_analysis']
            summary['Timestamps Analyzed'] = temporal_data.get('total_timestamps', 0)
        
        return summary

def main():
    root = tk.Tk()
    app = LogSentinel(root)
    root.mainloop()

if __name__ == "__main__":
    main()
