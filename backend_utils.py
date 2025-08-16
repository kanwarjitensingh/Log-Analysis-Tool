#!/usr/bin/env python3
"""
Backend utilities for log analysis
Contains core analysis functions separated from UI
"""

import re
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any

class LogProcessor:
    """Backend log processing class"""
    
    def __init__(self):
        self.patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'timestamp_iso': r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            'timestamp_apache': r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
            'timestamp_syslog': r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',
            'http_status': r' (\d{3}) ',
            'http_method': r'"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)',
        }
        
        self.error_patterns = {
            'HTTP 4xx': r' 4\d{2} ',
            'HTTP 5xx': r' 5\d{2} ',
            'Error': r'error|ERROR|Error',
            'Failed': r'failed|FAILED|Failed',
            'Exception': r'exception|Exception|EXCEPTION',
            'Warning': r'warning|Warning|WARNING',
            'Critical': r'critical|Critical|CRITICAL',
            'Timeout': r'timeout|Timeout|TIMEOUT'
        }
    
    def extract_ips(self, log_lines: List[str]) -> Dict[str, Any]:
        """Extract and analyze IP addresses"""
        ip_counter = Counter()
        ip_lines = defaultdict(list)
        
        for i, line in enumerate(log_lines, 1):
            ips = re.findall(self.patterns['ip'], line)
            for ip in ips:
                ip_counter[ip] += 1
                if len(ip_lines[ip]) < 5:  # Store sample lines
                    ip_lines[ip].append(i)
        
        # Calculate statistics
        total_ips = len(ip_counter)
        total_requests = sum(ip_counter.values())
        
        # Identify suspicious IPs (high request count)
        if total_requests > 0:
            avg_requests = total_requests / total_ips if total_ips > 0 else 0
            threshold = max(10, avg_requests * 3)
            suspicious_ips = {ip: count for ip, count in ip_counter.items() 
                            if count > threshold}
        else:
            suspicious_ips = {}
        
        return {
            'ip_counts': dict(ip_counter),
            'total_unique_ips': total_ips,
            'total_requests': total_requests,
            'top_ips': dict(ip_counter.most_common(20)),
            'suspicious_ips': suspicious_ips,
            'ip_sample_lines': dict(ip_lines)
        }
    
    def find_errors(self, log_lines: List[str]) -> Dict[str, Any]:
        """Find and categorize errors"""
        error_counts = defaultdict(int)
        error_samples = defaultdict(list)
        total_lines = len(log_lines)
        
        for i, line in enumerate(log_lines, 1):
            for error_type, pattern in self.error_patterns.items():
                if re.search(pattern, line):
                    error_counts[error_type] += 1
                    if len(error_samples[error_type]) < 10:
                        error_samples[error_type].append({
                            'line_number': i,
                            'content': line.strip()
                        })
        
        total_errors = sum(error_counts.values())
        error_rate = (total_errors / total_lines) * 100 if total_lines > 0 else 0
        
        return {
            'error_counts': dict(error_counts),
            'error_samples': dict(error_samples),
            'total_errors': total_errors,
            'error_rate_percent': round(error_rate, 2),
            'total_lines_analyzed': total_lines
        }
    
    def analyze_http_status(self, log_lines: List[str]) -> Dict[str, Any]:
        """Analyze HTTP status codes"""
        status_counter = Counter()
        method_counter = Counter()
        
        for line in log_lines:
            # Extract status codes
            status_matches = re.findall(self.patterns['http_status'], line)
            for status in status_matches:
                status_counter[status] += 1
            
            # Extract HTTP methods
            method_matches = re.findall(self.patterns['http_method'], line)
            for method in method_matches:
                method_counter[method] += 1
        
        total_requests = sum(status_counter.values())
        
        # Categorize status codes
        categories = {
            '2xx_success': [code for code in status_counter if code.startswith('2')],
            '3xx_redirect': [code for code in status_counter if code.startswith('3')],
            '4xx_client_error': [code for code in status_counter if code.startswith('4')],
            '5xx_server_error': [code for code in status_counter if code.startswith('5')]
        }
        
        category_stats = {}
        for category, codes in categories.items():
            count = sum(status_counter[code] for code in codes)
            percentage = (count / total_requests) * 100 if total_requests > 0 else 0
            category_stats[category] = {
                'count': count,
                'percentage': round(percentage, 2),
                'codes': {code: status_counter[code] for code in codes}
            }
        
        return {
            'status_counts': dict(status_counter),
            'method_counts': dict(method_counter),
            'total_requests': total_requests,
            'category_stats': category_stats,
            'top_status_codes': dict(status_counter.most_common(10))
        }
    
    def analyze_time_patterns(self, log_lines: List[str]) -> Dict[str, Any]:
        """Analyze time-based patterns"""
        hour_counter = Counter()
        date_counter = Counter()
        day_of_week_counter = Counter()
        timestamps_found = []
        
        # Extract timestamps
        for line in log_lines:
            timestamp = None
            
            # Try different timestamp patterns
            for pattern_name, pattern in [
                ('iso', self.patterns['timestamp_iso']),
                ('apache', self.patterns['timestamp_apache']),
                ('syslog', self.patterns['timestamp_syslog'])
            ]:
                matches = re.findall(pattern, line)
                if matches:
                    timestamp = matches[0]
                    timestamps_found.append((timestamp, pattern_name))
                    break
        
        # Parse timestamps
        parsed_times = []
        for timestamp, pattern_type in timestamps_found:
            try:
                dt = None
                if pattern_type == 'iso':
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                elif pattern_type == 'apache':
                    dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S')
                elif pattern_type == 'syslog':
                    # Assume current year for syslog format
                    current_year = datetime.now().year
                    dt = datetime.strptime(f"{current_year} {timestamp}", '%Y %b %d %H:%M:%S')
                
                if dt:
                    parsed_times.append(dt)
                    hour_counter[dt.hour] += 1
                    date_counter[dt.date().isoformat()] += 1
                    day_of_week_counter[dt.strftime('%A')] += 1
                    
            except ValueError:
                continue
        
        # Calculate peak times
        peak_hour = hour_counter.most_common(1)[0] if hour_counter else (0, 0)
        peak_date = date_counter.most_common(1)[0] if date_counter else ('', 0)
        
        # Time range analysis
        time_range = {}
        if parsed_times:
            min_time = min(parsed_times)
            max_time = max(parsed_times)
            time_range = {
                'start': min_time.isoformat(),
                'end': max_time.isoformat(),
                'duration_hours': (max_time - min_time).total_seconds() / 3600
            }
        
        return {
            'hour_distribution': dict(hour_counter),
            'date_distribution': dict(date_counter),
            'day_of_week_distribution': dict(day_of_week_counter),
            'total_timestamps': len(timestamps_found),
            'peak_hour': {'hour': peak_hour[0], 'count': peak_hour[1]},
            'peak_date': {'date': peak_date[0], 'count': peak_date[1]},
            'time_range': time_range,
            'hourly_stats': self._calculate_hourly_stats(hour_counter)
        }
    
    def _calculate_hourly_stats(self, hour_counter: Counter) -> Dict[str, Any]:
        """Calculate hourly statistics"""
        if not hour_counter:
            return {}
        
        total_events = sum(hour_counter.values())
        hourly_avg = total_events / 24
        
        # Classify hours
        quiet_hours = [hour for hour, count in hour_counter.items() 
                      if count < hourly_avg * 0.5]
        busy_hours = [hour for hour, count in hour_counter.items() 
                     if count > hourly_avg * 1.5]
        
        return {
            'average_per_hour': round(hourly_avg, 2),
            'quiet_hours': sorted(quiet_hours),
            'busy_hours': sorted(busy_hours),
            'peak_activity_period': self._find_peak_period(hour_counter)
        }
    
    def _find_peak_period(self, hour_counter: Counter) -> Dict[str, Any]:
        """Find the busiest consecutive 4-hour period"""
        if len(hour_counter) < 4:
            return {}
        
        max_sum = 0
        peak_start = 0
        
        for start_hour in range(24):
            period_sum = sum(hour_counter.get((start_hour + i) % 24, 0) for i in range(4))
            if period_sum > max_sum:
                max_sum = period_sum
                peak_start = start_hour
        
        return {
            'start_hour': peak_start,
            'end_hour': (peak_start + 3) % 24,
            'total_events': max_sum,
            'description': f"{peak_start:02d}:00 - {(peak_start + 4) % 24:02d}:00"
        }
    
    def generate_summary_report(self, analyses: Dict[str, Any]) -> str:
        """Generate a text summary of all analyses"""
        report_lines = []
        report_lines.append("=== LOG ANALYSIS SUMMARY REPORT ===")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # IP Analysis Summary
        if 'ips' in analyses:
            ip_data = analyses['ips']
            report_lines.append("IP ANALYSIS:")
            report_lines.append(f"  - Unique IPs: {ip_data.get('total_unique_ips', 0)}")
            report_lines.append(f"  - Total requests: {ip_data.get('total_requests', 0)}")
            report_lines.append(f"  - Suspicious IPs: {len(ip_data.get('suspicious_ips', {}))}")
            report_lines.append("")
        
        # Error Analysis Summary
        if 'errors' in analyses:
            error_data = analyses['errors']
            report_lines.append("ERROR ANALYSIS:")
            report_lines.append(f"  - Total errors: {error_data.get('total_errors', 0)}")
            report_lines.append(f"  - Error rate: {error_data.get('error_rate_percent', 0)}%")
            report_lines.append(f"  - Lines analyzed: {error_data.get('total_lines_analyzed', 0)}")
            report_lines.append("")
        
        # HTTP Status Summary
        if 'http_status' in analyses:
            http_data = analyses['http_status']
            report_lines.append("HTTP STATUS ANALYSIS:")
            report_lines.append(f"  - Total requests: {http_data.get('total_requests', 0)}")
            category_stats = http_data.get('category_stats', {})
            for category, stats in category_stats.items():
                if stats['count'] > 0:
                    report_lines.append(f"  - {category}: {stats['count']} ({stats['percentage']}%)")
            report_lines.append("")
        
        # Time Analysis Summary
        if 'time' in analyses:
            time_data = analyses['time']
            report_lines.append("TIME ANALYSIS:")
            report_lines.append(f"  - Timestamps found: {time_data.get('total_timestamps', 0)}")
            peak_hour = time_data.get('peak_hour', {})
            if peak_hour:
                report_lines.append(f"  - Peak hour: {peak_hour.get('hour', 0):02d}:00 ({peak_hour.get('count', 0)} events)")
            peak_period = time_data.get('hourly_stats', {}).get('peak_activity_period', {})
            if peak_period:
                report_lines.append(f"  - Peak period: {peak_period.get('description', 'N/A')}")
            report_lines.append("")
        
        return "\n".join(report_lines)

def main():
    """Test the backend utilities"""
    processor = LogProcessor()
    
    # Sample log lines for testing
    sample_logs = [
        '192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.101 - - [01/Jan/2024:12:01:00 +0000] "POST /login HTTP/1.1" 404 567',
        '2024-01-01 13:00:00 [ERROR] Authentication failed for user admin',
        '2024-01-01 13:05:00 [WARNING] High memory usage detected'
    ]
    
    print("Testing backend utilities...")
    
    # Test IP analysis
    ip_results = processor.extract_ips(sample_logs)
    print(f"Found {ip_results['total_unique_ips']} unique IPs")
    
    # Test error analysis  
    error_results = processor.find_errors(sample_logs)
    print(f"Found {error_results['total_errors']} errors")
    
    # Test HTTP status analysis
    http_results = processor.analyze_http_status(sample_logs)
    print(f"Analyzed {http_results['total_requests']} HTTP requests")
    
    # Test time analysis
    time_results = processor.analyze_time_patterns(sample_logs)
    print(f"Found {time_results['total_timestamps']} timestamps")
    
    print("Backend utilities test completed!")

if __name__ == "__main__":
    main()