#!/usr/bin/env python3
"""
LogSentinel Backend Processing Engine
Advanced backend utilities for comprehensive log analysis
"""

import re
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any

class LogSentinelProcessor:
    """Advanced log processing engine for LogSentinel"""
    
    def __init__(self):
        self.patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'timestamp_iso': r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            'timestamp_apache': r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
            'timestamp_syslog': r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',
            'http_status': r' (\d{3}) ',
            'http_method': r'"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)',
            'user_agent': r'"([^"]*)"$',
            'url_path': r'"[A-Z]+ ([^"]*) HTTP',
        }
        
        self.threat_patterns = {
            'SQL Injection': r'union.*select|drop.*table|insert.*into|delete.*from|\'.*or.*\'|\'.*and.*\'',
            'XSS Attempts': r'<script|javascript:|onload=|onerror=|alert\(',
            'Path Traversal': r'\.\./|\.\.\%2f|\.\.\\',
            'Command Injection': r';.*whoami|;.*cat.*passwd|;.*ls.*-la|&&.*rm|`.*id`',
            'Auth Bypass': r'admin.*admin|root.*root|1.*=.*1|true.*true',
            'Brute Force': r'(login.*fail|auth.*fail|invalid.*password).*\d{3,}'
        }
        
        self.error_patterns = {
            'HTTP 4xx Client Errors': r' 4\d{2} ',
            'HTTP 5xx Server Errors': r' 5\d{2} ',
            'Authentication Failures': r'auth.*fail|login.*fail|authentication.*failed',
            'Authorization Denied': r'access.*denied|permission.*denied|unauthorized|forbidden',
            'System Errors': r'error|ERROR|Error',
            'Application Failures': r'failed|FAILED|Failed|exception|Exception|EXCEPTION',
            'Security Warnings': r'warning|Warning|WARNING|alert|Alert|ALERT',
            'Critical Events': r'critical|Critical|CRITICAL|fatal|Fatal|FATAL',
            'Database Errors': r'sql.*error|database.*error|connection.*failed|query.*failed',
            'Timeout Events': r'timeout|Timeout|TIMEOUT|timed.*out',
            'Memory Issues': r'memory.*error|out.*of.*memory|malloc.*failed',
            'Network Issues': r'network.*error|connection.*refused|host.*unreachable'
        }
    
    def extract_ips_advanced(self, log_lines: List[str]) -> Dict[str, Any]:
        """Advanced IP extraction with geolocation patterns and threat analysis"""
        ip_counter = Counter()
        ip_lines = defaultdict(list)
        ip_user_agents = defaultdict(set)
        ip_paths = defaultdict(set)
        suspicious_activities = defaultdict(list)
        
        for i, line in enumerate(log_lines, 1):
            ips = re.findall(self.patterns['ip'], line)
            
            for ip in ips:
                ip_counter[ip] += 1
                if len(ip_lines[ip]) < 10:  # Store more sample lines
                    ip_lines[ip].append(i)
                
                # Extract user agents for this IP
                user_agent_match = re.search(self.patterns['user_agent'], line)
                if user_agent_match:
                    ip_user_agents[ip].add(user_agent_match.group(1)[:50])  # Truncate long UAs
                
                # Extract URL paths for this IP
                path_match = re.search(self.patterns['url_path'], line)
                if path_match:
                    ip_paths[ip].add(path_match.group(1)[:30])  # Truncate long paths
                
                # Check for threat patterns
                for threat_type, pattern in self.threat_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious_activities[ip].append(threat_type)
        
        # Advanced threat analysis
        total_ips = len(ip_counter)
        total_requests = sum(ip_counter.values())
        
        # Dynamic threshold calculation
        if total_requests > 0:
            avg_requests = total_requests / total_ips if total_ips > 0 else 0
            high_volume_threshold = max(20, avg_requests * 5)
            medium_volume_threshold = max(10, avg_requests * 2)
            
            # Categorize IPs by threat level
            high_risk_ips = {}
            medium_risk_ips = {}
            suspicious_ips = {}
            
            for ip, count in ip_counter.items():
                risk_score = 0
                risk_factors = []
                
                # Volume-based scoring
                if count > high_volume_threshold:
                    risk_score += 3
                    risk_factors.append(f"High volume ({count} requests)")
                elif count > medium_volume_threshold:
                    risk_score += 1
                    risk_factors.append(f"Medium volume ({count} requests)")
                
                # Threat pattern scoring
                if ip in suspicious_activities:
                    threat_count = len(set(suspicious_activities[ip]))
                    risk_score += threat_count * 2
                    risk_factors.append(f"Threat patterns: {', '.join(set(suspicious_activities[ip]))}")
                
                # User agent diversity (potential bot detection)
                ua_count = len(ip_user_agents.get(ip, set()))
                if ua_count > 5:
                    risk_score += 1
                    risk_factors.append(f"Multiple user agents ({ua_count})")
                elif ua_count == 0:
                    risk_score += 1
                    risk_factors.append("No user agent")
                
                # Path diversity (potential scanning)
                path_count = len(ip_paths.get(ip, set()))
                if path_count > 20:
                    risk_score += 2
                    risk_factors.append(f"Path scanning ({path_count} paths)")
                
                # Categorize based on risk score
                ip_data = {
                    'count': count,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'user_agents': list(ip_user_agents.get(ip, set()))[:5],  # Top 5 UAs
                    'paths': list(ip_paths.get(ip, set()))[:10],  # Top 10 paths
                    'sample_lines': ip_lines.get(ip, [])[:5]
                }
                
                if risk_score >= 5:
                    high_risk_ips[ip] = ip_data
                elif risk_score >= 3:
                    medium_risk_ips[ip] = ip_data
                elif risk_score >= 1:
                    suspicious_ips[ip] = ip_data
        else:
            high_risk_ips = {}
            medium_risk_ips = {}
            suspicious_ips = {}
        
        return {
            'ip_counts': dict(ip_counter),
            'total_unique_ips': total_ips,
            'total_requests': total_requests,
            'top_ips': dict(ip_counter.most_common(25)),
            'high_risk_ips': high_risk_ips,
            'medium_risk_ips': medium_risk_ips,
            'suspicious_ips': suspicious_ips,
            'threat_summary': self._generate_threat_summary(high_risk_ips, medium_risk_ips, suspicious_ips),
            'ip_sample_lines': dict(ip_lines)
        }
    
    def _generate_threat_summary(self, high_risk: dict, medium_risk: dict, suspicious: dict) -> dict:
        """Generate threat intelligence summary"""
        return {
            'high_risk_count': len(high_risk),
            'medium_risk_count': len(medium_risk),
            'suspicious_count': len(suspicious),
            'total_flagged': len(high_risk) + len(medium_risk) + len(suspicious),
            'threat_level': self._calculate_overall_threat_level(high_risk, medium_risk, suspicious)
        }
    
    def _calculate_overall_threat_level(self, high_risk: dict, medium_risk: dict, suspicious: dict) -> str:
        """Calculate overall threat level for the environment"""
        if len(high_risk) >= 5:
            return "CRITICAL"
        elif len(high_risk) >= 2 or len(medium_risk) >= 10:
            return "HIGH"
        elif len(medium_risk) >= 3 or len(suspicious) >= 15:
            return "MEDIUM"
        elif len(suspicious) >= 5:
            return "LOW"
        else:
            return "MINIMAL"
    
    def find_errors_advanced(self, log_lines: List[str]) -> Dict[str, Any]:
        """Advanced error detection with context analysis"""
        error_counts = defaultdict(int)
        error_samples = defaultdict(list)
        error_context = defaultdict(list)
        total_lines = len(log_lines)
        
        for i, line in enumerate(log_lines, 1):
            for error_type, pattern in self.error_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    error_counts[error_type] += 1
                    
                    if len(error_samples[error_type]) < 15:  # More samples
                        error_samples[error_type].append({
                            'line_number': i,
                            'content': line.strip(),
                            'timestamp': self._extract_timestamp(line),
                            'severity': self._assess_error_severity(error_type, line)
                        })
                    
                    # Collect context (lines before and after)
                    if len(error_context[error_type]) < 5:
                        context = []
                        for j in range(max(0, i-2), min(len(log_lines), i+3)):
                            if j != i-1:  # Skip the error line itself
                                context.append(f"Line {j+1}: {log_lines[j].strip()}")
                        error_context[error_type].append({
                            'error_line': i,
                            'context': context
                        })
        
        total_errors = sum(error_counts.values())
        error_rate = (total_errors / total_lines) * 100 if total_lines > 0 else 0
        
        # Advanced error analysis
        critical_errors = sum(count for error_type, count in error_counts.items() 
                            if 'critical' in error_type.lower() or 'fatal' in error_type.lower())
        
        security_errors = sum(count for error_type, count in error_counts.items() 
                            if any(keyword in error_type.lower() for keyword in ['auth', 'access', 'security']))
        
        return {
            'error_counts': dict(error_counts),
            'error_samples': dict(error_samples),
            'error_context': dict(error_context),
            'total_errors': total_errors,
            'critical_errors': critical_errors,
            'security_errors': security_errors,
            'error_rate_percent': round(error_rate, 2),
            'total_lines_analyzed': total_lines,
            'error_timeline': self._analyze_error_timeline(error_samples),
            'severity_assessment': self._assess_overall_severity(error_rate, critical_errors, security_errors)
        }
    
    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from log line"""
        for pattern_name, pattern in [
            ('iso', self.patterns['timestamp_iso']),
            ('apache', self.patterns['timestamp_apache']),
            ('syslog', self.patterns['timestamp_syslog'])
        ]:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return "Unknown"
    
    def _assess_error_severity(self, error_type: str, line: str) -> str:
        """Assess the severity of an individual error"""
        line_lower = line.lower()
        error_type_lower = error_type.lower()
        
        if any(keyword in error_type_lower for keyword in ['critical', 'fatal']):
            return "CRITICAL"
        elif any(keyword in line_lower for keyword in ['critical', 'fatal', 'emergency']):
            return "CRITICAL"
        elif any(keyword in error_type_lower for keyword in ['5xx', 'auth', 'security']):
            return "HIGH"
        elif any(keyword in error_type_lower for keyword in ['error', 'failed', 'exception']):
            return "MEDIUM"
        elif any(keyword in error_type_lower for keyword in ['warning', 'alert']):
            return "LOW"
        else:
            return "INFO"
    
    def _analyze_error_timeline(self, error_samples: dict) -> dict:
        """Analyze error occurrence patterns over time"""
        timeline = {}
        for error_type, samples in error_samples.items():
            timestamps = []
            for sample in samples:
                if sample['timestamp'] != "Unknown":
                    timestamps.append(sample['timestamp'])
            
            if timestamps:
                timeline[error_type] = {
                    'first_occurrence': min(timestamps),
                    'last_occurrence': max(timestamps),
                    'sample_count': len(timestamps)
                }
        
        return timeline
    
    def _assess_overall_severity(self, error_rate: float, critical_errors: int, security_errors: int) -> str:
        """Assess overall system health based on error patterns"""
        if critical_errors > 10 or security_errors > 20 or error_rate > 15:
            return "CRITICAL"
        elif critical_errors > 5 or security_errors > 10 or error_rate > 10:
            return "HIGH"
        elif critical_errors > 0 or security_errors > 5 or error_rate > 5:
            return "MEDIUM"
        elif error_rate > 1:
            return "LOW"
        else:
            return "NORMAL"
    
    def analyze_http_status_advanced(self, log_lines: List[str]) -> Dict[str, Any]:
        """Advanced HTTP status analysis with performance metrics"""
        status_counter = Counter()
        method_counter = Counter()
        status_by_method = defaultdict(lambda: defaultdict(int))
        response_size_stats = defaultdict(list)
        
        for line in log_lines:
            # Extract status codes
            status_matches = re.findall(self.patterns['http_status'], line)
            method_matches = re.findall(self.patterns['http_method'], line)
            
            if status_matches and method_matches:
                status = status_matches[0]
                method = method_matches[0]
                
                status_counter[status] += 1
                method_counter[method] += 1
                status_by_method[method][status] += 1
                
                # Extract response size if available
                size_match = re.search(r' (\d+)$| (\d+) "[^"]*"$', line)
                if size_match:
                    size = int(size_match.group(1) or size_match.group(2))
                    response_size_stats[status].append(size)
        
        total_requests = sum(status_counter.values())
        
        # Advanced categorization
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
        
        # Performance analysis
        avg_response_sizes = {}
        for status, sizes in response_size_stats.items():
            if sizes:
                avg_response_sizes[status] = {
                    'average': round(sum(sizes) / len(sizes), 2),
                    'min': min(sizes),
                    'max': max(sizes),
                    'samples': len(sizes)
                }
        
        # Health assessment
        error_rate = category_stats['4xx_client_error']['percentage'] + category_stats['5xx_server_error']['percentage']
        health_status = self._assess_http_health(category_stats, error_rate)
        
        return {
            'status_counts': dict(status_counter),
            'method_counts': dict(method_counter),
            'status_by_method': {method: dict(statuses) for method, statuses in status_by_method.items()},
            'total_requests': total_requests,
            'category_stats': category_stats,
            'top_status_codes': dict(status_counter.most_common(15)),
            'response_size_stats': avg_response_sizes,
            'error_rate': round(error_rate, 2),
            'health_status': health_status,
            'performance_insights': self._generate_performance_insights(method_counter, category_stats)
        }
    
    def _assess_http_health(self, category_stats: dict, error_rate: float) -> str:
        """Assess HTTP service health"""
        server_error_rate = category_stats['5xx_server_error']['percentage']
        
        if server_error_rate > 5:
            return "CRITICAL"
        elif error_rate > 20 or server_error_rate > 2:
            return "POOR"
        elif error_rate > 10 or server_error_rate > 1:
            return "FAIR"
        elif error_rate > 5:
            return "GOOD"
        else:
            return "EXCELLENT"
    
    def _generate_performance_insights(self, method_counter: dict, category_stats: dict) -> list:
        """Generate performance insights from HTTP data"""
        insights = []
        
        total_requests = sum(method_counter.values())
        
        # Method distribution insights
        if 'GET' in method_counter:
            get_percentage = (method_counter['GET'] / total_requests) * 100
            if get_percentage > 80:
                insights.append("High GET request ratio indicates mostly read operations")
            elif get_percentage < 50:
                insights.append("Balanced read/write operations detected")
        
        # Error pattern insights
        client_errors = category_stats['4xx_client_error']['percentage']
        server_errors = category_stats['5xx_server_error']['percentage']
        
        if client_errors > 15:
            insights.append("High client error rate may indicate API issues or attacks")
        if server_errors > 3:
            insights.append("Server errors detected - investigate application stability")
        
        # Success rate insights
        success_rate = category_stats['2xx_success']['percentage']
        if success_rate > 95:
            insights.append("Excellent service availability")
        elif success_rate < 80:
            insights.append("Low success rate requires immediate attention")
        
        return insights
    
    def analyze_time_patterns_advanced(self, log_lines: List[str]) -> Dict[str, Any]:
        """Advanced temporal analysis with anomaly detection"""
        hour_counter = Counter()
        date_counter = Counter()
        day_of_week_counter = Counter()
        minute_counter = Counter()
        timestamps_found = []
        parsed_times = []
        
        # Enhanced timestamp extraction
        for line in log_lines:
            timestamp = None
            
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
        
        # Parse and analyze timestamps
        for timestamp, pattern_type in timestamps_found:
            try:
                dt = None
                if pattern_type == 'iso':
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                elif pattern_type == 'apache':
                    dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S')
                elif pattern_type == 'syslog':
                    current_year = datetime.now().year
                    dt = datetime.strptime(f"{current_year} {timestamp}", '%Y %b %d %H:%M:%S')
                
                if dt:
                    parsed_times.append(dt)
                    hour_counter[dt.hour] += 1
                    date_counter[dt.date().isoformat()] += 1
                    day_of_week_counter[dt.strftime('%A')] += 1
                    minute_counter[dt.minute] += 1
                    
            except ValueError:
                continue
        
        # Advanced analytics
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
                'duration_hours': round((max_time - min_time).total_seconds() / 3600, 2),
                'duration_days': (max_time - min_time).days
            }
        
        # Anomaly detection
        anomalies = self._detect_temporal_anomalies(hour_counter, date_counter, parsed_times)
        
        return {
            'hour_distribution': dict(hour_counter),
            'date_distribution': dict(date_counter),
            'day_of_week_distribution': dict(day_of_week_counter),
            'minute_distribution': dict(minute_counter),
            'total_timestamps': len(timestamps_found),
            'parsed_timestamps': len(parsed_times),
            'peak_hour': {'hour': peak_hour[0], 'count': peak_hour[1]},
            'peak_date': {'date': peak_date[0], 'count': peak_date[1]},
            'time_range': time_range,
            'hourly_stats': self._calculate_hourly_stats_advanced(hour_counter),
            'anomalies': anomalies,
            'activity_patterns': self._identify_activity_patterns(hour_counter, day_of_week_counter)
        }
    
    def _detect_temporal_anomalies(self, hour_counter: Counter, date_counter: Counter, parsed_times: list) -> dict:
        """Detect unusual temporal patterns"""
        anomalies = {
            'unusual_hours': [],
            'unusual_dates': [],
            'activity_spikes': [],
            'quiet_periods': []
        }
        
        if not hour_counter:
            return anomalies
        
        # Calculate statistics
        hourly_values = list(hour_counter.values())
        avg_hourly = sum(hourly_values) / len(hourly_values)
        
        # Find unusual hours (significantly above or below average)
        for hour, count in hour_counter.items():
            if count > avg_hourly * 3:
                anomalies['unusual_hours'].append({
                    'hour': hour,
                    'count': count,
                    'deviation': f"{((count / avg_hourly) - 1) * 100:.1f}% above average"
                })
        
        # Find unusual dates
        if date_counter:
            daily_values = list(date_counter.values())
            avg_daily = sum(daily_values) / len(daily_values)
            
            for date, count in date_counter.items():
                if count > avg_daily * 2:
                    anomalies['unusual_dates'].append({
                        'date': date,
                        'count': count,
                        'deviation': f"{((count / avg_daily) - 1) * 100:.1f}% above average"
                    })
        
        return anomalies
    
    def _calculate_hourly_stats_advanced(self, hour_counter: Counter) -> Dict[str, Any]:
        """Calculate comprehensive hourly statistics"""
        if not hour_counter:
            return {}
        
        total_events = sum(hour_counter.values())
        hourly_avg = total_events / 24
        
        # Classify hours with more granular categories
        very_quiet_hours = [hour for hour, count in hour_counter.items() 
                           if count < hourly_avg * 0.25]
        quiet_hours = [hour for hour, count in hour_counter.items() 
                      if hourly_avg * 0.25 <= count < hourly_avg * 0.75]
        normal_hours = [hour for hour, count in hour_counter.items() 
                       if hourly_avg * 0.75 <= count <= hourly_avg * 1.5]
        busy_hours = [hour for hour, count in hour_counter.items() 
                     if hourly_avg * 1.5 < count <= hourly_avg * 3]
        very_busy_hours = [hour for hour, count in hour_counter.items() 
                          if count > hourly_avg * 3]
        
        return {
            'average_per_hour': round(hourly_avg, 2),
            'very_quiet_hours': sorted(very_quiet_hours),
            'quiet_hours': sorted(quiet_hours),
            'normal_hours': sorted(normal_hours),
            'busy_hours': sorted(busy_hours),
            'very_busy_hours': sorted(very_busy_hours),
            'peak_activity_period': self._find_peak_period_advanced(hour_counter),
            'activity_variance': self._calculate_activity_variance(hour_counter, hourly_avg)
        }
    
    def _find_peak_period_advanced(self, hour_counter: Counter) -> Dict[str, Any]:
        """Find multiple peak periods with detailed analysis"""
        if len(hour_counter) < 4:
            return {}
        
        periods = []
        
        # Find all 4-hour periods
        for start_hour in range(24):
            period_sum = sum(hour_counter.get((start_hour + i) % 24, 0) for i in range(4))
            periods.append({
                'start_hour': start_hour,
                'end_hour': (start_hour + 3) % 24,
                'total_events': period_sum,
                'description': f"{start_hour:02d}:00 - {(start_hour + 4) % 24:02d}:00"
            })
        
        # Sort by activity level
        periods.sort(key=lambda x: x['total_events'], reverse=True)
        
        return {
            'primary_peak': periods[0],
            'secondary_peak': periods[1] if len(periods) > 1 else None,
            'quietest_period': periods[-1]
        }
    
    def _calculate_activity_variance(self, hour_counter: Counter, hourly_avg: float) -> dict:
        """Calculate activity variance metrics"""
        hourly_values = [hour_counter.get(hour, 0) for hour in range(24)]
        
        # Calculate variance
        variance = sum((value - hourly_avg) ** 2 for value in hourly_values) / 24
        std_deviation = variance ** 0.5
        
        # Activity consistency rating
        coefficient_of_variation = (std_deviation / hourly_avg) if hourly_avg > 0 else 0
        
        if coefficient_of_variation < 0.5:
            consistency = "Very Consistent"
        elif coefficient_of_variation < 1.0:
            consistency = "Moderately Consistent"
        elif coefficient_of_variation < 1.5:
            consistency = "Variable"
        else:
            consistency = "Highly Variable"
        
        return {
            'variance': round(variance, 2),
            'standard_deviation': round(std_deviation, 2),
            'coefficient_of_variation': round(coefficient_of_variation, 2),
            'consistency_rating': consistency
        }
    
    def _identify_activity_patterns(self, hour_counter: Counter, day_counter: Counter) -> dict:
        """Identify common activity patterns"""
        patterns = []
        
        if not hour_counter:
            return {'patterns': patterns}
        
        # Business hours pattern (9 AM - 5 PM)
        business_hours = [9, 10, 11, 12, 13, 14, 15, 16, 17]
        business_activity = sum(hour_counter.get(hour, 0) for hour in business_hours)
        total_activity = sum(hour_counter.values())
        
        if business_activity / total_activity > 0.6:
            patterns.append("Business Hours Dominant - Peak activity during 9 AM - 5 PM")
        
        # Night time activity pattern (10 PM - 6 AM)
        night_hours = [22, 23, 0, 1, 2, 3, 4, 5, 6]
        night_activity = sum(hour_counter.get(hour, 0) for hour in night_hours)
        
        if night_activity / total_activity > 0.4:
            patterns.append("Significant Night Activity - Possible automated systems or attacks")
        
        # Weekend vs weekday analysis
        if day_counter:
            weekend_days = ['Saturday', 'Sunday']
            weekday_activity = sum(count for day, count in day_counter.items() 
                                 if day not in weekend_days)
            weekend_activity = sum(count for day, count in day_counter.items() 
                                 if day in weekend_days)
            
            if weekend_activity > 0:
                weekend_ratio = weekend_activity / (weekday_activity + weekend_activity)
                if weekend_ratio > 0.4:
                    patterns.append("High Weekend Activity - 24/7 operations or suspicious activity")
        
        return {
            'patterns': patterns,
            'business_hours_percentage': round((business_activity / total_activity) * 100, 1) if total_activity > 0 else 0,
            'night_activity_percentage': round((night_activity / total_activity) * 100, 1) if total_activity > 0 else 0
        }
    
    def generate_comprehensive_report(self, analyses: Dict[str, Any]) -> str:
        """Generate comprehensive security analysis report"""
        report_lines = []
        report_lines.append("╔" + "═" * 78 + "╗")
        report_lines.append("║" + " " * 20 + "LOGSENTINEL COMPREHENSIVE REPORT" + " " * 26 + "║")
        report_lines.append("╚" + "═" * 78 + "╝")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Executive Summary
        report_lines.append("🎯 EXECUTIVE SUMMARY")
        report_lines.append("=" * 50)
        
        overall_threat_level = "MINIMAL"
        critical_findings = []
        
        # IP Analysis Summary
        if 'ips' in analyses:
            ip_data = analyses['ips']
            report_lines.append(f"📊 IP Intelligence:")
            report_lines.append(f"   • Unique IP addresses: {ip_data.get('total_unique_ips', 0)}")
            report_lines.append(f"   • Total requests: {ip_data.get('total_requests', 0)}")
            
            threat_summary = ip_data.get('threat_summary', {})
            if threat_summary:
                threat_level = threat_summary.get('threat_level', 'MINIMAL')
                overall_threat_level = max(overall_threat_level, threat_level, key=lambda x: 
                    ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                
                report_lines.append(f"   • Threat level: {threat_level}")
                report_lines.append(f"   • High-risk IPs: {threat_summary.get('high_risk_count', 0)}")
                report_lines.append(f"   • Flagged IPs: {threat_summary.get('total_flagged', 0)}")
                
                if threat_summary.get('high_risk_count', 0) > 0:
                    critical_findings.append(f"High-risk IP addresses detected ({threat_summary.get('high_risk_count', 0)})")
            report_lines.append("")
        
        # Error Analysis Summary
        if 'errors' in analyses:
            error_data = analyses['errors']
            report_lines.append(f"🚨 Error Intelligence:")
            report_lines.append(f"   • Total errors: {error_data.get('total_errors', 0)}")
            report_lines.append(f"   • Error rate: {error_data.get('error_rate_percent', 0)}%")
            report_lines.append(f"   • Critical errors: {error_data.get('critical_errors', 0)}")
            report_lines.append(f"   • Security errors: {error_data.get('security_errors', 0)}")
            
            severity = error_data.get('severity_assessment', 'NORMAL')
            if severity in ['HIGH', 'CRITICAL']:
                overall_threat_level = max(overall_threat_level, severity, key=lambda x: 
                    ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                critical_findings.append(f"System health concern: {severity} error severity")
            
            report_lines.append(f"   • Severity assessment: {severity}")
            report_lines.append("")
        
        # HTTP Analysis Summary
        if 'http_status' in analyses:
            http_data = analyses['http_status']
            report_lines.append(f"🌐 HTTP Traffic Intelligence:")
            report_lines.append(f"   • Total requests: {http_data.get('total_requests', 0)}")
            report_lines.append(f"   • Error rate: {http_data.get('error_rate', 0)}%")
            
            health_status = http_data.get('health_status', 'UNKNOWN')
            if health_status in ['POOR', 'CRITICAL']:
                critical_findings.append(f"HTTP service health: {health_status}")
            
            report_lines.append(f"   • Service health: {health_status}")
            report_lines.append("")
        
        # Time Analysis Summary
        if 'time' in analyses:
            time_data = analyses['time']
            report_lines.append(f"⏰ Temporal Analysis:")
            report_lines.append(f"   • Timestamps analyzed: {time_data.get('total_timestamps', 0)}")
            
            time_range = time_data.get('time_range', {})
            if time_range:
                report_lines.append(f"   • Time span: {time_range.get('duration_days', 0)} days")
                
            anomalies = time_data.get('anomalies', {})
            unusual_patterns = len(anomalies.get('unusual_hours', [])) + len(anomalies.get('unusual_dates', []))
            if unusual_patterns > 0:
                critical_findings.append(f"Temporal anomalies detected ({unusual_patterns})")
            
            report_lines.append(f"   • Anomalies detected: {unusual_patterns}")
            report_lines.append("")
        
        # Overall Assessment
        report_lines.append("🎖️ OVERALL SECURITY ASSESSMENT")
        report_lines.append("=" * 50)
        report_lines.append(f"Threat Level: {overall_threat_level}")
        
        if critical_findings:
            report_lines.append("\n🚨 CRITICAL FINDINGS:")
            for finding in critical_findings:
                report_lines.append(f"   • {finding}")
        else:
            report_lines.append("\n✅ No critical security issues detected")
        
        report_lines.append("")
        
        # Detailed Analysis Sections
        if 'ips' in analyses:
            ip_data = analyses['ips']
            report_lines.append("🔍 DETAILED IP THREAT ANALYSIS")
            report_lines.append("=" * 50)
            
            # High-risk IPs
            high_risk_ips = ip_data.get('high_risk_ips', {})
            if high_risk_ips:
                report_lines.append("🔴 HIGH-RISK IP ADDRESSES:")
                for ip, data in list(high_risk_ips.items())[:10]:
                    report_lines.append(f"   IP: {ip}")
                    report_lines.append(f"   Requests: {data['count']}")
                    report_lines.append(f"   Risk Score: {data['risk_score']}")
                    report_lines.append(f"   Risk Factors: {', '.join(data['risk_factors'])}")
                    report_lines.append("")
            
            # Top IPs
            top_ips = ip_data.get('top_ips', {})
            if top_ips:
                report_lines.append("📊 TOP IP ADDRESSES:")
                for i, (ip, count) in enumerate(list(top_ips.items())[:10], 1):
                    report_lines.append(f"   {i:2d}. {ip:<15} - {count:>6} requests")
                report_lines.append("")
        
        if 'errors' in analyses:
            error_data = analyses['errors']
            report_lines.append("🔍 DETAILED ERROR ANALYSIS")
            report_lines.append("=" * 50)
            
            error_counts = error_data.get('error_counts', {})
            if error_counts:
                report_lines.append("📈 ERROR CATEGORIES:")
                for error_type, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        report_lines.append(f"   {error_type}: {count} occurrences")
                report_lines.append("")
            
            # Show sample errors
            error_samples = error_data.get('error_samples', {})
            for error_type, samples in list(error_samples.items())[:3]:
                if samples:
                    report_lines.append(f"📝 SAMPLE {error_type.upper()}:")
                    for sample in samples[:3]:
                        report_lines.append(f"   Line {sample['line_number']}: {sample['content'][:80]}...")
                    report_lines.append("")
        
        # Recommendations
        report_lines.append("💡 SECURITY RECOMMENDATIONS")
        report_lines.append("=" * 50)
        
        recommendations = self._generate_security_recommendations(analyses, overall_threat_level)
        for recommendation in recommendations:
            report_lines.append(f"• {recommendation}")
        
        report_lines.append("")
        report_lines.append("=" * 78)
        report_lines.append("Report generated by LogSentinel - Advanced Log Analysis Tool")
        report_lines.append("=" * 78)
        
        return "\n".join(report_lines)
    
    def _generate_security_recommendations(self, analyses: dict, threat_level: str) -> list:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # General recommendations based on threat level
        if threat_level == 'CRITICAL':
            recommendations.append("IMMEDIATE ACTION REQUIRED: Implement emergency incident response procedures")
            recommendations.append("Block high-risk IP addresses at firewall level")
            recommendations.append("Escalate to security team for immediate investigation")
        elif threat_level in ['HIGH', 'MEDIUM']:
            recommendations.append("Enhanced monitoring recommended for flagged IP addresses")
            recommendations.append("Review and strengthen access controls")
        
        # IP-based recommendations
        if 'ips' in analyses:
            ip_data = analyses['ips']
            high_risk_count = len(ip_data.get('high_risk_ips', {}))
            
            if high_risk_count > 0:
                recommendations.append(f"Investigate {high_risk_count} high-risk IP addresses for malicious activity")
                recommendations.append("Consider implementing rate limiting for suspicious IPs")
                recommendations.append("Review geographic access patterns for anomalies")
        
        # Error-based recommendations
        if 'errors' in analyses:
            error_data = analyses['errors']
            error_rate = error_data.get('error_rate_percent', 0)
            
            if error_rate > 10:
                recommendations.append("High error rate detected - investigate application stability")
                recommendations.append("Review system logs for root cause analysis")
            
            if error_data.get('security_errors', 0) > 5:
                recommendations.append("Multiple security errors detected - review authentication systems")
                recommendations.append("Audit user access patterns and permissions")
        
        # HTTP-based recommendations
        if 'http_status' in analyses:
            http_data = analyses['http_status']
            health_status = http_data.get('health_status', '')
            
            if health_status in ['POOR', 'CRITICAL']:
                recommendations.append("HTTP service health is compromised - investigate server performance")
                recommendations.append("Review application error logs for systematic issues")
        
        # Temporal recommendations
        if 'time' in analyses:
            time_data = analyses['time']
            anomalies = time_data.get('anomalies', {})
            
            if anomalies.get('unusual_hours') or anomalies.get('unusual_dates'):
                recommendations.append("Temporal anomalies detected - investigate unusual activity patterns")
                recommendations.append("Review off-hours access for unauthorized activities")
        
        # General security best practices
        recommendations.extend([
            "Regularly update and patch all systems",
            "Implement comprehensive logging and monitoring",
            "Conduct regular security assessments",
            "Maintain updated incident response procedures",
            "Consider implementing SIEM solution for real-time monitoring"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations

def main():
    """Test the LogSentinel backend processor"""
    processor = LogSentinelProcessor()
    
    # Sample log lines for testing
    sample_logs = [
        '192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '192.168.1.101 - - [01/Jan/2024:12:01:00 +0000] "POST /login HTTP/1.1" 404 567 "-" "curl/7.68.0"',
        '2024-01-01 13:00:00 [ERROR] Authentication failed for user admin',
        '2024-01-01 13:05:00 [WARNING] High memory usage detected',
        '203.0.113.195 - - [01/Jan/2024:12:02:00 +0000] "GET /admin.php HTTP/1.1" 403 234 "-" "python-requests/2.25.1"',
        '203.0.113.195 - - [01/Jan/2024:12:03:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 345 "-" "sqlmap/1.4"'
    ]
    
    print("Testing LogSentinel backend processor...")
    print("=" * 50)
    
    # Test advanced IP analysis
    print("🔍 Testing IP threat analysis...")
    ip_results = processor.extract_ips_advanced(sample_logs)
    print(f"   Found {ip_results['total_unique_ips']} unique IPs")
    print(f"   Threat level: {ip_results['threat_summary']['threat_level']}")
    
    # Test advanced error analysis
    print("🚨 Testing error intelligence...")
    error_results = processor.find_errors_advanced(sample_logs)
    print(f"   Found {error_results['total_errors']} errors")
    print(f"   Severity: {error_results['severity_assessment']}")
    
    # Test advanced HTTP analysis
    print("🌐 Testing HTTP traffic analysis...")
    http_results = processor.analyze_http_status_advanced(sample_logs)
    print(f"   Analyzed {http_results['total_requests']} HTTP requests")
    print(f"   Health status: {http_results['health_status']}")
    
    # Test advanced time analysis
    print("⏰ Testing temporal analysis...")
    time_results = processor.analyze_time_patterns_advanced(sample_logs)
    print(f"   Found {time_results['total_timestamps']} timestamps")
    
    # Generate comprehensive report
    print("\n📊 Generating comprehensive report...")
    analyses = {
        'ips': ip_results,
        'errors': error_results,
        'http_status': http_results,
        'time': time_results
    }
    
    report = processor.generate_comprehensive_report(analyses)
    print("\n" + "=" * 50)
    print("SAMPLE REPORT PREVIEW:")
    print("=" * 50)
    print(report[:1000] + "..." if len(report) > 1000 else report)
    
    print("\nLogSentinel backend processor test completed!")

if __name__ == "__main__":
    main()
