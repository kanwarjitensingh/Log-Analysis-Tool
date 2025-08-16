#!/usr/bin/env python3
"""
Advanced Sample Log Generator for LogSentinel Testing
Generates realistic attack patterns and security events
"""

import random
import datetime
import os
import json
from collections import defaultdict

class AdvancedLogGenerator:
    def __init__(self):
        self.malicious_ips = [
            "203.0.113.195", "198.51.100.42", "192.0.2.146", 
            "45.76.123.45", "185.220.100.240", "66.240.205.34",
            "91.189.89.199", "103.224.182.251", "194.147.78.45"
        ]
        
        self.legitimate_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.50", "10.0.0.51", "172.16.0.10", "172.16.0.11"
        ]
        
        self.attack_patterns = {
            'sql_injection': [
                "union+select", "drop+table", "insert+into", "delete+from",
                "'+or+'1'='1", "'+and+'1'='1", "admin'--", "1' union select"
            ],
            'xss_attempts': [
                "<script>alert('xss')</script>", "javascript:alert(1)",
                "<img+src=x+onerror=alert(1)>", "onload=alert(document.cookie)"
            ],
            'path_traversal': [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32",
                "../../../etc/shadow", "..%2f..%2f..%2fetc%2fpasswd"
            ],
            'command_injection': [
                ";cat /etc/passwd", "&&rm -rf /", "`id`", ";whoami",
                "||ls -la", "&ping 127.0.0.1"
            ]
        }
        
        self.vulnerability_paths = [
            "/admin.php", "/config.php", "/wp-admin/", "/phpmyadmin/",
            "/cgi-bin/", "/.env", "/.git/config", "/backup.sql",
            "/uploads/shell.php", "/includes/config.inc.php"
        ]
        
        self.user_agents = {
            'legitimate': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
            ],
            'suspicious': [
                "sqlmap/1.4.7", "Nikto/2.1.6", "curl/7.68.0", "wget/1.20.3",
                "python-requests/2.25.1", "Gobuster/3.1.0", "Nmap Scripting Engine"
            ]
        }

    def generate_attack_scenario_logs(self, filename="sample_logs/advanced_attack_scenario.log", num_entries=3000):
        """Generate realistic attack scenario with multiple phases"""
        
        print(f"Generating advanced attack scenario logs...")
        
        with open(filename, 'w') as f:
            current_time = datetime.datetime.now() - datetime.timedelta(days=7)
            
            # Phase 1: Reconnaissance (20% of logs)
            print("  Phase 1: Reconnaissance scanning...")
            for i in range(int(num_entries * 0.2)):
                attacker_ip = random.choice(self.malicious_ips[:3])  # Main attackers
                
                # Port scanning attempts
                paths = ["/", "/robots.txt", "/sitemap.xml", "/admin", "/login"]
                path = random.choice(paths)
                status = random.choice([200, 404, 403, 301])
                user_agent = random.choice(self.user_agents['suspicious'])
                
                current_time += datetime.timedelta(seconds=random.randint(1, 30))
                
                log_entry = f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {random.randint(200, 1500)} "-" "{user_agent}"\n'
                f.write(log_entry)
            
            # Phase 2: Vulnerability scanning (25% of logs)
            print("  Phase 2: Vulnerability scanning...")
            for i in range(int(num_entries * 0.25)):
                attacker_ip = random.choice(self.malicious_ips[:3])
                
                # Test common vulnerabilities
                vuln_path = random.choice(self.vulnerability_paths)
                status = random.choice([404, 403, 200, 500])
                user_agent = random.choice(self.user_agents['suspicious'])
                
                current_time += datetime.timedelta(seconds=random.randint(1, 10))
                
                log_entry = f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {vuln_path} HTTP/1.1" {status} {random.randint(300, 2000)} "-" "{user_agent}"\n'
                f.write(log_entry)
            
            # Phase 3: Active exploitation attempts (30% of logs)
            print("  Phase 3: Active exploitation...")
            for i in range(int(num_entries * 0.3)):
                attacker_ip = random.choice(self.malicious_ips[:2])  # Focus attacks
                
                # Inject attack payloads
                attack_type = random.choice(list(self.attack_patterns.keys()))
                payload = random.choice(self.attack_patterns[attack_type])
                
                if attack_type == 'sql_injection':
                    path = f"/login?user=admin&password={payload}"
                    method = "POST"
                elif attack_type == 'xss_attempts':
                    path = f"/search?q={payload}"
                    method = "GET"
                elif attack_type == 'path_traversal':
                    path = f"/download?file={payload}"
                    method = "GET"
                else:  # command_injection
                    path = f"/execute?cmd=test{payload}"
                    method = "POST"
                
                status = random.choice([403, 500, 400, 200])  # Mixed responses
                user_agent = random.choice(self.user_agents['suspicious'])
                
                current_time += datetime.timedelta(seconds=random.randint(1, 5))
                
                log_entry = f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(400, 3000)} "-" "{user_agent}"\n'
                f.write(log_entry)
            
            # Phase 4: Legitimate traffic mixed in (25% of logs)
            print("  Phase 4: Legitimate traffic...")
            for i in range(int(num_entries * 0.25)):
                legitimate_ip = random.choice(self.legitimate_ips)
                
                normal_paths = ["/", "/index.html", "/about", "/contact", "/products", "/api/status"]
                path = random.choice(normal_paths)
                method = random.choice(["GET", "POST"])
                status = random.choice([200, 200, 200, 301, 304])  # Mostly successful
                user_agent = random.choice(self.user_agents['legitimate'])
                
                current_time += datetime.timedelta(seconds=random.randint(10, 300))
                
                log_entry = f'{legitimate_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(500, 5000)} "-" "{user_agent}"\n'
                f.write(log_entry)

    def generate_security_event_logs(self, filename="sample_logs/security_events.log", num_entries=1000):
        """Generate system security events and errors"""
        
        print(f"Generating security event logs...")
        
        security_events = [
            "[CRITICAL] Authentication failed for user admin from {ip}",
            "[HIGH] Multiple failed login attempts detected from {ip}",
            "[MEDIUM] Suspicious file access attempt: /etc/passwd",
            "[HIGH] Privilege escalation attempt detected for user {user}",
            "[CRITICAL] Unauthorized root access attempt",
            "[MEDIUM] Failed to authenticate user {user} via SSH",
            "[HIGH] Firewall blocked suspicious connection from {ip}",
            "[LOW] User {user} login successful",
            "[MEDIUM] Configuration file modified: /etc/security/limits.conf",
            "[HIGH] Potential brute force attack detected from {ip}",
            "[CRITICAL] System file integrity check failed",
            "[MEDIUM] Disk space critically low on /var partition",
            "[HIGH] Unusual network activity detected on port 22",
            "[LOW] Service restarted: apache2",
            "[MEDIUM] Memory usage exceeded threshold: 90%"
        ]
        
        users = ["admin", "root", "www-data", "mysql", "john", "alice", "bob"]
        
        with open(filename, 'w') as f:
            current_time = datetime.datetime.now() - datetime.timedelta(days=3)
            
            for i in range(num_entries):
                event_template = random.choice(security_events)
                
                # Replace placeholders
                if '{ip}' in event_template:
                    ip = random.choice(self.malicious_ips + self.legitimate_ips)
                    event_template = event_template.replace('{ip}', ip)
                
                if '{user}' in event_template:
                    user = random.choice(users)
                    event_template = event_template.replace('{user}', user)
                
                current_time += datetime.timedelta(minutes=random.randint(1, 60))
                
                log_entry = f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} {event_template}\n'
                f.write(log_entry)

    def generate_high_volume_logs(self, filename="sample_logs/high_volume_web.log", num_entries=5000):
        """Generate high-volume web logs with realistic patterns"""
        
        print(f"Generating high-volume web server logs...")
        
        # Create traffic patterns - business hours vs off hours
        business_hours = list(range(9, 18))  # 9 AM to 5 PM
        
        with open(filename, 'w') as f:
            current_time = datetime.datetime.now() - datetime.timedelta(days=30)
            
            for i in range(num_entries):
                # Weight traffic based on time of day
                if current_time.hour in business_hours:
                    # Higher legitimate traffic during business hours
                    ip = random.choice(self.legitimate_ips + self.legitimate_ips + self.malicious_ips)
                    user_agent_pool = self.user_agents['legitimate'] + self.user_agents['suspicious'][:1]
                else:
                    # More suspicious activity during off hours
                    ip = random.choice(self.malicious_ips + self.legitimate_ips)
                    user_agent_pool = self.user_agents['suspicious'] + self.user_agents['legitimate'][:1]
                
                # Create realistic request patterns
                if ip in self.malicious_ips:
                    # Attackers tend to make more requests
                    paths = self.vulnerability_paths + ["/", "/admin", "/login"]
                    status_codes = [404, 403, 200, 500, 401]
                    for _ in range(random.randint(1, 8)):  # Burst of requests
                        path = random.choice(paths)
                        status = random.choice(status_codes)
                        method = random.choice(["GET", "POST", "HEAD"])
                        user_agent = random.choice(self.user_agents['suspicious'])
                        
                        log_entry = f'{ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 2000)} "-" "{user_agent}"\n'
                        f.write(log_entry)
                        
                        current_time += datetime.timedelta(seconds=random.randint(1, 3))
                else:
                    # Legitimate users - normal patterns
                    normal_paths = ["/", "/index.html", "/about", "/products", "/contact", "/api/data"]
                    path = random.choice(normal_paths)
                    status = random.choice([200, 200, 200, 304, 301])
                    method = random.choice(["GET", "POST"])
                    user_agent = random.choice(self.user_agents['legitimate'])
                    
                    log_entry = f'{ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(1000, 10000)} "-" "{user_agent}"\n'
                    f.write(log_entry)
                
                # Advance time more during off hours
                if current_time.hour in business_hours:
                    current_time += datetime.timedelta(seconds=random.randint(30, 300))
                else:
                    current_time += datetime.timedelta(seconds=random.randint(60, 600))

    def generate_mixed_format_logs(self, filename="sample_logs/mixed_formats.log", num_entries=1500):
        """Generate logs with mixed timestamp formats"""
        
        print(f"Generating mixed format logs...")
        
        with open(filename, 'w') as f:
            current_time = datetime.datetime.now() - datetime.timedelta(days=5)
            
            for i in range(num_entries):
                # Randomly choose timestamp format
                format_choice = random.randint(1, 3)
                
                if format_choice == 1:  # ISO format
                    timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = f'{timestamp} [INFO] System event: User activity detected\n'
                elif format_choice == 2:  # Apache format
                    ip = random.choice(self.legitimate_ips + self.malicious_ips)
                    timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                    path = random.choice(["/", "/api/data", "/admin", "/login"])
                    status = random.choice([200, 404, 500])
                    log_entry = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} 1234 "-" "Mozilla/5.0"\n'
                else:  # Syslog format
                    timestamp = current_time.strftime("%b %d %H:%M:%S")
                    service = random.choice(["sshd", "httpd", "firewall", "kernel"])
                    message = random.choice([
                        "Connection accepted",
                        "Authentication failed",
                        "Service started",
                        "Configuration loaded"
                    ])
                    log_entry = f'{timestamp} server {service}: {message}\n'
                
                f.write(log_entry)
                current_time += datetime.timedelta(minutes=random.randint(1, 30))

    def generate_threat_intelligence_report(self, output_dir="sample_logs"):
        """Generate threat intelligence summary for the sample data"""
        
        report = {
            "threat_summary": {
                "high_risk_ips": self.malicious_ips[:3],
                "medium_risk_ips": self.malicious_ips[3:6],
                "attack_types_simulated": list(self.attack_patterns.keys()),
                "total_attack_attempts": 1500,
                "legitimate_traffic_percentage": 25
            },
            "attack_timeline": {
                "phase_1_reconnaissance": "First 20% of attack logs",
                "phase_2_vulnerability_scan": "Next 25% of attack logs", 
                "phase_3_exploitation": "Next 30% of attack logs",
                "phase_4_legitimate_mixed": "Final 25% of logs"
            },
            "indicators_of_compromise": {
                "suspicious_user_agents": self.user_agents['suspicious'],
                "attack_paths": self.vulnerability_paths,
                "malicious_payloads": {
                    k: v[:3] for k, v in self.attack_patterns.items()
                }
            }
        }
        
        report_file = os.path.join(output_dir, "threat_intelligence_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Threat intelligence report saved to: {report_file}")

def main():
    """Generate comprehensive sample log files for LogSentinel testing"""
    
    print("LogSentinel Advanced Sample Log Generator")
    print("=" * 50)
    
    # Create logs directory if it doesn't exist
    if not os.path.exists("sample_logs"):
        os.makedirs("sample_logs")
        print("Created sample_logs directory")
    
    generator = AdvancedLogGenerator()
    
    # Generate different types of realistic logs
    print("\nGenerating advanced sample log files...")
    
    generator.generate_attack_scenario_logs("sample_logs/attack_scenario.log", 3000)
    generator.generate_security_event_logs("sample_logs/security_events.log", 1000) 
    generator.generate_high_volume_logs("sample_logs/high_volume_web.log", 5000)
    generator.generate_mixed_format_logs("sample_logs/mixed_formats.log", 1500)
    
    # Generate threat intelligence report
    generator.generate_threat_intelligence_report()
    
    print("\n" + "=" * 50)
    print("Sample log files generated successfully!")
    print("\nGenerated files:")
    print("- attack_scenario.log (3000 entries) - Multi-phase attack simulation")
    print("- security_events.log (1000 entries) - System security events")
    print("- high_volume_web.log (5000 entries) - High-volume web traffic")
    print("- mixed_formats.log (1500 entries) - Mixed timestamp formats")
    print("- threat_intelligence_report.json - IOC and attack summary")
    print("\nFiles are ready for LogSentinel advanced analysis!")
    print("Recommended test sequence:")
    print("1. Load attack_scenario.log for comprehensive threat analysis")
    print("2. Test high_volume_web.log for performance and pattern detection")
    print("3. Use security_events.log for error intelligence testing")

if __name__ == "__main__":
    main()
