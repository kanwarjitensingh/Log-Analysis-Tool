#!/usr/bin/env python3
"""
Sample Log Generator for Testing Log Analyzer
Generates various types of log files for testing purposes
"""

import random
import datetime
import os

def generate_web_logs(filename="sample_web.log", num_entries=1000):
    """Generate Apache/Nginx style web server logs"""
    
    ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.10", "203.0.113.195",
        "198.51.100.42", "192.0.2.146", "malicious.ip.com", "suspicious.host.net",
        "192.168.1.200", "10.0.0.75", "172.16.0.25", "203.0.113.200"
    ]
    
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
    status_codes = [200, 200, 200, 301, 302, 404, 403, 500, 502, 503]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.68.0", "wget/1.20.3", "python-requests/2.25.1"
    ]
    
    paths = [
        "/", "/index.html", "/login", "/admin", "/api/users", "/dashboard",
        "/upload", "/download", "/search", "/profile", "/settings", "/logout",
        "/robots.txt", "/favicon.ico", "/.env", "/config.php", "/admin.php"
    ]
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            # Random timestamp within last 30 days
            days_ago = random.randint(0, 30)
            hours = random.randint(0, 23)
            minutes = random.randint(0, 59)
            seconds = random.randint(0, 59)
            
            timestamp = datetime.datetime.now() - datetime.timedelta(days=days_ago, hours=hours, minutes=minutes, seconds=seconds)
            
            ip = random.choice(ips)
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(status_codes)
            size = random.randint(100, 50000)
            user_agent = random.choice(user_agents)
            
            # Apache Common Log Format
            log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
            f.write(log_entry)
    
    print(f"Generated {num_entries} web log entries in {filename}")

def generate_system_logs(filename="sample_system.log", num_entries=500):
    """Generate system/application logs"""
    
    services = ["ssh", "apache2", "mysql", "firewall", "kernel", "systemd"]
    log_levels = ["INFO", "WARNING", "ERROR", "DEBUG", "CRITICAL"]
    
    error_messages = [
        "Connection refused",
        "Authentication failed",
        "Permission denied",
        "File not found",
        "Memory allocation failed",
        "Database connection timeout",
        "Invalid request format",
        "Service unavailable"
    ]
    
    info_messages = [
        "Service started successfully",
        "User logged in",
        "Configuration loaded",
        "Backup completed",
        "Cache cleared",
        "Connection established"
    ]
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            timestamp = datetime.datetime.now() - datetime.timedelta(
                days=random.randint(0, 7),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            service = random.choice(services)
            level = random.choice(log_levels)
            
            if level in ["ERROR", "CRITICAL"]:
                message = random.choice(error_messages)
            else:
                message = random.choice(info_messages)
            
            log_entry = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} [{level}] {service}: {message}\n'
            f.write(log_entry)
    
    print(f"Generated {num_entries} system log entries in {filename}")

def generate_security_logs(filename="sample_security.log", num_entries=300):
    """Generate security-related logs"""
    
    events = [
        "Login attempt from 192.168.1.100",
        "Failed login for user admin",
        "Successful authentication for user john",
        "Firewall blocked connection from 203.0.113.195",
        "Suspicious file access attempt",
        "Password changed for user alice",
        "Account locked due to multiple failed attempts",
        "Privileged command executed by root",
        "File permission changed",
        "Network intrusion detected"
    ]
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            timestamp = datetime.datetime.now() - datetime.timedelta(
                hours=random.randint(0, 168)  # Last week
            )
            
            event = random.choice(events)
            severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            
            log_entry = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} [SECURITY] [{severity}] {event}\n'
            f.write(log_entry)
    
    print(f"Generated {num_entries} security log entries in {filename}")

def main():
    """Generate sample logs for testing"""
    print("Generating sample log files...")
    
    # Create logs directory if it doesn't exist
    if not os.path.exists("sample_logs"):
        os.makedirs("sample_logs")
    
    # Generate different types of logs
    generate_web_logs("sample_logs/web_server.log", 2000)
    generate_system_logs("sample_logs/system.log", 800)
    generate_security_logs("sample_logs/security.log", 400)
    
    print("\nSample log files generated in 'sample_logs' directory:")
    print("- web_server.log (web server access logs)")
    print("- system.log (system/application logs)")
    print("- security.log (security event logs)")
    print("\nYou can use these files to test the Log Analyzer tool.")

if __name__ == "__main__":
    main()