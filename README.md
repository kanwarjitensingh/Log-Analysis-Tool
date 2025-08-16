# LogSentinel - Advanced Log Analysis Tool for Cybersecurity

**⚠️ ETHICAL USE ONLY - IMPORTANT DISCLAIMER**

**This project is designed EXCLUSIVELY for ethical security testing and educational purposes. This is a professional cybersecurity tool created for authorized penetration testing, security research, and educational environments only. I will NOT be responsible if this tool is used for wrong, illegal, or malicious purposes. Users must obtain explicit written permission before analyzing any networks or systems they do not own. By using this tool, you acknowledge that you understand and agree to use it only for legitimate, legal, and ethical purposes.**

---

## 🛡️ LogSentinel Overview

LogSentinel is an advanced, cross-platform log analysis tool specifically designed for cybersecurity professionals. It provides comprehensive threat intelligence, advanced pattern recognition, and sophisticated security event analysis with an intuitive GUI interface.

### 🎯 Key Features

#### 🔍 Advanced IP Threat Intelligence
- **Dynamic Risk Scoring** - Multi-factor risk assessment algorithm
- **Threat Pattern Detection** - Identifies SQL injection, XSS, path traversal, command injection
- **Behavioral Analysis** - User agent diversity, path scanning detection
- **Geographic Intelligence** - IP reputation and location-based risk assessment
- **Attack Vector Classification** - Categorizes threats by attack methodology

#### 🚨 Comprehensive Error Intelligence
- **Multi-Layer Error Detection** - HTTP errors, system failures, security events
- **Context Analysis** - Provides surrounding log context for better understanding
- **Severity Assessment** - Dynamic severity calculation based on error patterns
- **Timeline Analysis** - Temporal error correlation and pattern identification
- **Root Cause Indicators** - Advanced error classification and prioritization

#### 🌐 HTTP Traffic Analytics
- **Performance Metrics** - Response time analysis and bottleneck identification  
- **Status Code Intelligence** - Comprehensive HTTP response analysis
- **Method Distribution** - Request method patterns and anomaly detection
- **Health Assessment** - Service availability and performance scoring
- **Attack Pattern Recognition** - HTTP-based attack identification

#### ⏰ Temporal Pattern Analysis
- **Anomaly Detection** - Identifies unusual activity patterns
- **Business Hours Analysis** - Distinguishes legitimate vs suspicious timing
- **Activity Profiling** - Creates behavioral baselines for comparison
- **Peak Analysis** - Identifies traffic spikes and quiet periods
- **Weekend/Weekday Patterns** - Detects off-hours suspicious activity

#### 📊 Advanced Reporting
- **Executive Dashboards** - High-level security posture summaries
- **Detailed Technical Reports** - In-depth analysis with actionable recommendations
- **Threat Intelligence Feeds** - IOC extraction and threat landscape mapping
- **Risk Assessment Matrices** - Quantified risk scoring and prioritization
- **Export Capabilities** - JSON, CSV, and formatted text reports

## 🚀 Installation

### Linux (Kali Linux 2024/2025 Recommended)

```bash
# Clone the repository
git clone https://github.com/kanwarjitesingh/logsentinel.git
cd logsentinel

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x run.sh
chmod +x logsentinel.py

# Quick start
./run.sh
```

### Windows

```cmd
# Clone or download the repository
git clone https://github.com/kanwarjitesingh/logsentinel.git
cd logsentinel

# Run the automated setup
run.bat
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install required packages
pip install -r requirements.txt

# Generate sample data for testing
python3 generate_sample_logs.py

# Launch LogSentinel
python3 logsentinel.py
```

## 🎓 Quick Start Guide

### 1. Generate Test Data
```bash
python3 generate_sample_logs.py
```
This creates realistic attack scenarios and security events in `sample_logs/`

### 2. Launch LogSentinel
```bash
python3 logsentinel.py
```

### 3. Load Log File
- Click "Browse" to select a log file
- Choose from generated samples or your own logs
- Click "Load Log" to parse and prepare for analysis

### 4. Run Security Analysis
- **IP Threat Analysis** - Comprehensive IP reputation and behavioral analysis
- **Error Intelligence** - Advanced error pattern detection and context analysis  
- **HTTP Traffic Analysis** - Performance and security assessment of web traffic
- **Temporal Patterns** - Time-based anomaly detection and activity profiling

### 5. Generate Reports
- Click "Generate Report" for executive summary with actionable recommendations
- Export detailed technical reports in multiple formats

## 📁 Project Structure

```
logsentinel/
├── logsentinel.py              # Main GUI application with advanced analytics
├── backend_utils.py           # Advanced backend processing engine
├── generate_sample_logs.py    # Realistic attack scenario generator
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── run.sh                    # Linux/Unix launcher script
├── run.bat                   # Windows launcher script
└── sample_logs/              # Generated test data
    ├── attack_scenario.log       # Multi-phase attack simulation
    ├── security_events.log       # System security events
    ├── high_volume_web.log       # High-traffic web server logs
    ├── mixed_formats.log         # Various timestamp formats
    └── threat_intelligence_report.json  # IOC summary
```

## 🔧 Advanced Configuration

### Supported Log Formats

LogSentinel automatically detects and parses:

- **Web Server Logs**: Apache, Nginx, IIS access logs
- **System Logs**: Syslog, systemd journal, Windows Event logs
- **Security Logs**: Firewall logs, IDS/IPS alerts, authentication logs
- **Application Logs**: Custom application logs with timestamps
- **Cloud Logs**: AWS CloudTrail, Azure Activity logs, GCP audit logs

### Pattern Recognition Engine

The backend includes advanced regex patterns for:

- **Attack Vectors**: SQL injection, XSS, CSRF, path traversal, command injection
- **Reconnaissance**: Port scanning, directory enumeration, vulnerability scanning  
- **Authentication Attacks**: Brute force, credential stuffing, privilege escalation
- **Data Exfiltration**: Unusual download patterns, large file transfers
- **Malware Indicators**: C&C communication, suspicious user agents

## 🛠️ Advanced Usage

### Custom Threat Patterns

Extend the threat detection by modifying `backend_utils.py`:

```python
# Add custom attack patterns
custom_patterns = {
    'Custom Attack': r'your_regex_pattern_here',
    'Business Logic Bypass': r'price=0|quantity=-\d+',
    'API Abuse': r'api.*rate.*limit|api.*quota.*exceeded'
}
```

### Performance Tuning

For large log files (>1GB):
- Use streaming analysis mode
- Implement sampling for initial assessment
- Consider log preprocessing and filtering

### Integration Options

LogSentinel can be integrated with:
- **SIEM Systems**: Splunk, ELK Stack, QRadar
- **Threat Intelligence Platforms**: MISP, ThreatConnect
- **Incident Response Tools**: TheHive, RTIR
- **Vulnerability Scanners**: OpenVAS, Nessus

## 📊 Sample Analysis Results

### Threat Level Classifications

- **CRITICAL** ⭐⭐⭐⭐⭐ - Immediate action required
- **HIGH** ⭐⭐⭐⭐ - Priority investigation needed
- **MEDIUM** ⭐⭐⭐ - Enhanced monitoring recommended
- **LOW** ⭐⭐ - Routine monitoring sufficient
- **MINIMAL** ⭐ - No immediate threats detected

### Key Metrics Tracked

- **Risk Score Calculation** - Multi-factor threat assessment
- **Attack Success Rate** - Percentage of successful vs blocked attempts
- **Geographic Risk Distribution** - Threat sources by location
- **Temporal Risk Patterns** - Time-based attack correlation
- **Service Health Indicators** - Application availability metrics

## 🔒 Security Considerations

### Data Privacy
- All analysis performed locally (no data transmission)
- Log data remains on your system
- Encrypted storage options available
- Secure deletion of temporary files

### Operational Security
- Use appropriate file permissions (600/640 for log files)
- Implement log rotation and archival policies  
- Consider data classification and retention requirements
- Validate log integrity before analysis

### Compliance Support
- **GDPR**: Data minimization and privacy by design
- **HIPAA**: Healthcare data protection standards
- **PCI DSS**: Payment card industry security requirements
- **SOX**: Financial reporting compliance

## 🚨 Troubleshooting

### Common Issues

**Memory Issues with Large Files**:
```bash
# Increase Python memory limit
export PYTHONHASHSEED=0
ulimit -v 8388608  # 8GB virtual memory limit
```

**tkinter Not Available (Linux)**:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL  
sudo yum install tkinter

# Arch Linux
sudo pacman -S tk
```

**Permission Denied Errors**:
```bash
# Fix file permissions
chmod +x logsentinel.py run.sh
chmod 644 *.py requirements.txt
```

**Performance Optimization**:
- For files >100MB, consider pre-filtering logs
- Use SSD storage for better I/O performance
- Increase system RAM for large dataset analysis

### Debug Mode

Enable debug logging:
```bash
export LOGSENTINEL_DEBUG=1
python3 logsentinel.py
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-detection`)
3. **Commit** your changes (`git commit -m 'Add advanced threat detection'`)
4. **Push** to the branch (`git push origin feature/amazing-detection`)
5. **Open** a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation for new functionality
- Ensure cross-platform compatibility

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

**For Educational and Professional Cybersecurity Use Only**

## 🙏 Acknowledgments

- **MITRE ATT&CK Framework** - Attack pattern classifications
- **OWASP** - Web application security testing guidelines
- **SANS** - Incident response and forensics methodologies
- **CIS Controls** - Security best practices and benchmarks

## 📧 Support

For support, feature requests, or security reports:
- 📧 Email:kanwar.singh22@st.niituniversity.in
- 🐛 Issues: GitHub Issues page


---

**LogSentinel - Your Vigilant Guardian for Log Security Analysis**

*Stay alert. Stay secure. Let LogSentinel watch your logs.*
