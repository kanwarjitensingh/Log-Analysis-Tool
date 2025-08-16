# Log Analysis Tool for Cybersecurity

A simple, cross-platform log analysis tool with GUI interface for cybersecurity professionals. Analyzes system logs, web server logs, and security events.

## Features

- **IP Address Analysis** - Find top IPs and detect suspicious activity
- **Error Detection** - Identify HTTP errors, exceptions, and warnings  
- **HTTP Status Analysis** - Analyze web server response codes
- **Time Pattern Analysis** - Discover activity patterns by hour/date
- **Export Results** - Save analysis to JSON or text files
- **Cross-Platform** - Works on Linux (Kali), Windows, and macOS

## Installation

### Linux (Kali 2024/2025)

```bash
# Clone or download the project
git clone https://github.com/kanwarjitensingh/Log-Analysis-Tool.git
cd log-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies (minimal requirements)
pip install -r requirements.txt

# Run the application
python3 log_analyzer.py
```

### Windows

```cmd
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python log_analyzer.py
```

## Usage

1. **Launch the application**
   ```bash
   python3 log_analyzer.py
   ```

2. **Load a log file**
   - Click "Browse" to select your log file
   - Click "Load Log" to parse the file

3. **Run analysis**
   - Click analysis buttons: "Analyze IPs", "Find Errors", etc.
   - View results in the main window

4. **Export results**
   - Click "Export Results" to save analysis data

## Supported Log Formats

- Apache/Nginx access logs
- System logs (syslog format)
- Security event logs
- Custom text logs with timestamps

## Sample Data

Generate test log files:

```bash
python3 generate_sample_logs.py
```

This creates sample logs in `sample_logs/` directory.

## File Structure

```
log-analyzer/
├── log_analyzer.py          # Main application
├── generate_sample_logs.py  # Sample data generator
├── requirements.txt         # Dependencies
├── README.md               # This file
└── sample_logs/            # Generated test logs
    ├── web_server.log
    ├── system.log
    └── security.log
```

## Analysis Types

### IP Analysis
- Counts requests per IP address
- Identifies top requesters
- Flags suspicious high-volume IPs

### Error Detection  
- Finds HTTP 4xx/5xx status codes
- Detects error/exception keywords
- Shows example error lines

### HTTP Status Analysis
- Groups status codes by category (2xx, 3xx, 4xx, 5xx)
- Calculates percentages
- Identifies common response patterns

### Time Pattern Analysis
- Activity distribution by hour of day
- Peak usage times
- Date-based activity trends

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- No external dependencies required

## Troubleshooting

### Linux Issues
- If tkinter is missing: `sudo apt-get install python3-tk`
- For permission issues: `chmod +x log_analyzer.py`

### Windows Issues  
- Ensure Python is in PATH
- Use `python` instead of `python3`

### General Issues
- Large log files (>100MB) may take time to process
- Ensure log files are readable text format
- Check file permissions if loading fails

## Security Notes

- Tool analyzes logs locally (no network transmission)
- Exported results contain sensitive IP/error data
- Use appropriate file permissions for log files
- Consider data privacy when sharing analysis results

## License

This project is for educational and professional cybersecurity use.