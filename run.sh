#!/bin/bash
# LogSentinel - Advanced Log Analysis Tool Launch Script for Linux/Unix
# Version 2.0 - Enhanced startup with comprehensive system checks
# Optimized for Kali Linux 2024/2025 and Ubuntu-based systems

# Color codes for enhanced output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}$message${NC}"
}

print_banner() {
    echo
    print_status $CYAN "================================================================================"
    print_status $CYAN "                     LogSentinel - Advanced Log Analysis Tool"
    print_status $CYAN "                          Your Vigilant Guardian for Log Security"
    print_status $CYAN "================================================================================"
    echo
}

check_os() {
    print_status $BLUE "[INFO] Detecting operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="Linux"
        if command -v lsb_release &> /dev/null; then
            DISTRO=$(lsb_release -si 2>/dev/null)
            VERSION=$(lsb_release -sr 2>/dev/null)
            print_status $GREEN "[OK] Detected: $DISTRO $VERSION"
        elif [[ -f /etc/os-release ]]; then
            . /etc/os-release
            DISTRO=$NAME
            VERSION=$VERSION_ID
            print_status $GREEN "[OK] Detected: $DISTRO $VERSION"
        else
            print_status $YELLOW "[WARNING] Linux distribution detection failed"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        VERSION=$(sw_vers -productVersion)
        print_status $GREEN "[OK] Detected: macOS $VERSION"
    else
        OS="Unknown"
        print_status $YELLOW "[WARNING] Unknown operating system: $OSTYPE"
    fi
}

check_python() {
    print_status $BLUE "[INFO] Checking Python installation..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_status $RED "[ERROR] Python 3 is not installed or not found in PATH"
        echo
        if [[ "$OS" == "Linux" ]]; then
            echo "Install Python 3 using:"
            echo "  Ubuntu/Debian: sudo apt update && sudo apt install python3 python3-pip python3-venv"
            echo "  CentOS/RHEL:   sudo yum install python3 python3-pip"
            echo "  Arch Linux:    sudo pacman -S python python-pip"
            echo "  Kali Linux:    sudo apt update && sudo apt install python3 python3-pip python3-venv"
        elif [[ "$OS" == "macOS" ]]; then
            echo "Install Python 3 using:"
            echo "  Homebrew:      brew install python3"
            echo "  Or download from: https://python.org/downloads/"
        fi
        exit 1
    fi
    
    # Get Python version
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    print_status $GREEN "[OK] Found Python $PYTHON_VERSION"
    
    # Check Python version compatibility (require 3.6+)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 6 ]]; then
        print_status $RED "[ERROR] Python 3.6+ is required. Found Python $PYTHON_VERSION"
        echo "Please upgrade your Python installation"
        exit 1
    fi
    
    print_status $GREEN "[OK] Python version compatibility check passed"
}

check_dependencies() {
    print_status $BLUE "[INFO] Checking system dependencies..."
    
    # Check for tkinter
    if ! python3 -c "import tkinter" &> /dev/null; then
        print_status $YELLOW "[WARNING] GUI framework (tkinter) is not available"
        echo
        echo "Installing tkinter..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-tk
        elif command -v yum &> /dev/null; then
            sudo yum install -y tkinter
        elif command -v pacman &> /dev/null; then
            sudo pacman -S tk
        elif command -v brew &> /dev/null; then
            # macOS with Homebrew
            brew install python-tk
        else
            print_status $RED "[ERROR] Cannot install tkinter automatically"
            echo "Please install tkinter manually for your system"
            exit 1
        fi
        
        # Verify installation
        if python3 -c "import tkinter" &> /dev/null; then
            print_status $GREEN "[OK] GUI framework (tkinter) installed successfully"
        else
            print_status $RED "[ERROR] Failed to install tkinter"
            exit 1
        fi
    else
        print_status $GREEN "[OK] GUI framework (tkinter) is available"
    fi
}

setup_virtual_environment() {
    print_status $BLUE "[INFO] Setting up Python virtual environment..."
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_status $BLUE "[SETUP] Creating virtual environment for LogSentinel..."
        python3 -m venv venv
        
        if [ $? -ne 0 ]; then
            print_status $RED "[ERROR] Failed to create virtual environment"
            echo "Make sure python3-venv is installed:"
            echo "  Ubuntu/Debian: sudo apt install python3-venv"
            exit 1
        fi
        
        print_status $GREEN "[OK] Virtual environment created successfully"
    fi
    
    # Activate virtual environment
    print_status $BLUE "[INFO] Activating virtual environment..."
    source venv/bin/activate
    
    if [ $? -ne 0 ]; then
        print_status $RED "[ERROR] Failed to activate virtual environment"
        exit 1
    fi
    
    # Upgrade pip
    print_status $BLUE "[INFO] Upgrading pip..."
    pip install --upgrade pip &> /dev/null
    
    # Install dependencies if needed
    if [ ! -f "venv/installed_marker" ]; then
        print_status $BLUE "[SETUP] Installing LogSentinel dependencies..."
        print_status $BLUE "[INFO] This may take a few moments..."
        
        pip install -r requirements.txt
        
        if [ $? -eq 0 ]; then
            print_status $GREEN "[OK] Dependencies installed successfully"
            touch venv/installed_marker
        else
            print_status $YELLOW "[WARNING] Some dependencies might have failed to install"
            echo "LogSentinel will attempt to run with available packages"
        fi
    fi
}

verify_logsentinel_files() {
    print_status $BLUE "[INFO] Verifying LogSentinel installation..."
    
    local missing_files=0
    
    # Check for core files
    if [ ! -f "logsentinel.py" ]; then
        print_status $RED "[ERROR] LogSentinel main application file not found (logsentinel.py)"
        ((missing_files++))
    fi
    
    if [ ! -f "backend_utils.py" ]; then
        print_status $RED "[ERROR] LogSentinel backend utilities not found (backend_utils.py)"
        ((missing_files++))
    fi
    
    if [ ! -f "requirements.txt" ]; then
        print_status $YELLOW "[WARNING] Requirements file not found (requirements.txt)"
    fi
    
    if [ $missing_files -gt 0 ]; then
        print_status $RED "[ERROR] Missing $missing_files critical LogSentinel files"
        echo "Please ensure all LogSentinel files are in the current directory"
        exit 1
    fi
    
    print_status $GREEN "[OK] All critical LogSentinel files found"
}

generate_sample_data() {
    # Generate sample logs if they don't exist
    if [ ! -d "sample_logs" ]; then
        print_status $BLUE "[SETUP] Generating sample log files for testing..."
        
        if [ -f "generate_sample_logs.py" ]; then
            python3 generate_sample_logs.py
            
            if [ $? -eq 0 ]; then
                print_status $GREEN "[OK] Sample logs generated successfully"
            else
                print_status $YELLOW "[WARNING] Failed to generate sample logs"
                echo "You can still use LogSentinel with your own log files"
            fi
        else
            print_status $YELLOW "[WARNING] Sample log generator not found"
            echo "You can use LogSentinel with your own log files"
        fi
    fi
}

check_system_resources() {
    print_status $BLUE "[INFO] Checking system resources..."
    
    # Check available memory
    if command -v free &> /dev/null; then
        TOTAL_MEM=$(free -m | awk '/^Mem:/ {print $2}')
        AVAILABLE_MEM=$(free -m | awk '/^Mem:/ {print $7}')
        
        if [ -n "$TOTAL_MEM" ] && [ -n "$AVAILABLE_MEM" ]; then
            print_status $GREEN "[OK] System Memory: ${TOTAL_MEM}MB total, ${AVAILABLE_MEM}MB available"
            
            if [ $AVAILABLE_MEM -lt 512 ]; then
                print_status $YELLOW "[WARNING] Low available memory ($AVAILABLE_MEM MB)"
                echo "Large log files may cause performance issues"
            fi
        fi
    fi
    
    # Check disk space
    DISK_USAGE=$(df -h . | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ -n "$DISK_USAGE" ]; then
        if [ $DISK_USAGE -gt 90 ]; then
            print_status $YELLOW "[WARNING] Disk usage is high ($DISK_USAGE%)"
            echo "Ensure sufficient space for log analysis and reports"
        else
            print_status $GREEN "[OK] Disk space usage: $DISK_USAGE%"
        fi
    fi
}

display_system_info() {
    echo
    print_status $CYAN "[INFO] System Information:"
    echo "       OS: $OS"
    if [ -n "$DISTRO" ] && [ -n "$VERSION" ]; then
        echo "       Distribution: $DISTRO $VERSION"
    fi
    echo "       Python: $PYTHON_VERSION"
    echo "       Shell: $SHELL"
    echo "       Working Directory: $(pwd)"
    echo "       Virtual Environment: Active"
    echo "       User: $(whoami)"
}

launch_logsentinel() {
    echo
    print_status $BLUE "[LAUNCH] Starting LogSentinel Advanced Log Analysis Tool..."
    echo
    print_status $CYAN "=================================================================================="
    print_status $GREEN "Ready for comprehensive log security analysis!"
    print_status $CYAN "=================================================================================="
    echo
    
    # Set environment variables for better performance
    export PYTHONUNBUFFERED=1
    export PYTHONHASHSEED=0
    
    # Launch the main application
    python3 logsentinel.py
    LOGSENTINEL_EXIT_CODE=$?
    
    echo
    print_status $CYAN "=================================================================================="
    
    if [ $LOGSENTINEL_EXIT_CODE -eq 0 ]; then
        print_status $GREEN "[INFO] LogSentinel closed normally"
    else
        print_status $YELLOW "[WARNING] LogSentinel exited with code $LOGSENTINEL_EXIT_CODE"
        echo
        echo "If you experienced issues:"
        echo "1. Check that your log files are accessible and readable"
        echo "2. Ensure sufficient system memory for large files"
        echo "3. Verify file permissions (chmod 644 for log files)"
        echo "4. Try running with smaller sample files first"
        echo "5. Check the terminal output for specific error messages"
    fi
    
    echo
    print_status $CYAN "Thank you for using LogSentinel!"
    print_status $CYAN "For support visit: https://github.com/yourusername/logsentinel"
    echo
    
    return $LOGSENTINEL_EXIT_CODE
}

# Main execution flow
main() {
    print_banner
    check_os
    check_python
    check_dependencies
    setup_virtual_environment
    verify_logsentinel_files
    generate_sample_data
    check_system_resources
    display_system_info
    launch_logsentinel
    
    exit $?
}

# Set error handling
set -e
trap 'print_status $RED "[ERROR] Script failed on line $LINENO"' ERR

# Make script executable if needed
if [ ! -x "$0" ]; then
    chmod +x "$0"
fi

# Run main function
main "$@"
