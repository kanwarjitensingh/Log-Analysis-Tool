#!/bin/bash
# Log Analyzer Launch Script for Linux/Kali

echo "Log Analysis Tool - Cybersecurity"
echo "=================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/installed" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    touch venv/installed
fi

# Check if tkinter is available
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing tkinter..."
    sudo apt-get update && sudo apt-get install -y python3-tk
fi

# Generate sample logs if they don't exist
if [ ! -d "sample_logs" ]; then
    echo "Generating sample log files..."
    python3 generate_sample_logs.py
fi

# Launch the application
echo "Starting Log Analyzer..."
python3 log_analyzer.py

echo "Log Analyzer closed."