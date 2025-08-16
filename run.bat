@echo off
REM Log Analyzer Launch Script for Windows

echo Log Analysis Tool - Cybersecurity
echo ==================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies if needed
if not exist "venv\installed" (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo. > venv\installed
)

REM Generate sample logs if they don't exist
if not exist "sample_logs" (
    echo Generating sample log files...
    python generate_sample_logs.py
)

REM Launch the application
echo Starting Log Analyzer...
python log_analyzer.py

echo Log Analyzer closed.
pause