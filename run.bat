@echo off
REM LogSentinel - Advanced Log Analysis Tool Launch Script for Windows
REM Version 2.0 - Enhanced startup with comprehensive checks

echo.
echo ================================================================================
echo                      LogSentinel - Advanced Log Analysis Tool
echo                           Your Vigilant Guardian for Log Security
echo ================================================================================
echo.

REM Check if Python is installed and get version
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not found in PATH
    echo.
    echo Please install Python 3.6+ from https://python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Found Python %PYTHON_VERSION%

REM Check Python version compatibility
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    echo [ERROR] Python 3.6+ is required. Found Python %PYTHON_VERSION%
    echo Please upgrade your Python installation
    pause
    exit /b 1
)

if %MAJOR% EQU 3 if %MINOR% LSS 6 (
    echo [ERROR] Python 3.6+ is required. Found Python %PYTHON_VERSION%  
    echo Please upgrade your Python installation
    pause
    exit /b 1
)

echo [OK] Python version compatibility check passed

REM Check if virtual environment exists
if not exist "venv" (
    echo.
    echo [SETUP] Creating virtual environment for LogSentinel...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        echo Make sure you have the venv module installed
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created successfully
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

REM Check if dependencies are installed
if not exist "venv\installed_marker" (
    echo.
    echo [SETUP] Installing LogSentinel dependencies...
    echo [INFO] This may take a few moments...
    
    pip install --upgrade pip
    pip install -r requirements.txt
    
    if errorlevel 1 (
        echo [WARNING] Some dependencies might have failed to install
        echo LogSentinel will attempt to run with available packages
    ) else (
        echo [OK] Dependencies installed successfully
        echo. > venv\installed_marker
    )
)

REM Check for tkinter availability (critical for GUI)
python -c "import tkinter; print('[OK] GUI framework (tkinter) is available')" 2>nul
if errorlevel 1 (
    echo [ERROR] GUI framework (tkinter) is not available
    echo.
    echo This is usually because:
    echo 1. Python was installed without tkinter support
    echo 2. You are using a minimal Python distribution
    echo.
    echo Solutions:
    echo - Reinstall Python from python.org with full standard library
    echo - On Windows, tkinter should be included by default
    echo.
    pause
    exit /b 1
)

REM Check for core LogSentinel files
if not exist "logsentinel.py" (
    echo [ERROR] LogSentinel main application file not found
    echo Please ensure logsentinel.py is in the current directory
    pause
    exit /b 1
)

if not exist "backend_utils.py" (
    echo [ERROR] LogSentinel backend utilities not found
    echo Please ensure backend_utils.py is in the current directory
    pause
    exit /b 1
)

REM Generate sample logs if they don't exist
if not exist "sample_logs" (
    echo.
    echo [SETUP] Generating sample log files for testing...
    
    if exist "generate_sample_logs.py" (
        python generate_sample_logs.py
        if errorlevel 1 (
            echo [WARNING] Failed to generate sample logs
            echo You can still use LogSentinel with your own log files
        ) else (
            echo [OK] Sample logs generated successfully
        )
    ) else (
        echo [WARNING] Sample log generator not found
        echo You can use LogSentinel with your own log files
    )
)

REM Display system information
echo.
echo [INFO] System Information:
echo       OS: Windows
echo       Python: %PYTHON_VERSION%
echo       Working Directory: %CD%
echo       Virtual Environment: Active

REM Check available memory
for /f "skip=1" %%p in ('wmic os get TotalVisibleMemorySize ^| findstr [0-9]') do set TOTAL_MEM=%%p
if defined TOTAL_MEM (
    set /a TOTAL_MEM_GB=TOTAL_MEM/1024/1024
    echo       Available Memory: ~%TOTAL_MEM_GB%GB
    
    if %TOTAL_MEM_GB% LSS 2 (
        echo [WARNING] Low system memory detected. Large log files may cause issues.
    )
)

echo.
echo [LAUNCH] Starting LogSentinel Advanced Log Analysis Tool...
echo.
echo ================================================================================
echo Ready for comprehensive log security analysis!
echo ================================================================================
echo.

REM Launch the main application with error handling
python logsentinel.py
set LOGSENTINEL_EXIT_CODE=%errorlevel%

echo.
echo ================================================================================

if %LOGSENTINEL_EXIT_CODE% EQU 0 (
    echo [INFO] LogSentinel closed normally
) else (
    echo [WARNING] LogSentinel exited with code %LOGSENTINEL_EXIT_CODE%
    echo.
    echo If you experienced issues:
    echo 1. Check that your log files are accessible
    echo 2. Ensure sufficient system memory for large files
    echo 3. Verify file permissions
    echo 4. Try running with smaller sample files first
)

echo.
echo Thank you for using LogSentinel!
echo For support visit: https://github.com/yourusername/logsentinel
echo.

pause
exit /b %LOGSENTINEL_EXIT_CODE%
