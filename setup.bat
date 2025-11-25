@echo off
REM SpectreScan Quick Setup Script for Windows CMD
REM Run this script to set up SpectreScan with a virtual environment

echo ============================================================
echo   SpectreScan - Quick Setup Script
echo   by BitSpectreLabs
echo ============================================================
echo.

REM Check if Python is installed
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo       ERROR: Python not found. Please install Python 3.11 or higher.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo       Found: %PYTHON_VERSION%
echo.

REM Check if virtual environment exists
echo [2/5] Checking virtual environment...
if exist ".venv" (
    echo       Virtual environment already exists
) else (
    echo       Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo       ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo       Virtual environment created successfully
)
echo.

REM Activate virtual environment
echo [3/5] Activating virtual environment...
call .venv\Scripts\activate.bat
echo       Virtual environment activated
echo.

REM Install dependencies
echo [4/5] Installing dependencies...
.venv\Scripts\python.exe -m pip install --upgrade pip -q
.venv\Scripts\python.exe -m pip install -r requirements.txt -q
if errorlevel 1 (
    echo       ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo       Dependencies installed successfully
echo.

REM Install SpectreScan
echo [5/5] Installing SpectreScan...
.venv\Scripts\python.exe -m pip install -e . -q
if errorlevel 1 (
    echo       ERROR: Failed to install SpectreScan
    pause
    exit /b 1
)
echo       SpectreScan installed successfully
echo.

REM Verify installation
echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.

REM Show version
.venv\Scripts\spectrescan.exe version
echo.

REM Usage instructions
echo Quick Start Commands:
echo   # Activate virtual environment (if not already active):
echo   .venv\Scripts\activate.bat
echo.
echo   # Run a quick scan:
echo   spectrescan 192.168.1.1 --quick
echo.
echo   # Show help:
echo   spectrescan --help
echo.
echo   # Launch GUI:
echo   spectrescan --gui
echo.
echo   # Launch TUI:
echo   spectrescan --tui
echo.

echo For more information, see README.md
echo.
pause
