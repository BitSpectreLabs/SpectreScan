# SpectreScan Quick Setup Script for Windows PowerShell
# Run this script to set up SpectreScan with a virtual environment

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host "=" * 59 -ForegroundColor Cyan
Write-Host "  SpectreScan - Quick Setup Script" -ForegroundColor Cyan
Write-Host "  by BitSpectreLabs" -ForegroundColor Cyan  
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host "=" * 59 -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ERROR: Python not found. Please install Python 3.11 or higher." -ForegroundColor Red
    exit 1
}

$pythonVersion = python --version
Write-Host "      Found: $pythonVersion" -ForegroundColor Green
Write-Host ""

# Check if virtual environment exists
Write-Host "[2/5] Checking virtual environment..." -ForegroundColor Yellow
if (Test-Path ".venv") {
    Write-Host "      Virtual environment already exists" -ForegroundColor Green
} else {
    Write-Host "      Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      Virtual environment created successfully" -ForegroundColor Green
    } else {
        Write-Host "      ERROR: Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Activate virtual environment
Write-Host "[3/5] Activating virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1
Write-Host "      Virtual environment activated" -ForegroundColor Green
Write-Host ""

# Install dependencies
Write-Host "[4/5] Installing dependencies..." -ForegroundColor Yellow
.\.venv\Scripts\python.exe -m pip install --upgrade pip -q
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "      Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "      ERROR: Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Install SpectreScan
Write-Host "[5/5] Installing SpectreScan..." -ForegroundColor Yellow
.\.venv\Scripts\python.exe -m pip install -e . -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "      SpectreScan installed successfully" -ForegroundColor Green
} else {
    Write-Host "      ERROR: Failed to install SpectreScan" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Verify installation
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host "=" * 59 -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host "=" * 59 -ForegroundColor Cyan
Write-Host ""

# Show version
$version = .\.venv\Scripts\spectrescan.exe version 2>&1
Write-Host "$version" -ForegroundColor Cyan
Write-Host ""

# Usage instructions
Write-Host "Quick Start Commands:" -ForegroundColor Yellow
Write-Host "  # Activate virtual environment (if not already active):" -ForegroundColor White
Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Run a quick scan:" -ForegroundColor White
Write-Host "  spectrescan 192.168.1.1 --quick" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Show help:" -ForegroundColor White
Write-Host "  spectrescan --help" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Launch GUI:" -ForegroundColor White
Write-Host "  spectrescan --gui" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Launch TUI:" -ForegroundColor White
Write-Host "  spectrescan --tui" -ForegroundColor Cyan
Write-Host ""

Write-Host "For more information, see README.md" -ForegroundColor Gray
Write-Host ""
