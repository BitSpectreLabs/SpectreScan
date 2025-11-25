#!/bin/bash
# SpectreScan Quick Setup Script for Linux/macOS
# Run this script to set up SpectreScan with a virtual environment

echo "============================================================"
echo "  SpectreScan - Quick Setup Script"
echo "  by BitSpectreLabs"
echo "============================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Check if Python is installed
echo -e "${YELLOW}[1/5] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}      ERROR: Python3 not found. Please install Python 3.11 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}      Found: $PYTHON_VERSION${NC}"
echo ""

# Check if virtual environment exists
echo -e "${YELLOW}[2/5] Checking virtual environment...${NC}"
if [ -d ".venv" ]; then
    echo -e "${GREEN}      Virtual environment already exists${NC}"
else
    echo -e "${CYAN}      Creating virtual environment...${NC}"
    python3 -m venv .venv
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}      Virtual environment created successfully${NC}"
    else
        echo -e "${RED}      ERROR: Failed to create virtual environment${NC}"
        exit 1
    fi
fi
echo ""

# Activate virtual environment
echo -e "${YELLOW}[3/5] Activating virtual environment...${NC}"
source .venv/bin/activate
echo -e "${GREEN}      Virtual environment activated${NC}"
echo ""

# Install dependencies
echo -e "${YELLOW}[4/5] Installing dependencies...${NC}"
.venv/bin/python -m pip install --upgrade pip -q
.venv/bin/python -m pip install -r requirements.txt -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}      Dependencies installed successfully${NC}"
else
    echo -e "${RED}      ERROR: Failed to install dependencies${NC}"
    exit 1
fi
echo ""

# Install SpectreScan
echo -e "${YELLOW}[5/5] Installing SpectreScan...${NC}"
.venv/bin/python -m pip install -e . -q
if [ $? -eq 0 ]; then
    echo -e "${GREEN}      SpectreScan installed successfully${NC}"
else
    echo -e "${RED}      ERROR: Failed to install SpectreScan${NC}"
    exit 1
fi
echo ""

# Verify installation
echo "============================================================"
echo -e "${GREEN}  Setup Complete!${NC}"
echo "============================================================"
echo ""

# Show version
VERSION=$(.venv/bin/spectrescan version 2>&1)
echo -e "${CYAN}$VERSION${NC}"
echo ""

# Usage instructions
echo -e "${YELLOW}Quick Start Commands:${NC}"
echo -e "  ${NC}# Activate virtual environment (if not already active):${NC}"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo ""
echo -e "  ${NC}# Run a quick scan:${NC}"
echo -e "  ${CYAN}spectrescan 192.168.1.1 --quick${NC}"
echo ""
echo -e "  ${NC}# Show help:${NC}"
echo -e "  ${CYAN}spectrescan --help${NC}"
echo ""
echo -e "  ${NC}# Launch GUI:${NC}"
echo -e "  ${CYAN}spectrescan --gui${NC}"
echo ""
echo -e "  ${NC}# Launch TUI:${NC}"
echo -e "  ${CYAN}spectrescan --tui${NC}"
echo ""

echo -e "${GRAY}For more information, see README.md${NC}"
echo ""
