#!/bin/bash
# Setup script for Metasploitable dataset
# This script helps you scan Metasploitable and create a baseline

echo "============================================================"
echo "  Metasploitable Dataset Setup"
echo "============================================================"
echo ""
echo "Prerequisites:"
echo "1. Metasploitable 2 or 3 VM running"
echo "2. nmap installed on your system"
echo "3. Network connectivity to Metasploitable VM"
echo ""
echo "Metasploitable Download:"
echo "  https://sourceforge.net/projects/metasploitable/"
echo ""
read -p "Enter Metasploitable IP address: " METASPLOITABLE_IP

if [ -z "$METASPLOITABLE_IP" ]; then
    echo "Error: IP address required"
    exit 1
fi

echo ""
echo "Testing connectivity..."
if ping -c 1 -W 2 "$METASPLOITABLE_IP" > /dev/null 2>&1; then
    echo " Host is reachable"
else
    echo " Cannot reach $METASPLOITABLE_IP"
    echo "  Make sure Metasploitable VM is running"
    exit 1
fi

echo ""
echo "Starting nmap scan (this may take a few minutes)..."
echo "Scanning: $METASPLOITABLE_IP"

# Comprehensive scan with version detection
nmap -sV -sC -O -p- \
     -oX ../data/raw/metasploitable_scan.xml \
     -oN ../data/raw/metasploitable_scan.txt \
     "$METASPLOITABLE_IP"

if [ $? -eq 0 ]; then
    echo ""
    echo " Scan complete!"
    echo "  XML output: data/raw/metasploitable_scan.xml"
    echo "  Text output: data/raw/metasploitable_scan.txt"
    echo ""
    echo "Next steps:"
    echo "1. Review the scan results"
    echo "2. Run: python scripts/create_baseline_from_metasploitable.py"
    echo "3. This will create the baseline file with known vulnerabilities"
else
    echo " Scan failed"
    exit 1
fi
