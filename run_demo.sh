#!/bin/bash
echo "Installing dependencies..."
pip3 install -r requirements.txt
echo "Running Unified IDS..."
python3 ids_unified_both_modes.py
