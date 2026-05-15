#!/bin/bash
# SafeScan — Start the development server
# Usage: ./run.sh

# Navigate to the project directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check for Python 3.10 first (has all deps), fallback to python3
if [ -x "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3" ]; then
    PYTHON="/Library/Frameworks/Python.framework/Versions/3.10/bin/python3"
    echo "Using Python 3.10"
else
    PYTHON="python3"
    echo "Using system python3 — you may need to: pip install -r backend/requirements.txt"
fi

echo ""
echo "  🛡️  SafeScan — AI Threat Analyzer"
echo "  Starting server on http://localhost:8000"
echo ""

$PYTHON -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
