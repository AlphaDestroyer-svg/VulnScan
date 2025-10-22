@echo off
echo Starting VulnScan Web Interface...
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv .venv
    echo.
)

call .venv\Scripts\activate.bat

echo Installing/updating dependencies...
pip install -q flask flask-cors requests colorama
echo.

echo Starting web server on http://localhost:5000
echo Press Ctrl+C to stop
echo.

python web_server.py
