@echo off
echo Starting Final Year Project SIEM Application...
echo.

REM Activate virtual environment if it exists
if exist .venv\Scripts\activate (
    call .venv\Scripts\activate
)

REM Run Streamlit via Python module
python -m streamlit run Webapp\app.py

pause