@echo off
set PYTHONPATH=%PYTHONPATH%;"%~dp0"
cd "%~dp0"
set PYTHON_EXE=%~dp0.venv\Scripts\python.exe
%PYTHON_EXE% ./test_unpack.py
timeout 30