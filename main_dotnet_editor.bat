


@echo off
set "OUT_PATH=%USERPROFILE%\Downloads\testprog_unpacked.exe"
set "INPUT_EXE=%~dp0rsc\jit_hook_test_binary\test_packed_binary\testprog_packed.exe"
set "WIN_DEBUG_OUTPUT=%~dp0rsc\jit_hook_test_binary\windbg_output"



set PYTHONPATH=%PYTHONPATH%;"%~dp0"
cd "%~dp0"
set PYTHON_EXE=%~dp0.venv\Scripts\python.exe
%PYTHON_EXE% ./main_dotnet_editor.py -i "%INPUT_EXE%" -o "%OUT_PATH%" -w "%WIN_DEBUG_OUTPUT%" -ns -a
timeout 30