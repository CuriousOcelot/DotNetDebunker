@echo off
:: Ask the user for input
:ask
set /p choice=Do you want to setup virtual environment? (Y/N):

:: Take only the first letter of the input
set "choice=%choice:~0,1%"

:: Check input and act accordingly
if /i "%choice%"=="Y" (
    echo Installing virtual environment
    goto continue
) else if /i "%choice%"=="N" (
    echo Exiting...
    goto end
) else (
    echo Invalid choice. Please enter Y or N.
    goto ask
)

:end
pause
exit /b

:continue
REM Check if the '.venv' directory already exists
IF EXIST ".venv" (
    echo The virtual environment '.venv' already exists. Installation is canceled.
    timeout /t 10 /nobreak >nul
    exit /b 1
)

REM Check if the 'requirements.txt' file exists
IF NOT EXIST "requirements.txt" (
    echo 'requirements.txt' file not found! Please make sure the file exists in the current directory.
    timeout /t 10 /nobreak >nul
    exit /b 1
)

REM Step 1: Create a virtual environment in the '.venv' directory
echo Creating a virtual environment in the '.venv' directory...
python -m venv .venv

REM Step 2: Activate the virtual environment
echo Activating the virtual environment...
call .venv\Scripts\activate.bat

REM Step 3: Install the dependencies from 'requirements.txt'
echo Installing dependencies from 'requirements.txt'...
pip install -r requirements.txt

REM Notify that the environment is set up
echo Virtual environment created and dependencies installed successfully.

echo Script complete!
pause >nul