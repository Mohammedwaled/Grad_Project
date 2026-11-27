@echo off
setlocal
cd /d "%~dp0"
set "PY=.venv\Scripts\python.exe"

if "%~1"=="" goto help
if /i "%~1"=="setup" goto setup

if not exist "%PY%" (
    echo [!] .venv not found. Run this first:  .\run setup
    exit /b 1
)

if /i "%~1"=="validate" goto validate
if /i "%~1"=="twin" goto twin
if /i "%~1"=="test" goto test
goto help

:setup
if not exist "%PY%" (
    echo Creating .venv ...
    py -3 -m venv .venv
    if errorlevel 1 python -m venv .venv
)
if not exist "%PY%" (
    echo [!] Could not create .venv. Make sure Python is installed.
    exit /b 1
)
"%PY%" -m pip install -r requirements.txt
exit /b %errorlevel%

:validate
"%PY%" data\schema\src\validate_config.py %2
exit /b %errorlevel%

:twin
"%PY%" src\build_twin.py %2
exit /b %errorlevel%

:test
"%PY%" -m unittest discover -s data\schema\tests
if errorlevel 1 exit /b 1
"%PY%" -m unittest discover -s tests
exit /b %errorlevel%

:help
echo.
echo Usage:  .\run ^<command^>
echo.
echo   setup      create .venv if missing + install requirements (once)
echo   validate   check data\network.json  (or:  .\run validate path\to\file.json)
echo   twin       build and print the digital twin
echo   test       run all tests
echo.
exit /b 0
