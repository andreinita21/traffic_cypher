@echo off
setlocal enabledelayedexpansion

rem ============================================================================
rem  Traffic Cypher (C) - Windows launcher
rem  The C implementation depends on POSIX APIs (pthread, sockets, OpenSSL).
rem  On Windows the supported path is WSL 2. This script forwards to run.sh
rem  inside WSL, installing dependencies on first run.
rem ============================================================================

echo.
echo +==========================================================+
echo ^|     T R A F F I C   C Y P H E R   ^(C^)                  ^|
echo ^|     Windows launcher                                     ^|
echo +==========================================================+
echo.

where wsl >nul 2>nul
if errorlevel 1 (
    echo [-] WSL is not installed.
    echo.
    echo The C implementation needs a POSIX environment ^(pthread, OpenSSL, sockets^).
    echo Install WSL 2 once with the following command in an elevated PowerShell:
    echo.
    echo     wsl --install
    echo.
    echo Then re-run this script. Alternatively, use the Rust implementation in
    echo ..\traffic_cypher_in_Rust which builds natively on Windows.
    echo.
    pause
    exit /b 1
)

echo [*] WSL detected. Forwarding to run.sh inside WSL...
echo.

rem Convert the script directory to a WSL path and run.
for %%I in ("%~dp0.") do set "WIN_DIR=%%~fI"
wsl bash -c "cd \"$(wslpath -u '%WIN_DIR%')\" && chmod +x ./run.sh && ./run.sh"

if errorlevel 1 (
    echo.
    echo [-] run.sh exited with an error.
    pause
    exit /b 1
)

echo.
pause
endlocal
