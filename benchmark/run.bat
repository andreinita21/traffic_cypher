@echo off
setlocal enabledelayedexpansion

rem ============================================================================
rem  Traffic Cypher Benchmark Suite - Windows launcher
rem  The benchmark suite measures the C and Rust implementations side by side.
rem  The C side requires a POSIX environment, so this script forwards to WSL.
rem ============================================================================

echo.
echo +==========================================================+
echo ^|     T R A F F I C   C Y P H E R   B E N C H M A R K     ^|
echo ^|     Windows launcher                                     ^|
echo +==========================================================+
echo.

where wsl >nul 2>nul
if errorlevel 1 (
    echo [-] WSL is not installed.
    echo.
    echo The benchmark suite needs a POSIX environment to build the C
    echo implementation. Install WSL 2 once with:
    echo.
    echo     wsl --install
    echo.
    echo Then re-run this script. The benchmark will build both implementations
    echo inside WSL and compare them.
    echo.
    pause
    exit /b 1
)

echo [*] WSL detected. Forwarding to run.sh inside WSL...
echo [*] This will run a clean build of both implementations and may take
echo     several minutes on the first run.
echo.

for %%I in ("%~dp0.") do set "WIN_DIR=%%~fI"
wsl bash -c "cd \"$(wslpath -u '%WIN_DIR%')\" && chmod +x ./run.sh && ./run.sh"

if errorlevel 1 (
    echo.
    echo [-] Benchmark exited with an error.
    pause
    exit /b 1
)

echo.
echo [+] Benchmark complete. Results in benchmark\results\
pause
endlocal
