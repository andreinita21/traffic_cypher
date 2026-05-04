@echo off
setlocal enabledelayedexpansion

rem ============================================================================
rem  Traffic Cypher (Rust) - Windows launcher
rem  Builds and runs the Rust implementation natively on Windows.
rem ============================================================================

cd /d "%~dp0"

echo.
echo +==========================================================+
echo ^|     T R A F F I C   C Y P H E R   ^(Rust^)               ^|
echo ^|     Windows launcher                                     ^|
echo +==========================================================+
echo.

rem ---------------------------------------------------------------
rem 1. Check for cargo / rustc
rem ---------------------------------------------------------------
where cargo >nul 2>nul
if errorlevel 1 (
    echo [-] Rust toolchain not found.
    echo.
    echo Install Rust from https://rustup.rs/ then re-run this script.
    echo The official installer adds cargo and rustc to your PATH automatically.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('rustc --version') do set "RUSTC_VERSION=%%v"
echo [+] Rust found: %RUSTC_VERSION%

rem ---------------------------------------------------------------
rem 2. Check for ffmpeg and yt-dlp (needed at runtime, not build time)
rem ---------------------------------------------------------------
set MISSING=0
where ffmpeg >nul 2>nul
if errorlevel 1 (
    echo [!] ffmpeg not found in PATH ^(needed for frame decoding^)
    set MISSING=1
) else (
    echo [+] ffmpeg found
)

where yt-dlp >nul 2>nul
if errorlevel 1 (
    echo [!] yt-dlp not found in PATH ^(needed to read YouTube livestreams^)
    set MISSING=1
) else (
    echo [+] yt-dlp found
)

if "%MISSING%"=="1" (
    echo.
    echo Install the missing tools before running the CLI key generator:
    echo.
    echo   winget install Gyan.FFmpeg
    echo   winget install yt-dlp.yt-dlp
    echo.
    echo The Password Manager mode does not need them and will still work.
    echo.
)

rem ---------------------------------------------------------------
rem 3. Build release binaries
rem ---------------------------------------------------------------
echo.
echo [*] Building Traffic Cypher ^(--release^)...
cargo build --release --bins
if errorlevel 1 (
    echo [-] Build failed.
    pause
    exit /b 1
)
echo [+] Build successful.
echo.
echo   target\release\traffic_cypher.exe  - CLI key generator
echo   target\release\pm.exe              - Password manager web UI
echo   target\release\bench.exe           - Benchmark harness
echo.

rem ---------------------------------------------------------------
rem 4. Mode selection
rem ---------------------------------------------------------------
echo How would you like to run Traffic Cypher?
echo.
echo   1^) Password Manager only       ^(web UI on http://127.0.0.1:9876^)
echo   2^) CLI key generator only       ^(requires a YouTube live URL^)
echo   3^) Just build, don't run
echo.
set /p CHOICE="Choose [1-3] (default: 1): "
if "%CHOICE%"=="" set CHOICE=1

if "%CHOICE%"=="1" goto :run_pm
if "%CHOICE%"=="2" goto :run_cli
if "%CHOICE%"=="3" goto :done
echo [-] Invalid choice
pause
exit /b 1

:run_pm
echo.
echo [*] Starting Password Manager on http://127.0.0.1:9876
echo [*] Press Ctrl+C to stop
start "" "http://127.0.0.1:9876"
target\release\pm.exe
goto :done

:run_cli
echo.
set /p STREAM_URL="Enter YouTube livestream URL: "
if "%STREAM_URL%"=="" (
    echo [-] No URL provided.
    pause
    exit /b 1
)
echo.
echo [*] Starting CLI key generator. Press Ctrl+C to stop.
echo.
target\release\traffic_cypher.exe -u "%STREAM_URL%" --show-metrics
goto :done

:done
echo.
pause
endlocal
