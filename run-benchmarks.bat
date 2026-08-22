@echo off
REM Double-click this file to run every CHRONOS benchmark and collect the results.
REM
REM Results land in benchmark-results\<timestamp>\ with a SUMMARY.md, the machine
REM specification, and one log per step. Nothing is uploaded and nothing outside
REM this folder is modified.

cd /d "%~dp0"

echo.
echo  CHRONOS - full benchmark collection
echo  ----------------------------------
echo  This takes 20-40 minutes. The first run is slowest because TFHE-rs and
echo  arkworks compile from scratch.
echo.
echo  Plug into mains power first: on battery the CPU throttles and the timings
echo  will not be reproducible.
echo.
pause

powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\collect_benchmarks.ps1" %*

echo.
echo  Done. Open the newest folder under benchmark-results\ and read SUMMARY.md
echo.
pause
