@echo off
echo Testing Asthak.exe startup...
echo ================================
cd /d C:\Users\HP\Desktop\rp\build
echo Running from: %CD%
echo.
echo Checking for required files:
if exist Asthak.exe (echo [OK] Asthak.exe found) else (echo [MISSING] Asthak.exe NOT found!)
if exist libAsthak_Hook.dll (echo [OK] libAsthak_Hook.dll found) else (echo [MISSING] libAsthak_Hook.dll NOT found!)
if exist C:\Users\HP\Desktop\rp\rules.yar (echo [OK] rules.yar found) else (echo [MISSING] rules.yar NOT found!)
echo.
echo Checking MinGW runtime DLLs:
for %%f in (libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll) do (
    where %%f >nul 2>&1 && echo [OK] %%f in PATH || (
        if exist "C:\msys64\mingw64\bin\%%f" (echo [OK] %%f in msys64) else (echo [WARN] %%f not found in PATH)
    )
)
echo.
echo Attempting to start Asthak.exe (5 second timeout)...
start /wait /b "" "C:\Users\HP\Desktop\rp\build\Asthak.exe" > C:\Users\HP\Desktop\rp\asthak_run.txt 2>&1
echo Exit code: %ERRORLEVEL%
echo.
echo Output captured in asthak_run.txt:
type C:\Users\HP\Desktop\rp\asthak_run.txt
echo ================================
pause
