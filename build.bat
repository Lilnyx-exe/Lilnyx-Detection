@echo off
echo =======================================================
echo   Lilnyx Detection Core C++ Builder - Thinking Team
echo =======================================================

g++ -O2 -std=c++17 -static -static-libgcc -static-libstdc++ ^
    src/main.cpp src/forensics.cpp src/bypass.cpp src/active_scanner.cpp src/defender.cpp src/reg_scanner.cpp src/remediation.cpp src/report.cpp ^
    -o DetectCheat.exe ^
    -ladvapi32 -lole32 -lshell32 -lpsapi -lwevtapi

if %ERRORLEVEL% EQU 0 (
    strip DetectCheat.exe
    echo.
    echo [SUCCESS] DetectCheat.exe successfully built!
    echo Output: %~dp0DetectCheat.exe
) else (
    echo.
    echo [ERROR] Build failed with error code %ERRORLEVEL%
)
