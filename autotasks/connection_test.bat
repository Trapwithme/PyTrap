@echo off
echo === PyRat Auto-Execute Test ===
echo Test executed at %TIME% on %DATE%
echo This file was automatically sent to the client from the autotasks system
echo.
echo Connection successful!
echo.

:: Create a verification file to confirm execution
echo Test executed successfully at %TIME% on %DATE% > %USERPROFILE%\Downloads\PyRat\connection_verified.txt
echo Verification file created at: %USERPROFILE%\Downloads\PyRat\connection_verified.txt

:: Allow time to see the console
timeout /t 10 