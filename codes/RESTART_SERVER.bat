@echo off
echo Stopping any running server...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *web_server*" 2>nul
timeout /t 2 /nobreak >nul
echo.
echo Starting CipherTalk Web Server...
python web_server.py

