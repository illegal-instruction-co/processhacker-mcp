@echo off
set LOGFILE=C:\Users\machi\Desktop\lab\ProcessHackerMCP\mcp_debug.log
echo [WRAPPER START] %DATE% %TIME% >> %LOGFILE%

REM Pipe stdin to the exe, and tee stdout and stderr to the log
C:\Users\machi\Desktop\lab\ProcessHackerMCP\build\ProcessHackerMCP.exe >> %LOGFILE% 2>&1
