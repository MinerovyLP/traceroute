@echo off
cd /d "C:\Users\Admin\Desktop\randomjs\Multithreaded Traceroute"
:start
set /p dest="node tracert.js "
node tracert.js %dest%
echo.
goto start