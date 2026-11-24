@echo off
title 1 - WebUI Assessment Dashboard
uvicorn server:app --host 127.0.0.1 --port 8000 --log-level warning
pause
exit
