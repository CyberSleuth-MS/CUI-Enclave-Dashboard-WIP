@echo off
title 2 - Security Controls Assessment - Update Dashboard
python assess.py --region us-east-2 --json results.json --report gap-report.md
pause
exit
