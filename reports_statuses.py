# reports_statuses.py
from pathlib import Path
import json, os, requests


def set_gap_report_status(status, server_url):
    response = requests.patch(
        f"{server_url}/api/reports/gap-report",
        json={"status": status},
        timeout=5
    )
    response.raise_for_status()


def start_gap_report(server_url):
    set_gap_report_status("generating", server_url)


def finish_gap_report(server_url):
    set_gap_report_status("done", server_url)
