# ws_test.py (Web Socket Test for Audit and Accountability as an example)
import httpx
import json


PHASE_ID = "aaa"


def send_terminal(event):
    line = f"[{PHASE_ID}]" + json.dumps(event)
    response = httpx.post(
        "http://127.0.0.1:8000/api/terminal/output",
        json={
            "phase_id": PHASE_ID,
            "line": line
        }
    )
    print(response.status_code, response.json())


for i in range(15):
    send_terminal({
        "type": "status",
        "text": "Hello from Python!"
    })
    send_terminal({
        "type": "status",
        "text": "Loading model..."
    })
    send_terminal({
        "type": "status",
        "text": "Processing input..."
    })
    send_terminal({
        "type": "status",
        "text": "Processing completed!"
    })
