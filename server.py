# server.py (Mostly done, just lacks implementation in assess.py of terminal mini-pages)
import json
import markdown
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import WebSocket, WebSocketDisconnect  # For terminal drawers
from pydantic import BaseModel, Field

app = FastAPI()
terminal_clients = {}
terminal_history = {}

BASE_DIR = Path(__file__).parent
DATA_FILE = BASE_DIR / "workflow.json"
HTML_FILE = BASE_DIR / "index.html"

# Web Dashboard
VALID_STATUSES = {"pending", "active", "success", "warning", "failure"}
# Gap Report / Assessment Results JSON
VALID_REPORT_STATUSES = {"pending", "generating", "done", "error"}

# DEFAULT_WORKFLOW = {
    # "reports": {
        # "gap-report": "pending"
    # },
    # "phases": [
        # {
            # "id": "mfa",
            # "title": "🛡 Access Control",
            # "file": "monitor.html",
            # "background": "/assets/mfa.jpg",
            # "steps": [
                # {"id": "email", "label": "Email Verified", "status": "pending"},
                # {"id": "password", "label": "Password Rotation Policy", "status": "pending"},
                # {
                    # "id": "mfa-enabled",
                    # "label": "MFA Enabled For All Users",
                    # "status": "pending",
                    # "message": "2 users still require MFA enrollment."
                # }
            # ]
        # },
        # {
            # "id": "aaa",
            # "title": "🛡 Audit and Accountability",
            # "file": "monitor.html",
            # "background": "/assets/aaa.jpg",
            # "steps": [
                # {
                    # "id": "email-3.1.1",
                    # "label": "Email Verified",
                    # "status": "pending"
                # },
                # {
                    # "id": "password-3.1.22",
                    # "label": "Password Rotation Policy",
                    # "status": "pending"
                # },
                # {
                    # "id": "mfa-enabled-3.2.1-3.2.2",
                    # "label": "MFA Enabled For All Users",
                    # "status": "pending",
                    # "message": "2 users still require MFA enrollment."
                # }
            # ]
        # },
        # {
            # "id": "password-phase",
            # "title": "🔑 Password Security",
            # "file": "monitor.html",
            # "background": "/assets/passwords.jpg",
            # "steps": [
                # {"id": "complexity", "label": "Password Complexity", "status": "pending"},
                # {"id": "expiration", "label": "Password Expiration", "status": "pending"}
            # ]
        # }
    # ]
# }
# NOT THIS
#DEFAULT_WORKFLOW = {"reports": {"gap-report": "pending"}, "phases": [{}]}
# MUST BE
DEFAULT_WORKFLOW = {"reports": {"gap-report": "pending"}, "phases": []}


# Not needed due to usage in a live/real-time environment
#def save_workflow():
    # temporary = DATA_FILE.with_suffix(".tmp")
    # temporary.write_text(
        # json.dumps(WORKFLOW, indent=4, ensure_ascii=False),
        # encoding="utf-8"
    # )
    # temporary.replace(DATA_FILE)


# if DATA_FILE.exists():
    # WORKFLOW = json.loads(DATA_FILE.read_text(encoding="utf-8"))
# else:
    # WORKFLOW = DEFAULT_WORKFLOW
    #save_workflow()
WORKFLOW = DEFAULT_WORKFLOW


class ReportUpdate(BaseModel):
    status: str


class StepUpdate(BaseModel):
    status: str | None = None
    label: str | None = None
    message: str | None = None


class StepCreate(BaseModel):
    id: str
    label: str
    status: str = "pending"
    message: str | None = None


class PhaseCreate(BaseModel):
    id: str
    title: str
    file: str | None = None
    background: str | None = None
    steps: list[StepCreate] = Field(default_factory=list)


class PhaseUpdate(BaseModel):
    title: str | None = None
    file: str | None = None
    background: str | None = None
    status: str | None = None


class TerminalOutput(BaseModel):
    phase_id: str
    line: str


def get_phase(phase_id):
    for phase in WORKFLOW["phases"]:
        if phase["id"] == phase_id:
            return phase
    raise HTTPException(404, "Phase not found")


def get_step(phase, step_id):
    for step in phase["steps"]:
        if step["id"] == step_id:
            return step
    raise HTTPException(404, "Step not found")


@app.get("/")
async def index():
    return FileResponse(HTML_FILE)


@app.get("/api/workflow")
async def get_workflow():
    return WORKFLOW


app.mount("/assets", StaticFiles(directory=BASE_DIR), name="assets")


@app.websocket("/ws/terminal/{phase_id}")
async def terminal_websocket(websocket: WebSocket, phase_id: str):
    await websocket.accept()
    clients = terminal_clients.setdefault(phase_id, set())
    clients.add(websocket)
    try:
        # Replay previously received messages
        for line in terminal_history.get(phase_id, []):
            await websocket.send_text(line)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(websocket)
        if not clients:
            terminal_clients.pop(phase_id, None)


@app.post("/api/terminal/output")
async def terminal_output(data: TerminalOutput):
    phase_id = data.phase_id
    history = terminal_history.setdefault(phase_id, [])
    # New run: clear previous terminal output
    if '"type": "start"' in data.line or '"type":"start"' in data.line:
        history.clear()
    history.append(data.line)
    clients = terminal_clients.get(phase_id, set())
    disconnected = []
    for client in list(clients):
        try:
            await client.send_text(data.line)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        clients.discard(client)
    if not clients:
        terminal_clients.pop(phase_id, None)
    return {
        "success": True,
        "clients": len(clients),
        "stored": len(history)
    }


@app.get(
    "/api/reports/{report_id}",
    response_class=HTMLResponse
)
@app.get(
    "/api/reports/{report_id}.md",
    response_class=HTMLResponse
)
async def get_report(report_id: str):

    if report_id not in WORKFLOW["reports"]:
        raise HTTPException(404, "Report not found")

    if WORKFLOW["reports"][report_id] != "done":
        raise HTTPException(404, "Report is not ready")

    report_path = Path(__file__).resolve().parent / f"{report_id}.md"

    if not report_path.is_file():
        raise HTTPException(404, "Report file not found")

    content = report_path.read_text(encoding="utf-8")

    html_content = markdown.markdown(
        content,
        extensions=[
            "tables",
            "fenced_code",
            "toc",
            "attr_list"
        ]
    )

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <title>{report_id.replace('-', ' ').title()}</title>

        <style>
            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                padding: 40px 20px;
                background: #f1f5f9;
                color: #1e293b;
                font-family: Inter, -apple-system, BlinkMacSystemFont,
                             "Segoe UI", sans-serif;
                line-height: 1.7;
            }}

            .report-container {{
                max-width: 1000px;
                margin: auto;
                background: white;
                padding: 50px 65px;
                border-radius: 14px;
                box-shadow: 0 4px 25px rgba(0,0,0,0.06);
            }}

            h1 {{
                font-size: 2.2rem;
                color: #0f172a;
                border-bottom: 3px solid #3b82f6;
                padding-bottom: 18px;
                margin-bottom: 30px;
            }}

            h2 {{
                color: #1e40af;
                margin-top: 42px;
                padding-bottom: 10px;
                border-bottom: 1px solid #e2e8f0;
            }}

            h3 {{
                color: #334155;
                margin-top: 28px;
            }}

            p {{
                margin: 16px 0;
            }}

            ul, ol {{
                padding-left: 28px;
            }}

            li {{
                margin: 8px 0;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 25px 0;
                font-size: 0.95rem;
            }}

            th {{
                background: #1e40af;
                color: white;
                text-align: left;
            }}

            th, td {{
                padding: 13px 16px;
                border: 1px solid #e2e8f0;
            }}

            tr:nth-child(even) {{
                background: #f8fafc;
            }}

            blockquote {{
                margin: 25px 0;
                padding: 15px 22px;
                border-left: 4px solid #3b82f6;
                background: #eff6ff;
                color: #334155;
            }}

            code {{
                background: #f1f5f9;
                padding: 3px 6px;
                border-radius: 4px;
                font-size: 0.9em;
            }}

            pre {{
                background: #0f172a;
                color: #e2e8f0;
                padding: 20px;
                border-radius: 9px;
                overflow-x: auto;
            }}

            pre code {{
                background: transparent;
                padding: 0;
                color: inherit;
            }}

            a {{
                color: #2563eb;
                text-decoration: none;
            }}

            a:hover {{
                text-decoration: underline;
            }}

            img {{
                max-width: 100%;
                border-radius: 8px;
            }}

            hr {{
                border: none;
                border-top: 1px solid #e2e8f0;
                margin: 35px 0;
            }}

            @media (max-width: 650px) {{
                body {{
                    padding: 10px;
                }}

                .report-container {{
                    padding: 25px 20px;
                }}

                h1 {{
                    font-size: 1.7rem;
                }}

                table {{
                    display: block;
                    overflow-x: auto;
                }}
            }}
        </style>
    </head>

    <body>
        <main class="report-container">
            {html_content}
        </main>
    </body>
    </html>
    """)


@app.patch("/api/reports/{report_id}")
async def update_report(report_id: str, data: ReportUpdate):

    if report_id not in WORKFLOW["reports"]:
        raise HTTPException(404, "Report not found")
    if data.status not in VALID_REPORT_STATUSES:
        raise HTTPException(400, "Invalid report status")

    WORKFLOW["reports"][report_id] = data.status
    return {
        "success": True,
        "report": report_id,
        "status": data.status
    }


@app.patch("/api/phases/{phase_id}")
async def update_phase(phase_id: str, data: PhaseUpdate):
    phase = get_phase(phase_id)
    updates = data.model_dump(exclude_unset=True)
    if "status" in updates and updates["status"] not in VALID_STATUSES:
        raise HTTPException(400, "Invalid status")
    phase.update(updates)
    return {"success": True, "phase": phase}


@app.patch("/api/phases/{phase_id}/steps/{step_id}")
async def update_step(phase_id: str, step_id: str, data: StepUpdate):
    phase = get_phase(phase_id)
    step = get_step(phase, step_id)
    updates = data.model_dump(exclude_unset=True)

    if "status" in updates and updates["status"] not in VALID_STATUSES:
        raise HTTPException(400, "Invalid status")

    step.update(updates)
    #save_workflow()
    return {"success": True, "step": step}


@app.post("/api/phases/{phase_id}/steps")
async def add_step(phase_id: str, data: StepCreate):
    phase = get_phase(phase_id)

    if data.status not in VALID_STATUSES:
        raise HTTPException(400, "Invalid status")

    if any(step["id"] == data.id for step in phase["steps"]):
        raise HTTPException(409, "Step ID already exists")

    step = data.model_dump()
    phase["steps"].append(step)
    #save_workflow()
    return {"success": True, "step": step}


@app.delete("/api/phases/{phase_id}/steps/{step_id}")
async def remove_step(phase_id: str, step_id: str):
    phase = get_phase(phase_id)
    step = get_step(phase, step_id)
    
    phase["steps"].remove(step)
    #save_workflow()
    return {"success": True}


@app.post("/api/phases")
async def add_phase(data: PhaseCreate):
    # Causes wrong error if None
    #if any(phase["id"] == data.id for phase in WORKFLOW["phases"]):
    # Allows for None
    if any(phase.get("id") == data.id for phase in WORKFLOW["phases"]):
        raise HTTPException(409, "Phase ID already exists")

    if any(step.status not in VALID_STATUSES for step in data.steps):
        raise HTTPException(400, "Invalid step status")

    phase = data.model_dump()
    WORKFLOW["phases"].append(phase)
    #save_workflow()
    return {"success": True, "phase": phase}


@app.delete("/api/phases/{phase_id}")
async def remove_phase(phase_id: str):
    phase = get_phase(phase_id)
    WORKFLOW["phases"].remove(phase)
    #save_workflow()
    return {"success": True}
