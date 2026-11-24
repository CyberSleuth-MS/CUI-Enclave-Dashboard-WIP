import httpx
S = "http://127.0.0.1:8000"

# Success
httpx.post(f"{S}/api/phases", json={"id": "t", "title": "Test", "steps": [{"id": "a", "label": "A", "status": "pending"}]})
httpx.patch(f"{S}/api/phases/t/steps/a", json={"status": "success", "label": "Done"}).raise_for_status()

# Failure
httpx.post(f"{S}/api/phases", json={"id": "t2", "title": "Test Two", "steps": [{"id": "a", "label": "A", "status": "pending"}]})
httpx.patch(f"{S}/api/phases/t2/steps/a", json={"status": "failure", "label": "Done"}).raise_for_status()
