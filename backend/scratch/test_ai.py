import requests
import json

payload = {
    "project_id": "dummy",
    "message": "hello"
}
try:
    res = requests.post("http://127.0.0.1:8765/api/analysis/project-summary", json=payload, stream=True)
    print("Status:", res.status_code)
    for line in res.iter_lines():
        if line:
            print(line.decode('utf-8'))
except Exception as e:
    print("Error:", e)
