import requests

payload = {
    'project_name': 'test_project',
    'files': [
        {'filename': 'url shortner/backend/app.py', 'source_code': 'import os\nos.system("ls")'},
        {'filename': 'url shortner/frontend/App.tsx', 'source_code': 'console.log(1)'}
    ]
}

try:
    response = requests.post('http://127.0.0.1:8000/api/analyze', json=payload)
    print("STATUS CODE:", response.status_code)
    print("JSON RESPONSE:", response.json())
except Exception as e:
    print("EXCEPTION:", e)
