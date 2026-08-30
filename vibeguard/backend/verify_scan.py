import requests
import json

payload = {
    'project_name': 'url shortner',
    'files': [
        {'filename': 'url shortner/backend/app.py', 'source_code': 'import os\nos.system("ls")'},
        {'filename': 'url shortner/backend/requirements.txt', 'source_code': 'flask==0.12.3'},
        {'filename': 'url shortner/frontend/package.json', 'source_code': '{"dependencies": {"express": "4.17.2"}}'},
        {'filename': 'url shortner/frontend/src/App.tsx', 'source_code': 'console.log("hello");'},
        {'filename': 'url shortner/frontend/src/index.tsx', 'source_code': 'import React from "react";'},
        {'filename': 'url shortner/backend/models.py', 'source_code': 'class User: pass'},
        {'filename': 'url shortner/backend/auth.py', 'source_code': 'password = "super_secret_password_123"'},
        {'filename': 'url shortner/backend/utils.py', 'source_code': 'import yaml\nyaml.load("test")'},
        {'filename': 'url shortner/backend/config.py', 'source_code': 'DEBUG = True'},
        {'filename': 'url shortner/frontend/src/api.js', 'source_code': 'fetch("http://example.com", {mode: "no-cors"})'},
        {'filename': 'url shortner/frontend/src/components/List.tsx', 'source_code': 'export default function List() { return <div dangerouslySetInnerHTML={{__html: "hello"}} /> }'}
    ]
}

try:
    print(f"Sending {len(payload['files'])} files to /api/analyze...")
    response = requests.post('http://127.0.0.1:8000/api/analyze', json=payload)
    print("STATUS CODE:", response.status_code)
    
    if response.ok:
        data = response.json()
        print("\nScan completed successfully!")
        print("Total findings:", data.get('total_findings'))
        print("Metadata:", json.dumps(data.get('scan_metadata'), indent=2))
        
        print("\nSample of findings:")
        for finding in data.get('findings', [])[:5]:
            print(f"- [{finding['severity']}] {finding['title']} in {finding['file_path']}")
    else:
        print("JSON RESPONSE:", response.json())
except Exception as e:
    print("EXCEPTION:", e)
