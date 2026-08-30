import requests

payload = {
    'project_name': 'test_project',
    'files': [
        {'filename': 'app.py', 'source_code': 'print("hello")'},
        {'filename': 'myenv/Lib/site-packages/pytest/__init__.py', 'source_code': ''},
        {'filename': 'node_modules/express/index.js', 'source_code': 'console.log(1)'}
    ]
}

response = requests.post('http://127.0.0.1:8000/api/analyze', json=payload)
print(response.status_code)
print(response.json())
