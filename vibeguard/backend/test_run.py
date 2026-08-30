import sys
import os
import traceback

sys.path.append(r'd:\tcs hackathon\tcs-hackathon\vibeguard')

from backend.database.connection import SessionLocal
from backend.services.scan_orchestrator import run_full_scan
from backend.utils import file_safety

workspace_dir = file_safety.new_workspace()
try:
    project_root = file_safety.detect_project_root(workspace_dir)
    db = SessionLocal()
    try:
        report = run_full_scan(
            db=db,
            project_name="test_project",
            workspace_dir=workspace_dir,
            project_root=project_root
        )
        print("SUCCESS")
    finally:
        db.close()
except Exception as e:
    traceback.print_exc()
finally:
    file_safety.cleanup_workspace(workspace_dir)
