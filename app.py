import os
import subprocess
import json
import shutil
import uuid
from git import Repo
import schedule
import time

REPO_DIR = 'cloned_repos'
REPORT_DIR = 'scheduled_reports'
os.makedirs(REPO_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# Repo configuration (can be made dynamic later)
REPO_URL = 'https://github.com/knithin/SAST-Tool'
REPO_NAME = 'SAST-Tool'

def clone_or_pull_repo():
    repo_path = os.path.join(REPO_DIR, REPO_NAME)
    if not os.path.exists(repo_path):
        print("Cloning repository...")
        Repo.clone_from(REPO_URL, repo_path)
    else:
        print("Pulling latest changes...")
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        origin.pull()
    return repo_path

def get_changed_files(repo_path):
    repo = Repo(repo_path)
    commits = list(repo.iter_commits('master', max_count=2))
    if len(commits) < 2:
        return []  # First commit — no changes
    diff_index = commits[0].diff(commits[1])
    changed_files = [item.a_path for item in diff_index if item.a_path.endswith('.py')]
    return changed_files

def run_bandit_scan(path):
    result = subprocess.run(['bandit', '-r', path, '-f', 'json'],
                            capture_output=True, text=True)
    output_json = json.loads(result.stdout)
    return output_json, result.stdout

def scheduled_task():
    print("=== Running Scheduled SAST Task ===")
    repo_path = clone_or_pull_repo()
    changed_files = get_changed_files(repo_path)
    print(f"Changed Python files: {changed_files if changed_files else 'None (Full scan)'}")

    scan_path = repo_path  # Optionally restrict to only changed files
    report, raw_log = run_bandit_scan(scan_path)

    # Save JSON report
    report_id = str(uuid.uuid4())
    report_path = os.path.join(REPORT_DIR, f"{report_id}.json")
    with open(report_path, 'w') as f:
        json.dump(report, f)

    print(f"Bandit scan complete. Report saved to {report_path}\n")

# Schedule: Run every 10 minutes
schedule.every(10).minutes.do(scheduled_task)

print("Scheduled SAST tool started. Running every 10 minutes...")
while True:
    schedule.run_pending()
    time.sleep(1)
