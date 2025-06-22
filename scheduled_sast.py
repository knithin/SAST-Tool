import os, subprocess, json, shutil, uuid, schedule, time
from git import Repo

REPO_DIR, REPORT_DIR = 'cloned_repos', 'scheduled_reports'
for folder in [REPO_DIR, REPORT_DIR]: os.makedirs(folder, exist_ok=True)

REPO_URL = 'https://github.com/knithin/SAST-Tool.git'
REPO_NAME = 'SAST-Tool'

def clone_or_pull_repo():
    path = os.path.join(REPO_DIR, REPO_NAME)
    if not os.path.exists(path): Repo.clone_from(REPO_URL, path)
    else: Repo(path).remotes.origin.pull()
    return path

def run_bandit(path):
    result = subprocess.run(['bandit', '-r', path, '-f', 'json'],
                            capture_output=True, text=True)
    return json.loads(result.stdout)

def scheduled_task():
    print("Running scheduled SAST...")
    repo_path = clone_or_pull_repo()
    report = run_bandit(repo_path)
    report_path = os.path.join(REPORT_DIR, f"{uuid.uuid4()}.json")
    with open(report_path, 'w') as f: json.dump(report, f)
    print(f"Report saved: {report_path}")

schedule.every(10).minutes.do(scheduled_task)

while True:
    schedule.run_pending()
    time.sleep(1)
