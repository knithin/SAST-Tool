# 🔍 Python SAST Web & Scheduled Scanner using Bandit

A comprehensive **Static Application Security Testing (SAST) tool** built with **Flask, Bandit, and GitPython**, designed to scan Python projects for security vulnerabilities both manually via a web interface and automatically via scheduled Git repository scans.

---

## 🚀 Features

### 🌐 Web-Based SAST Scanning
- **ZIP File Upload:** Upload a ZIP file containing your Python project via a modern, Bootstrap-powered UI.
- **Automatic Extraction:** The ZIP file is extracted server-side and scanned using Bandit.
- **Vulnerability Table:** A clear, tabular display of Bandit results showing issue ID, severity, confidence, file path, and line number.
- **Raw Bandit Logs:** Full JSON log output displayed on the result page for in-depth analysis.
- **Downloadable JSON Report:** Easily download the full Bandit scan result as a JSON file.

---

### 🔁 Scheduled Git Repository Scanning
- **GitHub/GitLab URL Support:** Specify a Git repository URL instead of uploading files.
- **Auto Clone/Pull:** Repositories are cloned (first time) or pulled (subsequent runs) to ensure the latest code is scanned.
- **Bandit SAST Execution:** The entire repository is scanned for security issues.
- **Automatic JSON Report Saving:** Each scan result is stored locally with a unique ID for historical tracking.
- **Configurable Scan Frequency:** Uses the `schedule` Python library to run scans at customizable intervals (default: every 10 minutes). -- **In Progress**

---

### 🛡️ Security & Reliability Features
- **ZIP Content Validation:** Ensures only `.py` files are scanned from uploaded ZIPs.
- **File Size Limiting:** Restricts uploaded ZIP files to avoid DoS attacks (default: 10 MB).
- **Error Handling:** Friendly error pages and server-side checks to prevent misuse.
- **Docker-Ready:** Can be containerized and deployed securely using Docker. **In-Progress**

---

## 🛠️ Tech Stack

- **Backend:** Python 3, Flask, GitPython
- **Frontend:** HTML5, Bootstrap 5
- **Static Analysis:** Bandit
- **Scheduler:** Python `schedule` library
- **Containerization:** Docker (Optional)

---

## 📦 Setup & Installation

### 1. Clone the Repository:
```bash
git clone https://github.com/knithin/SAST-Tool.git
pip install flask bandit GitPython schedule
cd SAST-Tool
