from flask import Flask, request, render_template, send_file
import subprocess, os, json, zipfile, shutil, uuid
from git import Repo

app = Flask(__name__)

# Directories for handling files and reports
UPLOAD_FOLDER = 'uploads'
EXTRACT_FOLDER = 'extracted'
REPORT_FOLDER = 'reports'

# Ensure folders exist
for folder in [UPLOAD_FOLDER, EXTRACT_FOLDER, REPORT_FOLDER]:
    os.makedirs(folder, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_code():
    git_url = request.form.get('git_url')  # Git URL input from form
    extract_path = ''
    filename = ''

    try:
        if git_url:  # If Git URL provided
            repo_id = str(uuid.uuid4())
            extract_path = os.path.join(EXTRACT_FOLDER, repo_id)
            os.makedirs(extract_path, exist_ok=True)
            print(f"Cloning repository from {git_url}...")
            Repo.clone_from(git_url, extract_path)
            filename = git_url

        elif 'file' in request.files and request.files['file'].filename != '':
            file = request.files['file']
            if not file.filename.endswith('.zip'):
                return "Error: Only ZIP files are allowed.", 400
            zip_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(zip_path)
            extract_path = os.path.join(EXTRACT_FOLDER, str(uuid.uuid4()))
            os.makedirs(extract_path, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            filename = file.filename
        else:
            return "Error: No ZIP file or Git URL provided.", 400

        # Run Bandit on extracted/cloned path
        result = subprocess.run(['bandit', '-r', extract_path, '-f', 'json'],
                                capture_output=True, text=True)

        output_json = json.loads(result.stdout)
        issues = output_json.get('results', [])
        raw_log = result.stdout

        # Save JSON report for download
        report_id = str(uuid.uuid4())
        report_path = os.path.join(REPORT_FOLDER, f"{report_id}.json")
        with open(report_path, 'w') as f:
            json.dump(output_json, f)

        # Clean extracted files
        shutil.rmtree(extract_path, ignore_errors=True)

        return render_template('report.html',
                               issues=issues,
                               filename=filename,
                               raw_log=raw_log,
                               report_id=report_id,
                               git_url=git_url)

    except Exception as e:
        return f"Server Error: {str(e)}", 500

@app.route('/download_report/<report_id>')
def download_report(report_id):
    report_path = os.path.join(REPORT_FOLDER, f"{report_id}.json")
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    else:
        return "Error: Report not found.", 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
