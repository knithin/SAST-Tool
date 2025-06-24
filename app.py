from flask import Flask, request, render_template, send_file, jsonify
import subprocess, os, json, zipfile, shutil, uuid, smtplib, re, requests
from git import Repo
from email.message import EmailMessage
from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
EXTRACT_FOLDER = 'extracted'
REPORT_FOLDER = 'reports'
for folder in [UPLOAD_FOLDER, EXTRACT_FOLDER, REPORT_FOLDER]:
    os.makedirs(folder, exist_ok=True)

SMTP_SERVER, SMTP_PORT = 'localhost', 1025
SENDER_EMAIL, RECIPIENT_EMAIL = 'noreply@cdc.com', 'test@cdc.com'

LAST_COMMITS = {}
scheduler = BackgroundScheduler()
scheduler.start()

CWE_CVSS_MAPPING = {"CWE-79": 7.5, "CWE-89": 9.8, "CWE-78": 9.8, "CWE-200": 5.3, "CWE-22": 7.5, "CWE-352": 6.5}
SEVERITY_CVSS_MAPPING = {"INFO": 3.1, "WARNING": 5.0, "ERROR": 7.5}

def map_cwe_to_cvss(cwe_list):
    scores = [CWE_CVSS_MAPPING[c] for c in cwe_list if c in CWE_CVSS_MAPPING]
    return max(scores) if scores else None

def map_severity_to_cvss(sev):
    return SEVERITY_CVSS_MAPPING.get(sev.upper(), 0)

def cvss_to_severity(cvss):
    if cvss >= 9.0: return 'Critical'
    if cvss >= 7.0: return 'High'
    if cvss >= 4.0: return 'Medium'
    if cvss >= 0.1: return 'Low'
    return 'Info'

def send_email(report_path):
    msg = EmailMessage()
    msg['Subject'] = 'SAST Scan Report'
    msg['From'], msg['To'] = SENDER_EMAIL, RECIPIENT_EMAIL
    msg.set_content(f"Scan complete. Report ID: {os.path.basename(report_path)}")
    with open(report_path, 'rb') as f:
        msg.add_attachment(f.read(), maintype='application', subtype='json', filename=os.path.basename(report_path))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.send_message(msg)
    except Exception as e:
        print("Email error:", e)

def run_semgrep(path):
    r = subprocess.run(['semgrep','--config','auto',path,'--json'], capture_output=True, text=True)
    data = json.loads(r.stdout)
    for issue in data.get('results', []):
        cwe = issue.get('extra', {}).get('metadata', {}).get('cwe', [])
        sev = issue.get('extra', {}).get('severity','INFO')
        cv = map_cwe_to_cvss(cwe) or map_severity_to_cvss(sev)
        issue['cvss_score'] = cv
        issue['normalized_severity'] = cvss_to_severity(cv)
    return data, r.stdout

def scheduled_job(repo_url):
    repo_id = repo_url.rstrip('/').split('/')[-1].replace('.git','')
    path = os.path.join(EXTRACT_FOLDER, repo_id)
    if not os.path.exists(path):
        Repo.clone_from(repo_url, path)
    else:
        Repo(path).remotes.origin.pull()
    sha = Repo(path).head.commit.hexsha
    if LAST_COMMITS.get(repo_url)==sha: return
    LAST_COMMITS[repo_url]=sha
    data, _ = run_semgrep(path)
    if data:
        rp = os.path.join(REPORT_FOLDER, f"{uuid.uuid4()}.json")
        with open(rp,'w') as f: json.dump(data,f)
        send_email(rp)

def scan_web_secrets(base_url, pages=10):
    patterns = {
        'AWS_KEY': r'AKIA[0-9A-Z]{16}',
        'Bearer_Token': r'Bearer\s[\w\-._~+/]+=*',
        'API_Key': r'api[_-]?key[\'"\s:=\w]{16,}'
    }
    found=[]
    seen, q=set(), [base_url]
    while q and len(seen)<pages:
        url = q.pop(0); seen.add(url)
        try:
            r = requests.get(url, timeout=5, verify=False)
        except:
            continue
        text = r.text
        for name, pat in patterns.items():
            for m in re.findall(pat, text):
                found.append({'pattern': name,'match': m,'url': url})
        soup = BeautifulSoup(text,'html.parser')
        for a in soup.find_all('a',href=True):
            u=urljoin(base_url,a['href'])
            if urlparse(u).netloc==urlparse(base_url).netloc and u not in seen:
                q.append(u)
    return found

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    git_url = request.form.get('git_url')
    web_url = request.form.get('target_url')
    auto = request.form.get('auto_scan')=='on'
    extract=''
    filename=''
    site_findings=[]
    try:
        if web_url:
            site_findings = scan_web_secrets(web_url)
        if git_url:
            extract = os.path.join(EXTRACT_FOLDER, str(uuid.uuid4()))
            Repo.clone_from(git_url, extract)
            filename = git_url
            if auto:
                scheduler.add_job(scheduled_job,'interval',minutes=60,args=[git_url],id=git_url,replace_existing=True)
        elif 'file' in request.files and request.files['file'].filename:
            f=request.files['file']
            if not f.filename.endswith('.zip'):
                return "Only ZIP allowed",400
            zp=os.path.join(UPLOAD_FOLDER,f.filename); f.save(zp)
            extract=os.path.join(EXTRACT_FOLDER,str(uuid.uuid4()))
            zipfile.ZipFile(zp).extractall(extract)
            filename=f.filename
        else:
            return "Provide ZIP, Git URL, or Web URL",400

        sem_data, raw = run_semgrep(extract) if extract else ({'results':[]}, '')
        rid=str(uuid.uuid4()); rp=os.path.join(REPORT_FOLDER,f"{rid}.json")
        with open(rp,'w') as o: json.dump(sem_data,o)
        send_email(rp)
        if extract: shutil.rmtree(extract,ignore_errors=True)

        return render_template('report.html', issues=sem_data['results'],
                               raw_log=raw, report_id=rid, git_url=git_url,
                               target_url=web_url, website_findings=site_findings)
    except Exception as e:
        return f"Server Error: {e}",500

@app.route('/download_report/<report_id>')
def dl(report_id):
    p=os.path.join(REPORT_FOLDER,f"{report_id}.json")
    return send_file(p,as_attachment=True) if os.path.exists(p) else ("Not found",404)

if __name__=='__main__':
    app.run(debug=False, use_reloader=False, port=5000)
