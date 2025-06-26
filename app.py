from flask import Flask, render_template, request, send_file
import subprocess, os, json, zipfile, shutil, uuid, smtplib, re, requests, socket, ssl, urllib3, time
from git import Repo
from email.message import EmailMessage
from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup
from zapv2 import ZAPv2
from urllib.parse import urlparse, urljoin
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
UPLOAD_FOLDER, EXTRACT_FOLDER, REPORT_FOLDER = 'uploads','extracted','reports'
for d in [UPLOAD_FOLDER, EXTRACT_FOLDER, REPORT_FOLDER]: os.makedirs(d, exist_ok=True)

SMTP_SERVER, SMTP_PORT = 'localhost', 1025
SENDER_EMAIL, RECIPIENT_EMAIL = 'noreply@mail.com', 'test@mail.com'
scheduler = BackgroundScheduler(); scheduler.start()
LAST_COMMITS = {}

CWE_CVSS = {"CWE-79":7.5,"CWE-89":9.8,"CWE-78":9.8,"CWE-200":5.3,"CWE-22":7.5,"CWE-352":6.5}
SEV_CVSS = {"INFO":3.1,"WARNING":5.0,"ERROR":7.5}

def map_cwsev(cwe_list):
    s = [CWE_CVSS[c] for c in cwe_list if c in CWE_CVSS]
    return max(s) if s else None

def sev_to_cvss(s): return SEV_CVSS.get(s.upper(), 0)
def cvss_to_sev(c): return "Critical" if c>=9 else "High" if c>=7 else "Medium" if c>=4 else "Low" if c>=0.1 else "Info"

def send_email_report(path):
    msg = EmailMessage()
    msg['Subject'] = 'SAST Scan Report'
    msg['From'], msg['To'] = SENDER_EMAIL, RECIPIENT_EMAIL
    msg.set_content(f"Scan complete: {os.path.basename(path)}")
    with open(path,'rb') as f:
        msg.add_attachment(f.read(), maintype='application', subtype='json', filename=os.path.basename(path))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s: s.send_message(msg)
    except Exception as e:
        print("Email error:", e)

def run_semgrep(path):
    r = subprocess.run(['semgrep','--config','auto',path,'--json'], capture_output=True, text=True)
    data = json.loads(r.stdout or "{}")
    for i in data.get("results", []):
        cwe = i.get("extra",{}).get("metadata",{}).get("cwe", [])
        sev = i.get("extra",{}).get("severity", "INFO")
        cv = map_cwsev(cwe) or sev_to_cvss(sev)
        i["cvss_score"]=cv; i["normalized_severity"]=cvss_to_sev(cv)
    return data, r.stdout

def scheduled_job(repo):
    name = repo.rstrip('/').split('/')[-1].replace('.git','')
    p = os.path.join(EXTRACT_FOLDER, name)
    if not os.path.exists(p): Repo.clone_from(repo, p)
    else: Repo(p).remotes.origin.pull()
    sha = Repo(p).head.commit.hexsha
    if LAST_COMMITS.get(repo) == sha: return
    LAST_COMMITS[repo] = sha
    data, _ = run_semgrep(p)
    rid = str(uuid.uuid4()); out = os.path.join(REPORT_FOLDER,f"{rid}.json")
    with open(out,'w') as f: json.dump(data, f)
    send_email_report(out)

def crawl_subdomains(base, max_pages=20):
    visited, q, subs = set(), [base], set()
    dom = urlparse(base).hostname
    while q and len(visited) < max_pages:
        u = q.pop(0); visited.add(u)
        try: r = requests.get(u, timeout=5, verify=False)
        except: continue
        for a in BeautifulSoup(r.text,"html.parser").find_all('a', href=True):
            link = urljoin(base, a['href']); p = urlparse(link)
            if p.scheme in ['http','https'] and p.netloc.endswith(dom):
                if link not in visited: q.append(link)
                subs.add(p.netloc)
    return sorted(subs)

def get_ssl_info(h):
    ctx=ssl.create_default_context()
    with socket.create_connection((h,443),timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=h) as s: cert=s.getpeercert()
    exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    iss = dict(x[0] for x in cert['issuer']).get('O','')
    return {'hostname':h, 'issuer':iss, 'expiry':exp.strftime('%Y-%m-%d'),
            'status':'Valid' if exp>datetime.utcnow() else 'Expired'}

def scan_secrets(txt):
    pats = {'AWS_KEY':r'AKIA[0-9A-Z]{16}','Bearer':r'Bearer\s[\w\-._~+/]+=*'}
    return [{'pattern':n,'match':m} for n,p in pats.items() for m in re.findall(p, txt)]

def run_zap_scan(target, apikey='', zap_port=8080):
    zap = ZAPv2(apikey=apikey, proxies={'http':f'http://127.0.0.1:{zap_port}','https':f'http://127.0.0.1:{zap_port}'})
    zap.urlopen(target); time.sleep(2)
    scanid = zap.spider.scan(target)
    while int(zap.spider.status(scanid)) < 100: time.sleep(1)
    zap.ascan.scan(target)
    while int(zap.ascan.status()) < 100: time.sleep(2)
    return zap.core.alerts()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    fzip = request.files.get('file'); repo = request.form.get('git_url')
    web = request.form.get('target_url'); auto = request.form.get('auto_scan')=='on'
    scan_ssl = request.form.get('scan_certs')=='on'
    extract = None; code_results=[]; raw=""; subdomains=[]; certs=[]; secrets=[]; zap_alerts=[]

    try:
        if web:
            subdomains = crawl_subdomains(web)
            if scan_ssl: certs=[get_ssl_info(h) for h in subdomains]
            try:
                r = requests.get(web, timeout=5, verify=False)
                secrets = scan_secrets(r.text)
            except: pass
            try:
                zap_alerts = run_zap_scan(web)
            except Exception as e:
                print("ZAP error:", e)

        if repo:
            extract=os.path.join(EXTRACT_FOLDER, str(uuid.uuid4())); Repo.clone_from(repo, extract)
            if auto:
                scheduler.add_job(scheduled_job,'interval',minutes=60,args=[repo], id=repo, replace_existing=True)
        elif fzip and fzip.filename.endswith('.zip'):
            pth=os.path.join(UPLOAD_FOLDER,fzip.filename); fzip.save(pth)
            extract=os.path.join(EXTRACT_FOLDER, str(uuid.uuid4()))
            zipfile.ZipFile(pth).extractall(extract)

        if extract:
            data, raw = run_semgrep(extract)
            code_results = data.get("results", [])
            shutil.rmtree(extract, ignore_errors=True)

        rid=str(uuid.uuid4()); out=os.path.join(REPORT_FOLDER,f"{rid}.json")
        report={'issues':code_results,'secrets':secrets,'subdomains':subdomains,'certs':certs,'zap':zap_alerts,'raw':raw}
        with open(out,'w') as f: json.dump(report, f, indent=2)
        send_email_report(out)

        return render_template('report.html', issues=code_results, secrets=secrets,
                               subdomains=subdomains, cert_info=certs,
                               zap_results=zap_alerts, raw_log=raw,
                               report_id=rid, git_url=repo, target_url=web)
    except Exception as e:
        return f"Server Error: {e}", 500

@app.route('/download_report/<report_id>')
def dl(report_id):
    p=os.path.join(REPORT_FOLDER, f"{report_id}.json")
    return send_file(p,as_attachment=True) if os.path.exists(p) else ("Not found",404)

if __name__=='__main__':
    app.run(debug=False, use_reloader=False, port=5000)
