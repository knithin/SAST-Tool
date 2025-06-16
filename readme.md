# 🔍 Code Security Scanner Web Application - SAST Tool

A lightweight and extensible **web application for scanning uploaded code files** to detect security vulnerabilities using static analysis tools like [Bandit](https://bandit.readthedocs.io/en/latest/).

This tool is designed for developers, security enthusiasts, and DevSecOps teams to quickly assess Python code for security risks. The app features a minimalistic **Python Flask backend** and a simple **HTML frontend** for ease of use.

---

## 🚀 Features

- ✅ Upload Python code files via the web interface
- ✅ Perform **static code analysis** with Bandit
- ✅ Get instant **JSON vulnerability reports**
- ✅ Easy CI/CD and API integration
- ✅ Minimal dependencies & Docker-ready
- ⚙️ Easily extendable to other languages (e.g., `semgrep`)

---

## 🛠️ Tech Stack

- **Backend:** Python 3 + Flask
- **Frontend:** HTML5
- **Security Analysis Tool:** Bandit
- **Containerization:** Docker (optional)

---

## 📦 Installation

### 1. Clone the Repository

git clone https://github.com/yourusername/SAST-Tool.git

cd SAST-Tool

### 2. Install Dependencies

pip install flask bandit

---

## 🔧 Usage

### Start the Flask Server:

python app.py

### Access the Web Interface:

http://localhost:5000

Use the file upload form to submit your Python file for scanning. The vulnerability report will be generated in JSON format.

---

## 🐳 Docker (Optional)

### Build and Run:

docker build -t SAST-Tool .
docker run -p 5000:5000 SAST-Tool

---

## 📝 API Endpoint

| Method | Endpoint | Description                                       |
| ------ | -------- | ------------------------------------------------- |
| POST   | `/scan`  | Upload Python file and receive Bandit JSON report |

#### Example:

curl -X POST -F "file=@example.py" http://localhost:5000/scan

---

## ⚠️ Legal Notice

> This tool is intended **only for scanning code you have permission to audit**.
> Unauthorized scanning of third-party code or systems is **strictly prohibited**.
> Use responsibly and ethically, in line with your organization's policies and applicable laws.

---

## 🤝 Contributing

1. Fork this repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to your branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---
