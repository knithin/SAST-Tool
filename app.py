from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan_code():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Run Bandit for Python code scanning
    result = subprocess.run(['bandit', '-r', filepath, '-f', 'json'],
                            capture_output=True, text=True)
    return jsonify({'report': result.stdout})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
