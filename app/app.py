# a minimal functional flask app for security scanning demo

from flask import Flask, request, jsonify, render_template_string
import os

app = Flask(__name__)

# HTML template
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security CI/CD Pipeline</title>
</head>
<body>
    <h1>Security CI/CD Pipeline</h1>
    <p>This is a simple Flask application used to demonstrate security scanning.</p>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "security-pipeline"}), 200

@app.route('/api/echo', methods=['POST'])
def echo():
    data = request.get_json()
    if data:
        return jsonify({"echo": data}), 200     # returns posted data
    return jsonify({"error": "No data provided"}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)