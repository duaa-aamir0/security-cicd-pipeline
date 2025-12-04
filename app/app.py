from flask import Flask, request, jsonify, render_template_string, make_response
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

# Set security headers globally
@app.after_request
def set_security_headers(response):
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Basic CSP – restrict to self
    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Enable XSS Protection (legacy but harmless)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # If cookies used, force secure & HttpOnly (example)
    response.headers["Set-Cookie"] = "sessionid=demo; HttpOnly; Secure; SameSite=Strict"

    return response


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
        return jsonify({"echo": data}), 200
    return jsonify({"error": "No data provided"}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
