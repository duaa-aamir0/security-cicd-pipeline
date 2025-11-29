from flask import Flask, request, jsonify
import os
import pickle
import subprocess
import requests
import random

app = Flask(__name__)

# 1. Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"


# 2. SQL Injection vulnerability
@app.route("/query")
def unsafe_query():
    user_input = request.args.get("name", "")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return jsonify({"query_executed": query})


# 3. Command Injection
@app.route("/ping")
def unsafe_command():
    target = request.args.get("host", "")
    os.system("ping " + target)
    return jsonify({"status": "command executed", "host": target})


# 4. Insecure deserialization
@app.route("/deserialize", methods=["POST"])
def unsafe_deserialize():
    data = request.data
    try:
        obj = pickle.loads(data)
        return jsonify({"deserialized": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# 5. Subprocess with shell=True (command injection)
@app.route("/subprocess")
def unsafe_subprocess():
    user_input = request.args.get("path", "")
    subprocess.call("ls " + user_input, shell=True)
    return jsonify({"status": "subprocess executed", "path": user_input})


# 6. Insecure random token generation
@app.route("/token")
def generate_token():
    token = random.randint(1000, 9999)
    return jsonify({"generated_token": token})


# 7. Insecure HTTP request (no HTTPS)
@app.route("/insecure-request")
def insecure_request():
    response = requests.get("http://httpforever.com")
    return jsonify({"response": response.text})


# 8. eval() RCE vulnerability
@app.route("/eval")
def unsafe_eval():
    user_input = request.args.get("code", "")
    result = eval(user_input)  # VERY unsafe
    return jsonify({"result": result})


@app.route("/")
def index():
    return """
        <h1>Vulnerable Flask App Running</h1>
        <ul>
            <li>/query?name=xyz</li>
            <li>/ping?host=127.0.0.1</li>
            <li>/deserialize (POST raw data)</li>
            <li>/subprocess?path=/</li>
            <li>/token</li>
            <li>/insecure-request</li>
            <li>/eval?code=2*10</li>
        </ul>
    """


if __name__ == "__main__":
    # Important for Docker + ZAP scanning
    app.run(host="0.0.0.0", port=5000)
