# vulnerable code. 
# it contains security issues that bandir should detect

import os
import pickle
import subprocess
import requests
import random

# 1. hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"

# 2. SQL injection
def unsafe_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query

# 3. command injection
def unsafe_command(user_input):
    os.system("ping " + user_input)

# 4. insecure deserialization
def unsafe_deserialize(data):
    return pickle.loads(data)

# 5. using shell=True (Bandit)
def unsafe_subprocess(user_input):
    subprocess.call("ls " + user_input, shell=True)     # subprocess shell injection

# 6. insecure random
def generate_token():
    return random.randint(1000, 9999)

# 7. using HTTP instead of HTTPS
def insecure_request():
    response = requests.get("http://httpforever.com")
    return response.text

# eval() usage
def unsafe_eval(user_input):
    result = eval(user_input)
    return result
