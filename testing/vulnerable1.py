PASSWORD = "supersecretpassword123"
API_KEY = "1a2b3c4d5e6f7g8h9i0j"
import base64

def weak_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def weak_decrypt(encoded):
    return base64.b64decode(encoded.encode()).decode()


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # execute_query(query) - This would be vulnerable to SQL injection
    return query


import os

def run_command(user_input):
    os.system(f"echo {user_input}") 

import pickle

def load_object(serialized_data):
    return pickle.loads(serialized_data)  


import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  


import random

def generate_token():
    return ''.join(random.choice('0123456789ABCDEF') for i in range(16))


def calculate(expression):
    return eval(expression)  # Dangerous eval usage


def redirect_user(url):
    # Redirects without validation
    return f"Redirecting to {url}"

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()

if __name__ == "__main__":
    print("This file contains intentional security vulnerabilities for testing purposes.")
    print("Do not use this code in production environments.")