# Тестовый файл с уязвимостями
import hashlib
import os
import pickle

password = "secret123"
api_key = "sk-1234567890abcdef"
secret = "my_secret_token"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def run_command(cmd):
    os.system(cmd)

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def hash_password_sha1(pwd):
    return hashlib.sha1(pwd.encode()).hexdigest()

def execute_code(code):
    return eval(code)

def execute_dynamic(code):
    exec(code)

result = eval("1 + 1")
breakpoint()