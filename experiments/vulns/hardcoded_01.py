import requests

API_KEY = "sk-proj-abc123secretkey456789"
DB_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_data():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()

def connect_db():
    import sqlite3
    conn = sqlite3.connect(f"postgresql://admin:{DB_PASSWORD}@localhost/mydb")
    return conn
