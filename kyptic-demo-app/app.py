import os
import sqlite3
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Kyptic Demo Vulnerable App")

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SECRET_API_TOKEN = "super_secret_token_12345"

@app.get("/")
def read_root():
    return {"status": "running", "app": "Kyptic Demo Vulnerable App"}

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id, "key": AWS_ACCESS_KEY_ID}

@app.get("/api/search")
def search_users(q: str = ""):
    """Vulnerable SQL injection endpoint for demonstration."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'administrator'), ('alice', 'user'), ('bob', 'user')")
    query = f"SELECT id, username, role FROM users WHERE username = '{q}'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
    except sqlite3.OperationalError as e:
        return JSONResponse(status_code=500, content={"error": f"sqlite3.OperationalError: {str(e)}"})
