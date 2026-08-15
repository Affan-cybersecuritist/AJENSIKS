import sqlite3

def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'secret123')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('alice', 'password456')")
    conn.commit()
    return conn

def authenticate_user(conn, username, password):
    cursor = conn.cursor()
    # Parameterized query to prevent SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    return user is not None

if __name__ == "__main__":
    conn = init_db()
    print("Admin Auth:", authenticate_user(conn, "admin", "secret123"))
