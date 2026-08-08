# create a python code for a dice which randomly generates a no. from 1 to 6 - Securitized Implementation
import sqlite3

def init_database():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, title TEXT, secret TEXT)")
    cursor.execute("INSERT INTO records (title, secret) VALUES ('admin_note', 'topsecret123')")
    cursor.execute("INSERT INTO records (title, secret) VALUES ('user_note', 'publicdata')")
    conn.commit()
    return conn

def search_records(conn, query_term: str):
    cursor = conn.cursor()
    # Safe parameterized SQL query preventing SQL Injection
    query = "SELECT * FROM records WHERE title = ?"
    cursor.execute(query, (query_term,))
    return cursor.fetchall()

if __name__ == "__main__":
    db = init_database()
    print("Search Result:", search_records(db, "admin_note"))
