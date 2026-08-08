import os
import sys
import json
import subprocess

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

class DevSecOpsSwarm:
    def __init__(self, max_loops=3):
        self.max_loops = max_loops
        self.current_loop = 0

    def run_coder_agent(self, initial=True):
        print("\n==========================================")
        print("[AGENT 1] CODER AGENT (Developer)")
        print("==========================================")
        if initial:
            print("[Coder] Writing initial Python SQLite authentication in app.py...")
            code = '''import sqlite3

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
    # Initial implementation using raw string formatting (vulnerable to SQL injection)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user is not None

if __name__ == "__main__":
    conn = init_db()
    print("Admin Auth:", authenticate_user(conn, "admin", "secret123"))
'''
            with open("app.py", "w") as f:
                f.write(code)
            print("[Coder] Written app.py successfully.")
        else:
            print("[Coder] Refactoring app.py based on QA test failures...")

    def run_tester_agent(self):
        print("\n==========================================")
        print("[AGENT 2] TESTER AGENT (QA & Verification)")
        print("==========================================")
        test_code = '''import pytest
from app import init_db, authenticate_user

@pytest.fixture
def db_conn():
    return init_db()

def test_successful_login(db_conn):
    assert authenticate_user(db_conn, "admin", "secret123") is True

def test_failed_login_wrong_password(db_conn):
    assert authenticate_user(db_conn, "admin", "wrongpass") is False

def test_failed_login_nonexistent_user(db_conn):
    assert authenticate_user(db_conn, "ghost", "secret123") is False
'''
        with open("test_app.py", "w") as f:
            f.write(test_code)
        
        print("[Tester] Executing unit tests via pytest...")
        code, out, err = run_cmd(f"{sys.executable} -m pytest test_app.py -v")
        print(out)
        if code == 0:
            print("[Tester] SUCCESS: ALL UNIT TESTS PASSED!")
            return True
        else:
            print("[Tester] FAILURE: UNIT TESTS FAILED!")
            print(err)
            return False

    def run_hacker_agent(self):
        print("\n==========================================")
        print("[AGENT 3] HACKER AGENT (Red Team / Security)")
        print("==========================================")
        print("[Hacker] Running static security analysis with Bandit...")
        
        run_cmd(f"{sys.executable} -m bandit -r app.py -f json -o security_report.json")
        
        vulnerabilities = []
        if os.path.exists("security_report.json"):
            with open("security_report.json", "r") as f:
                try:
                    data = json.load(f)
                    results = data.get("results", [])
                    for item in results:
                        vulnerabilities.append({
                            "issue_text": item.get("issue_text"),
                            "severity": item.get("issue_severity"),
                            "confidence": item.get("issue_confidence"),
                            "line": item.get("line_number")
                        })
                except Exception:
                    pass

        with open("app.py", "r") as f:
            content = f.read()

        manual_sql_inj = False
        if "f\"SELECT" in content or "f'SELECT" in content or ("SELECT" in content and "%" in content):
            manual_sql_inj = True

        if vulnerabilities or manual_sql_inj:
            print("[Hacker] VULNERABILITY DETECTED!")
            report = "# Vulnerability Report\n\n"
            report += "## Critical Findings\n"
            if manual_sql_inj:
                report += "- **SQL Injection Vulnerability**: Raw string formatting in SQL query inside `authenticate_user`.\n"
            for v in vulnerabilities:
                report += f"- **[{v['severity']}]** Line {v['line']}: {v['issue_text']}\n"
            
            with open("vulnerability_report.md", "w") as f:
                f.write(report)
            print("[Hacker] Generated vulnerability_report.md.")
            return False
        else:
            print("[Hacker] CODEBASE VERIFIED SECURE!")
            return True

    def run_patcher_agent(self):
        print("\n==========================================")
        print("[AGENT 4] PATCHER AGENT (AppSec Engineer)")
        print("==========================================")
        print("[Patcher] Reading vulnerability_report.md and patching app.py...")
        
        patched_code = '''import sqlite3

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
'''
        with open("app.py", "w") as f:
            f.write(patched_code)
        print("[Patcher] Applied parameterized query security fix to app.py.")

    def execute(self):
        print("Starting Autonomous DevSecOps Swarm Pipeline...")
        self.run_coder_agent(initial=True)
        
        while self.current_loop < self.max_loops:
            self.current_loop += 1
            print(f"\n--- SWARM LOOP ITERATION {self.current_loop}/{self.max_loops} ---")
            
            # Step 1: Tester Agent
            tests_passed = self.run_tester_agent()
            if not tests_passed:
                print("[Orchestrator] Tests failed. Routing back to Coder Agent...")
                self.run_coder_agent(initial=False)
                continue
            
            # Step 2: Hacker Agent
            is_secure = self.run_hacker_agent()
            if is_secure:
                print("\n[Orchestrator] PIPELINE COMPLETE: Code is functionally tested & verified secure!")
                return True
            
            # Step 3: Patcher Agent
            print("[Orchestrator] Vulnerabilities found. Routing to Patcher Agent...")
            self.run_patcher_agent()
            
            # Loop re-verifies via Tester -> Hacker

        print("\n[Orchestrator] Max loop limit reached.")
        return False

if __name__ == "__main__":
    swarm = DevSecOpsSwarm(max_loops=3)
    swarm.execute()
