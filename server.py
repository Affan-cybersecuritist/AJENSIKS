import os
import sys
import json
import asyncio
import subprocess
import requests
import io
import re
import zipfile
import time
import shutil
import uuid
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv

load_dotenv(".env.local")
load_dotenv()

app = FastAPI(title="DevSecOps AI Swarm")

static_dir = os.path.join(os.path.dirname(__file__), "static")
workspaces_dir = os.path.join(os.path.dirname(__file__), "user_workspaces")
os.makedirs(static_dir, exist_ok=True)
os.makedirs(workspaces_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.middleware("http")
async def no_cache_static_assets(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

active_websockets = []
active_processes = {}   # process_id -> asyncio.subprocess.Process
workflow_states = {}    # (user_id, session_id) -> {"max_loops", "current_loop", "is_running", "selected_model"}
                         # Per-run state — NOT global — so concurrent runs (different tabs/users,
                         # or a test run happening alongside a real one) never corrupt each other's
                         # loop counters or running flags.

def get_workflow_state(user_id: str, session_id) -> dict:
    key = (user_id, session_id)
    if key not in workflow_states:
        workflow_states[key] = {"max_loops": 10, "current_loop": 0, "is_running": False, "selected_model": None}
    return workflow_states[key]

API_KEY_MODEL = "Gemini Cloud API (Key Enabled)"
CLAUDE_API_KEY_MODEL = "Claude API (Key Enabled)"
OPENROUTER_API_KEY_MODEL = "OpenRouter API (Key Enabled)"
PROVIDED_API_KEY = os.environ.get("GEMINI_API_KEY", "")
PROVIDED_ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
PROVIDED_OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

def is_api_key_model(model_name: str) -> bool:
    if not model_name: return False
    m = model_name.lower()
    return m == API_KEY_MODEL.lower() or m == CLAUDE_API_KEY_MODEL.lower() or m == OPENROUTER_API_KEY_MODEL.lower()

# ── Supabase JWT verification ──────────────────────────────────────────────────
# Every endpoint below used to take the tenant's user_id straight from the request body or
# URL and read/write that workspace directly. Nothing proved the caller owned it, so any
# client could read another tenant's generated code, security reports and session history —
# or overwrite them — just by changing the id it sent. The UI's sign-in gate is client-side
# only and does nothing to stop a direct HTTP request.
#
# Tokens are now verified cryptographically and the tenant id is taken from the *verified*
# claims; whatever the client puts in the body is ignored.
SUPABASE_URL = (os.environ.get("NEXT_PUBLIC_SUPABASE_URL") or os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_ANON_KEY") or ""
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
# Opt-out for local development only. Leaving this on in a deployed environment disables
# tenant isolation completely, so it defaults to OFF and must be set explicitly.
AUTH_DISABLED = os.environ.get("DEVSECOPS_DISABLE_AUTH", "").lower() in ("1", "true", "yes")

_jwks_client = None
_jwks_client_failed = False

def _get_jwks_client():
    """Supabase signs user tokens with a rotating asymmetric key published at the project's
    JWKS endpoint. PyJWKClient caches keys and refetches on unknown `kid`, so rotation is
    handled without a restart."""
    global _jwks_client, _jwks_client_failed
    if _jwks_client is not None or _jwks_client_failed or not SUPABASE_URL:
        return _jwks_client
    try:
        from jwt import PyJWKClient
        _jwks_client = PyJWKClient(f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json", cache_keys=True)
    except Exception as e:
        _jwks_client_failed = True
        print(f"[auth] JWKS client unavailable ({e}); will fall back to shared-secret / API verification.")
    return _jwks_client

_token_cache = {}  # token -> (user_id, expires_at_monotonic)

def _verify_jwt_locally(token: str):
    """Returns the subject claim, or None if the token can't be verified offline."""
    import jwt as _jwt
    try:
        header = _jwt.get_unverified_header(token)
    except Exception:
        return None
    alg = header.get("alg", "")

    if alg.startswith(("ES", "RS")):
        client = _get_jwks_client()
        if client is None:
            return None
        try:
            key = client.get_signing_key_from_jwt(token).key
            claims = _jwt.decode(token, key, algorithms=["ES256", "RS256"], audience="authenticated",
                                 options={"verify_exp": True})
            return claims.get("sub")
        except Exception:
            return None

    if alg == "HS256" and SUPABASE_JWT_SECRET:
        try:
            claims = _jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated",
                                 options={"verify_exp": True})
            return claims.get("sub")
        except Exception:
            return None
    return None

async def _verify_jwt_via_supabase(token: str):
    """Last-resort check for projects whose tokens can't be verified offline (legacy HS256
    with no JWT secret configured). Asks Supabase to validate the token for us."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return None
    try:
        r = await asyncio.to_thread(
            requests.get, f"{SUPABASE_URL}/auth/v1/user",
            headers={"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            return (r.json() or {}).get("id")
    except Exception as e:
        print(f"[auth] Supabase user lookup failed: {e}")
    return None

async def resolve_user_id(token: str):
    """Verified Supabase user id for a bearer token, or None."""
    if not token:
        return None
    now = time.monotonic()
    cached = _token_cache.get(token)
    if cached and cached[1] > now:
        return cached[0]

    user_id = _verify_jwt_locally(token)
    if user_id is None:
        user_id = await _verify_jwt_via_supabase(token)
    if user_id:
        # Short TTL: a signed-out or revoked token stops working quickly, while a burst of
        # requests during one pipeline run doesn't re-verify on every call.
        _token_cache[token] = (user_id, now + 60)
        if len(_token_cache) > 512:
            for k, (_, exp) in list(_token_cache.items()):
                if exp <= now:
                    _token_cache.pop(k, None)
    return user_id

def _bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()

async def current_user(authorization: Optional[str] = Header(None)) -> str:
    """FastAPI dependency: the authenticated tenant id. 401s when the token is missing or bad."""
    if AUTH_DISABLED:
        return "default_user"
    user_id = await resolve_user_id(_bearer_token(authorization))
    if not user_id:
        raise HTTPException(status_code=401, detail="Sign-in required: missing or invalid access token.")
    return user_id

def assert_owns(requested_user_id: Optional[str], auth_user_id: str) -> str:
    """Rejects a request whose URL/body names a different tenant than the verified token.
    Always returns the id to actually use — the verified one."""
    if AUTH_DISABLED:
        return requested_user_id or auth_user_id
    if requested_user_id and requested_user_id != auth_user_id:
        raise HTTPException(status_code=403, detail="You do not have access to this workspace.")
    return auth_user_id

async def broadcast(data: dict):
    """Sends an event only to sockets belonging to the tenant it concerns.

    This used to push every event to every connected socket and rely on the browser to
    discard other people's — meaning one user's generated source code, terminal output and
    security findings were transmitted to every other signed-in client, where anyone could
    read them straight off the WebSocket. Filtering now happens here, before the data leaves
    the server."""
    target_user = data.get("user_id")
    for ws in list(active_websockets):
        # Set when the socket authenticates; None for a socket that never identified itself.
        ws_user = getattr(ws, "_devsecops_user_id", None)
        if target_user is not None and ws_user is not None and ws_user != target_user:
            continue
        if target_user is not None and ws_user is None and not AUTH_DISABLED:
            continue  # unauthenticated socket never receives tenant-scoped data
        try:
            await ws.send_json(data)
        except Exception:
            if ws in active_websockets:
                active_websockets.remove(ws)

async def run_cmd(cmd, cwd=None, timeout=120):
    """Every build/test command the pipeline shells out to runs through here.

    This had NO timeout, which meant a generated test that reads stdin blocked forever and
    took the whole run with it — observed with a Java app whose "core" method took a Scanner
    and called nextLine() inside, so JUnit sat waiting on input that never came. stdin is also
    closed (DEVNULL) so such a read fails fast instead of waiting on a terminal that isn't
    there; the timeout is the backstop for anything that still spins."""
    try:
        res = await asyncio.to_thread(
            subprocess.run, cmd, shell=True, capture_output=True, text=True, cwd=cwd,
            timeout=timeout, stdin=subprocess.DEVNULL)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return 124, out, f"{err}\n[TIMEOUT] Command exceeded {timeout}s and was terminated. " \
                         f"A test that waits on input will do this — tests must never read stdin."

class PromptRequest(BaseModel):
    prompt: str
    max_loops: int = 10
    selected_model: Optional[str] = None
    user_id: str = "default_user"
    session_id: Optional[str] = None
    api_key: Optional[str] = None
    language: str = "python"

class CustomCodeRequest(BaseModel):
    code: str
    user_id: str = "default_user"
    session_id: Optional[str] = None
    filename: str = "generated_app.py"

class RunCodeRequest(BaseModel):
    code: str
    user_id: str = "default_user"
    session_id: Optional[str] = None
    selected_model: Optional[str] = None
    max_attempts: int = 2
    language: str = "python"

class RunInteractiveRequest(BaseModel):
    code: str
    process_id: str
    user_id: str = "default_user"
    session_id: Optional[str] = None
    language: str = "python"

class SendInputRequest(BaseModel):
    process_id: str
    text: str
    user_id: str = "default_user"
    session_id: Optional[str] = None

class CreateSessionRequest(BaseModel):
    user_id: str = "default_user"
    title: str = "New Program Workspace"

class RenameSessionRequest(BaseModel):
    user_id: str = "default_user"
    session_id: str
    new_title: str

class ExtendRequest(BaseModel):
    user_id: str = "default_user"
    session_id: Optional[str] = None

NO_CACHE_HEADERS = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}

def secure_join(base: str, *paths: str) -> str:
    final_path = os.path.abspath(os.path.join(base, *(str(p) for p in paths if p)))
    if not final_path.startswith(os.path.abspath(base)):
        raise ValueError("Path traversal detected")
    return final_path

def detect_session_app_files(session_dir: str):
    """Sessions can be Python, C++, or Java — the generated app/test filenames differ by
    extension. Several endpoints used to hardcode the Python names, so reloading or
    exporting a C++/Java session silently came back empty (code, tests, and the security
    report all blank) even though the pipeline had actually produced and saved them.
    Look up which language this session actually has on disk instead of assuming Python."""
    for ext in ("py", "cpp", "java"):
        candidate = os.path.join(session_dir, f"generated_app.{ext}")
        if os.path.exists(candidate):
            return f"generated_app.{ext}", f"test_generated_app.{ext}"
    return "generated_app.py", "test_generated_app.py"

@app.get("/")
async def get_index():
    return FileResponse(os.path.join(static_dir, "index.html"), headers=NO_CACHE_HEADERS)

@app.get("/coderunner")
async def get_code_runner():
    return FileResponse(os.path.join(static_dir, "code_runner.html"))

@app.get("/api/models")
async def list_models():
    models = [
        API_KEY_MODEL
    ]
    if PROVIDED_ANTHROPIC_API_KEY:
        models.append(CLAUDE_API_KEY_MODEL)
    if PROVIDED_OPENROUTER_API_KEY:
        models.append(OPENROUTER_API_KEY_MODEL)
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            m_list = r.json().get("models", [])
            for m in m_list:
                name = m.get("name")
                if name and name not in models:
                    models.append(name)
    except Exception:
        pass
    
    models.append("Auto-Detect / Dynamic Synthesizer")
    return {"models": models}

@app.get("/api/sessions/{user_id}")
async def list_user_sessions(user_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    user_sessions_dir = secure_join(workspaces_dir, user_id, "sessions")
    os.makedirs(user_sessions_dir, exist_ok=True)
    index_file = os.path.join(user_sessions_dir, "sessions_index.json")
    if os.path.exists(index_file):
        try:
            with open(index_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

@app.post("/api/sessions/create")
async def create_user_session(req: CreateSessionRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    user_sessions_dir = secure_join(workspaces_dir, req.user_id, "sessions")
    os.makedirs(user_sessions_dir, exist_ok=True)
    index_file = os.path.join(user_sessions_dir, "sessions_index.json")
    
    session_id = f"session_{int(time.time() * 1000)}"
    session_dir = os.path.join(user_sessions_dir, session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    new_session = {
        "id": session_id,
        "title": req.title,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    sessions = []
    if os.path.exists(index_file):
        try:
            with open(index_file, "r") as f:
                sessions = json.load(f)
        except Exception:
            pass
    
    sessions.insert(0, new_session)
    with open(index_file, "w") as f:
        json.dump(sessions, f, indent=2)
        
    return new_session

@app.post("/api/sessions/rename")
async def rename_user_session(req: RenameSessionRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    user_sessions_dir = secure_join(workspaces_dir, req.user_id, "sessions")
    index_file = os.path.join(user_sessions_dir, "sessions_index.json")
    if os.path.exists(index_file):
        try:
            with open(index_file, "r") as f:
                sessions = json.load(f)
            for s in sessions:
                if s["id"] == req.session_id:
                    s["title"] = req.new_title.strip()
                    break
            with open(index_file, "w") as f:
                json.dump(sessions, f, indent=2)
            return {"status": "renamed", "session_id": req.session_id, "new_title": req.new_title}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "error", "message": "Sessions index not found"}

@app.get("/api/sessions/{user_id}/{session_id}")
async def get_session_details(user_id: str, session_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    session_dir = secure_join(workspaces_dir, user_id, "sessions", session_id)
    if not os.path.exists(session_dir):
        session_dir = secure_join(workspaces_dir, user_id)
    
    res = {
        "app_code": "",
        "test_code": "",
        "vulnerability_report": "",
        "diff_before": "",
        "diff_after": "",
        "language": "python"
    }

    app_filename, test_filename = detect_session_app_files(session_dir)
    session_ext = os.path.splitext(app_filename)[1].lstrip(".")
    res["language"] = next((lang for lang, cfg in LANGUAGE_CONFIG.items() if cfg["ext"] == session_ext), "python")
    app_p = os.path.join(session_dir, app_filename)
    test_p = os.path.join(session_dir, test_filename)
    vuln_p = os.path.join(session_dir, "vulnerability_report.md")
    diff_p = os.path.join(session_dir, "patch_diff.json")

    if os.path.exists(app_p):
        with open(app_p, "r", encoding="utf-8") as f: res["app_code"] = f.read()
    if os.path.exists(test_p):
        with open(test_p, "r", encoding="utf-8") as f: res["test_code"] = f.read()
    if os.path.exists(vuln_p):
        with open(vuln_p, "r") as f: res["vulnerability_report"] = f.read()
    if os.path.exists(diff_p):
        try:
            with open(diff_p, "r") as f:
                diff_data = json.load(f)
            res["diff_before"] = diff_data.get("before", "")
            res["diff_after"] = diff_data.get("after", "")
        except Exception:
            pass

    return res

@app.delete("/api/sessions/{user_id}/{session_id}")
async def delete_user_session(user_id: str, session_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    user_sessions_dir = secure_join(workspaces_dir, user_id, "sessions")
    index_file = os.path.join(user_sessions_dir, "sessions_index.json")
    session_dir = os.path.join(user_sessions_dir, session_id)
    
    if os.path.exists(session_dir):
        shutil.rmtree(session_dir, ignore_errors=True)
        
    if os.path.exists(index_file):
        try:
            with open(index_file, "r") as f:
                sessions = json.load(f)
            sessions = [s for s in sessions if s["id"] != session_id]
            with open(index_file, "w") as f:
                json.dump(sessions, f, indent=2)
        except Exception:
            pass
            
    return {"status": "deleted", "session_id": session_id}

def parse_ast_tree(source_code: str):
    import ast

    def walk_node(node):
        node_name = type(node).__name__
        details = ""
        is_dangerous = False

        if isinstance(node, ast.FunctionDef):
            details = f"def {node.name}()"
        elif isinstance(node, ast.ClassDef):
            details = f"class {node.name}"
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            details = f"Call: {func_name}()"
            if func_name in ["eval", "exec", "system"]:
                is_dangerous = True
        elif isinstance(node, ast.Import):
            names = [n.name for n in node.names]
            details = f"import {', '.join(names)}"
        elif isinstance(node, ast.ImportFrom):
            details = f"from {node.module} import ..."
        elif isinstance(node, ast.BinOp):
            details = f"BinOp ({type(node.op).__name__})"

        children = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.ClassDef, ast.Call, ast.Import, ast.ImportFrom, ast.Expr, ast.Assign, ast.Return, ast.If, ast.Try)):
                children.append(walk_node(child))

        return {
            "node_type": node_name,
            "details": details or node_name,
            "is_dangerous": is_dangerous,
            "children": children[:10]
        }

    try:
        tree = ast.parse(source_code)
        return walk_node(tree)
    except Exception as e:
        return {"node_type": "Module", "details": f"AST Parse Notice: {str(e)}", "is_dangerous": False, "children": []}

@app.get("/api/ast-tree/{user_id}/{session_id}")
async def get_ast_tree(user_id: str, session_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    session_dir = secure_join(workspaces_dir, user_id, "sessions", session_id)
    if not os.path.exists(session_dir):
        session_dir = secure_join(workspaces_dir, user_id)
    
    app_p = os.path.join(session_dir, "generated_app.py")
    code = ""
    if os.path.exists(app_p):
        with open(app_p, "r") as f:
            code = f.read()
    
    tree_data = parse_ast_tree(code or "pass")
    return tree_data

@app.get("/api/swarm/export-pdf/{user_id}/{session_id}")
async def export_pdf_report(user_id: str, session_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    session_dir = secure_join(workspaces_dir, user_id, "sessions", session_id)
    if not os.path.exists(session_dir):
        session_dir = secure_join(workspaces_dir, user_id)

    session_data = {
        "prompt": "DevSecOps Swarm Code Synthesis",
        "vulnerability_report": "No swarm run has completed for this session yet."
    }

    vuln_p = os.path.join(session_dir, "vulnerability_report.md")
    if os.path.exists(vuln_p):
        with open(vuln_p, "r") as f:
            session_data["vulnerability_report"] = f.read()

    # The certificate used to unconditionally claim "GRADE A+ / 100% verified / zero
    # vulnerabilities" no matter what actually happened — including when the report body
    # itself said NOT COMPLETED or listed a critical finding. Derive the real outcome from
    # the report instead so the certificate can't contradict the audit it's certifying.
    report_text = session_data["vulnerability_report"]
    if "Result: VERIFIED SECURE" in report_text:
        grade_label, grade_color = "GRADE A+ (Securitized &amp; Verified)", "#15803d"
        qa_status, sast_status, compliance_status = "100% Test Suite Verified", "Zero Unhandled Vulnerabilities", "COMPLIANT [PASS]"
    elif "Result: NOT COMPLETED" in report_text:
        grade_label, grade_color = "GRADE INCOMPLETE (Manual Review Required)", "#b45309"
        qa_status, sast_status, compliance_status = "Run Did Not Converge", "Audit Stage Not Reached", "PENDING [INCOMPLETE]"
    elif "Critical Finding" in report_text:
        grade_label, grade_color = "GRADE F (Unresolved Vulnerabilities)", "#b91c1c"
        qa_status, sast_status, compliance_status = "Tests Passed", "Vulnerabilities Detected", "NON-COMPLIANT [FAIL]"
    else:
        grade_label, grade_color = "GRADE N/A (No Run Recorded)", "#6b5b63"
        qa_status, sast_status, compliance_status = "Not Yet Run", "Not Yet Run", "NOT AUDITED"

    app_filename, _ = detect_session_app_files(session_dir)
    session_ext = os.path.splitext(app_filename)[1].lstrip(".")
    pdf_language = next((lang for lang, cfg in LANGUAGE_CONFIG.items() if cfg["ext"] == session_ext), "python")
    test_tool = TEST_TOOL_NAME.get(pdf_language, "Pytest")
    sast_tool = SAST_TOOL_NAME.get(pdf_language, "Bandit")

    index_file = secure_join(workspaces_dir, user_id, "sessions", "sessions_index.json")
    if os.path.exists(index_file):
        try:
            with open(index_file, "r") as f:
                sessions = json.load(f)
            for s in sessions:
                if s["id"] == session_id:
                    session_data["prompt"] = s["title"]
                    break
        except Exception:
            pass

    pdf_buffer = io.BytesIO()
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, leading=22, textColor=colors.HexColor('#800f2f'))
        subtitle_style = ParagraphStyle('DocSubTitle', parent=styles['Normal'], fontName='Helvetica', fontSize=9.5, leading=13, textColor=colors.HexColor('#6b5b63'))
        heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=colors.HexColor('#d90429'), spaceBefore=10, spaceAfter=4)
        body_style = ParagraphStyle('BodyTextCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=12, textColor=colors.HexColor('#2b1b22'))

        elements = []
        elements.append(Paragraph("DevSecOps AI Swarm Executive Security Certificate", title_style))
        elements.append(Paragraph(f"Autonomous Application Security Audit & Remediation Certificate | User Tenant: {user_id[:8]}...", subtitle_style))
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#d90429'), spaceAfter=12))

        meta_data = [
            [Paragraph("<b>Target Requirement:</b>", body_style), Paragraph(session_data.get('prompt', 'DevSecOps Code Synthesis'), body_style)],
            [Paragraph("<b>Session Identifier:</b>", body_style), Paragraph(session_id, body_style)],
            [Paragraph("<b>Security Compliance Grade:</b>", body_style), Paragraph(f"<font color='{grade_color}'><b>{grade_label}</b></font>", body_style)],
            [Paragraph(f"<b>{test_tool} QA Pass Rate:</b>", body_style), Paragraph(f"<font color='{grade_color}'><b>{qa_status}</b></font>", body_style)],
            [Paragraph(f"<b>{sast_tool} SAST Rating:</b>", body_style), Paragraph(f"<font color='{grade_color}'><b>{sast_status}</b></font>", body_style)]
        ]
        t = Table(meta_data, colWidths=[150, 390])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fff0f3')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d90429')),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Enterprise Regulatory Compliance Framework Mapping", heading_style))
        compliance_cell = f"<font color='{grade_color}'><b>{compliance_status}</b></font>"
        comp_matrix = [
            [Paragraph("<b>Compliance Standard</b>", body_style), Paragraph("<b>Control Identifier</b>", body_style), Paragraph("<b>Audit Status</b>", body_style)],
            [Paragraph("OWASP Top 10:2021", body_style), Paragraph("A03:2021 - Injection Flaws", body_style), Paragraph(compliance_cell, body_style)],
            [Paragraph("SOC 2 Type II", body_style), Paragraph("CC7.1 - Security Change Management", body_style), Paragraph(compliance_cell, body_style)],
            [Paragraph("ISO/IEC 27001:2022", body_style), Paragraph("A.12.6.1 - Technical Vulnerabilities", body_style), Paragraph(compliance_cell, body_style)],
            [Paragraph("NIST SP 800-53", body_style), Paragraph("SI-10 - Information Input Validation", body_style), Paragraph(compliance_cell, body_style)]
        ]
        t_comp = Table(comp_matrix, colWidths=[150, 230, 160])
        t_comp.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#800f2f')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('PADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ]))
        elements.append(t_comp)
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Remediation & Security Audit Verification Summary", heading_style))
        audit_lines = session_data.get('vulnerability_report', '').split('\n')
        for line in audit_lines[:15]:
            if line.strip():
                clean_l = line.replace('#', '').strip()
                elements.append(Paragraph(clean_l, body_style))
                elements.append(Spacer(1, 2))

        elements.append(Spacer(1, 12))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc'), spaceAfter=8))
        elements.append(Paragraph("<i>Report autonomously generated by DevSecOps AI Swarm Engine. Certified for Enterprise Deployment.</i>", subtitle_style))

        doc.build(elements)
    except Exception as e:
        pdf_buffer.write(f"PDF Generation Notice: {str(e)}".encode())

    pdf_buffer.seek(0)
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=devsecops_security_certificate_{session_id[:8]}.pdf"}
    )

@app.websocket("/ws/swarm")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    # Browsers can't set headers on a WebSocket handshake, so the client identifies itself by
    # sending {"type":"AUTH","token":"<access token>"} as its first message. Until that token
    # verifies, this socket receives no tenant-scoped events (see broadcast()).
    websocket._devsecops_user_id = "default_user" if AUTH_DISABLED else None
    active_websockets.append(websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if isinstance(msg, dict) and msg.get("type") == "AUTH":
                uid = await resolve_user_id((msg.get("token") or "").strip())
                websocket._devsecops_user_id = uid or ("default_user" if AUTH_DISABLED else None)
                await websocket.send_json({"type": "AUTH_RESULT", "ok": bool(uid or AUTH_DISABLED)})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

# Tried in order. gemini-flash-latest gives the best code quality but currently resolves to a
# model with a free-tier cap of only 20 requests PER DAY — a single swarm run spends 5-10 calls
# (coder + each tester fix + each patcher fix), so on the free tier that cap is exhausted after
# two or three runs and every later run died instantly on HTTP 429. The -lite models carry a much
# larger free-tier allowance, so fall back to one rather than failing the run outright.
GEMINI_MODEL_CHAIN = ["gemini-flash-latest", "gemini-flash-lite-latest"]

def _gemini_quota_hint(body_text: str) -> str:
    """Pull the human-useful part out of Google's quota error (which model, what limit, and how
    long to wait) instead of reporting a generic 'quota exhausted' that tells the user nothing."""
    try:
        err = json.loads(body_text).get("error", {})
        msg = err.get("message", "") or ""
    except Exception:
        return ""
    limit = re.search(r"limit:\s*(\d+)", msg)
    model = re.search(r"model:\s*([\w.\-]+)", msg)
    retry = re.search(r"retry in ([\d.]+)s", msg)
    bits = []
    if limit and model:
        bits.append(f"free-tier cap of {limit.group(1)} requests/day on {model.group(1)}")
    elif limit:
        bits.append(f"free-tier cap of {limit.group(1)} requests")
    if retry:
        bits.append(f"retry in ~{int(float(retry.group(1)))}s")
    return " — " + "; ".join(bits) if bits else ""

async def query_gemini_raw(full_text: str, api_key: str):
    if not api_key or not api_key.strip():
        return None, "No Gemini API Key provided! Please enter your API Key in the UI input box or set the GEMINI_API_KEY environment variable."
    payload = {
        "contents": [{
            "parts": [{
                "text": full_text
            }]
        }]
    }
    last_err = "Unknown API error"
    for idx, model_name in enumerate(GEMINI_MODEL_CHAIN):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key.strip()}"
        try:
            r = await asyncio.to_thread(requests.post, url, json=payload, timeout=60)
            if r.status_code == 200:
                res_json = r.json()
                candidates = res_json.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        text = parts[0].get("text", "")
                        return text.strip(), None
                last_err = f"{model_name}: API returned no candidates (possibly blocked by a safety filter)."
            elif r.status_code == 400:
                return None, "HTTP 400 Bad Request: Invalid API Key or malformed request parameters."
            elif r.status_code in (429, 503):
                last_err = f"HTTP {r.status_code} on {model_name}{_gemini_quota_hint(r.text)}"
                if idx + 1 < len(GEMINI_MODEL_CHAIN):
                    continue  # quota/overload on this model — try the next one in the chain
            elif r.status_code == 404:
                last_err = f"HTTP 404: model {model_name} is not available to this API key."
                if idx + 1 < len(GEMINI_MODEL_CHAIN):
                    continue
            else:
                last_err = f"HTTP {r.status_code}: {r.text[:150]}"
        except Exception as e:
            last_err = str(e)
        break
    return None, last_err

async def query_gemini_api(prompt_text: str, api_key: str):
    return await query_gemini_raw(CODER_SYSTEM_PROMPT.format(prompt_text=prompt_text), api_key)

CODER_SYSTEM_PROMPT = "You are a Senior Security-Focused Python Architect. Build a highly professional, production-ready solution for this requirement: '{prompt_text}'. Use advanced object-oriented or functional patterns, strict type hinting, comprehensive docstrings, and robust error handling. Do NOT hardcode any test data or static execution blocks. You MUST build an interactive CLI loop (e.g. using 'while True:' and 'input()') so the user can interactively test all functionality. All core logic MUST live in standalone functions/classes (not just inline in the CLI loop) so it can be unit tested directly. You MUST also provide a pytest test file, delimited as $$FILE: test_generated_app.py$$ — this is NOT optional and the tests must NOT be trivial placeholders like 'assert True'; each test function must call your actual functions with representative inputs and assert the exact expected output/behavior (e.g. assert evaluate('5+5') == 10), covering the core functionality described in the requirement plus at least one edge case. If the solution requires multiple files (like models.py, utils.py, etc.), you MUST delimit them exactly like this:\n\n$$FILE: filename.py$$\n<file content>\n$$FILE: nextfile.py$$\n<file content>\n\nIf it's just one file, you must still use $$FILE: generated_app.py$$. Output ONLY the raw delimited code, absolutely no markdown wrappers like ```python."

async def query_claude_raw(full_text: str, api_key: str, model_name: str = "claude-sonnet-5"):
    if not api_key or not api_key.strip():
        return None, "No Anthropic API Key provided! Set the ANTHROPIC_API_KEY environment variable."
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key.strip(),
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    payload = {
        "model": model_name,
        "max_tokens": 8192,
        "messages": [
            {"role": "user", "content": full_text}
        ]
    }
    try:
        r = await asyncio.to_thread(requests.post, url, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            res_json = r.json()
            content_blocks = res_json.get("content", [])
            if content_blocks:
                text = content_blocks[0].get("text", "")
                return text.strip(), None
        elif r.status_code == 401:
            return None, "HTTP 401 Unauthorized: Invalid Anthropic API Key."
        elif r.status_code == 429:
            return None, "HTTP 429 Rate Limit Exceeded: Your Anthropic API Key quota has been temporarily exhausted."
        else:
            return None, f"HTTP {r.status_code}: {r.text[:150]}"
    except Exception as e:
        return None, str(e)
    return None, "Unknown API error"

async def query_claude_api(prompt_text: str, api_key: str, model_name: str = "claude-sonnet-5"):
    return await query_claude_raw(CODER_SYSTEM_PROMPT.format(prompt_text=prompt_text), api_key, model_name)

async def query_openrouter_raw(full_text: str, api_key: str, model_name: str = "deepseek/deepseek-chat"):
    if not api_key or not api_key.strip():
        return None, "No OpenRouter API Key provided! Enter your API key in the UI input box."
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "DevSecOps Swarm Platform",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "user",
                "content": full_text
            }
        ]
    }
    try:
        r = await asyncio.to_thread(requests.post, url, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            res_json = r.json()
            choices = res_json.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                return content.strip(), None
        elif r.status_code == 401:
            return None, "HTTP 401 Unauthorized: Invalid OpenRouter API Key."
        elif r.status_code == 429:
            return None, "HTTP 429 Rate Limit Exceeded on OpenRouter."
        else:
            return None, f"HTTP {r.status_code}: {r.text[:150]}"
    except Exception as e:
        return None, str(e)
    return None, "Unknown OpenRouter API error"

_OLLAMA_NUM_CTX_CACHE = {}

async def get_ollama_num_ctx(model_name: str) -> int:
    """Ollama silently defaults every request to a 2048-token context window unless the
    caller passes options.num_ctx explicitly — regardless of what the model itself
    actually supports. Our prompts (full app code + full test code + error output) can
    easily run 2000-4000+ tokens once a program grows past a trivial size, so at the
    default window the model was silently having its input/output truncated mid-token,
    producing garbled or incomplete code. That garbled code then fails tests, and the
    resulting fix_prompt is even bigger (it includes the previous broken code AND the
    error), so the truncation gets worse on every retry — this was the main driver of
    small local models looping for many iterations without converging.
    Look up the model's real trained context length via /api/show and request a window
    sized to it, capped at 8192 so machines without much RAM/VRAM don't get bogged down
    running a much larger KV cache than our prompts actually need."""
    if model_name in _OLLAMA_NUM_CTX_CACHE:
        return _OLLAMA_NUM_CTX_CACHE[model_name]
    ctx = 4096
    try:
        r = await asyncio.to_thread(requests.post, "http://localhost:11434/api/show", json={"name": model_name}, timeout=5)
        if r.status_code == 200:
            info = r.json().get("model_info", {})
            for key, val in info.items():
                if key.endswith(".context_length") and isinstance(val, int) and val > 0:
                    ctx = val
                    break
    except Exception:
        pass
    ctx = max(2048, min(ctx, 8192))
    _OLLAMA_NUM_CTX_CACHE[model_name] = ctx
    return ctx

async def query_ollama(prompt_text: str, model_name: str):
    try:
        num_ctx = await get_ollama_num_ctx(model_name)
        # Leaving num_predict uncapped (-1) let a model that fell into a repetitive/degenerate
        # generation ramble for as much of the context window as it had room for — measured in
        # testing at 4+ minutes for a single call once num_ctx was raised past 2048, which is
        # exactly the "taking hell lotta time" symptom this whole fix is meant to solve. Cap it
        # at half the context window: generous enough for the "under 120-150 lines" app+test
        # output our prompts ask for (a few thousand tokens, well under this cap), but bounded
        # so one bad generation can't eat the whole request budget.
        num_predict = max(1024, num_ctx // 2)
        r = await asyncio.to_thread(
            requests.post,
            "http://localhost:11434/api/generate",
            json={
                "model": model_name,
                "prompt": prompt_text,
                "stream": False,
                "options": {
                    "num_ctx": num_ctx,
                    "num_predict": num_predict,
                    "temperature": 0.3,      # code generation needs to be deterministic/correct, not
                                              # creative; Ollama's default (0.8) was a real contributor
                                              # to small models producing inconsistent, broken code.
                                              # Not pushed lower than this — very low temperature makes
                                              # a model MORE likely to get stuck greedily repeating the
                                              # same phrase once it starts one (observed live: a test
                                              # name degenerating into "..._and_description" x40+).
                    "repeat_penalty": 1.3,   # actively discourage repeating recent tokens, the other
                                              # half of the fix for that same repeated-phrase failure
                                              # mode (Ollama's own default of 1.1 wasn't enough).
                },
                "keep_alive": "10m",       # keep the model loaded across the coder/tester/hacker/
                                            # patcher stages of one pipeline run instead of risking
                                            # an unload-and-reload stall mid-run.
            },
            timeout=75   # Bounded well under the pipeline's 90s fix-loop time budget so a single
                         # slow/degenerate call can never on its own blow through the whole budget —
                         # real generations measured in testing finish in 10-70s, so this still gives
                         # legitimate calls comfortable room.
        )
        if r.status_code == 200:
            resp = r.json().get("response", "")
            return resp.strip()
        print(f"Ollama query error: HTTP {r.status_code}: {r.text[:300]}")
    except Exception as e:
        print("Ollama query error:", e)
    return None

# ── Multi-language pipeline support ─────────────────────────────────────────

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "tools")
JUNIT_JAR = os.path.join(TOOLS_DIR, "junit-platform-console-standalone.jar")
GSON_JAR = os.path.join(TOOLS_DIR, "gson.jar")
JAVA_CLASSPATH = f"{JUNIT_JAR};{GSON_JAR}"

LANGUAGE_CONFIG = {
    "python": {"display": "Python", "ext": "py"},
    "cpp": {"display": "C++", "ext": "cpp"},
    "java": {"display": "Java", "ext": "java"},
}

def lang_ext(language: str) -> str:
    return LANGUAGE_CONFIG.get(language, LANGUAGE_CONFIG["python"])["ext"]

def lang_display(language: str) -> str:
    return LANGUAGE_CONFIG.get(language, LANGUAGE_CONFIG["python"])["display"]

def fix_java_class_visibility(code: str) -> str:
    """Java requires a `public class X` to live in a file named X.java. Our pipeline always
    writes to generated_app.java, so any top-level `public class` (which LLMs add despite
    instructions not to) causes a guaranteed compile failure. Strip the modifier defensively
    rather than relying on prompt compliance."""
    import re
    return re.sub(r"\bpublic\s+class\s+", "class ", code)

def strip_code_fences(text: str) -> str:
    import re
    text = text.strip()
    # Prefer an actual fenced code block anywhere in the response (handles models that
    # add conversational preamble/postamble around the code instead of pure fenced output).
    fence_match = re.search(r"```[a-zA-Z0-9+]*\n(.*?)```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()
    # No fence found at all — strip any stray leading/trailing fence markers just in case.
    text = re.sub(r"^```[a-zA-Z0-9+]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.strip()

def sanitize_python_trailing_garbage(content: str) -> str:
    """Some local/small models ignore 'no explanations' and append a plain-English
    note after the code with no fence or delimiter separating it, which guarantees
    a SyntaxError. If the content doesn't parse as-is, progressively drop trailing
    lines until it does (or give up and return the original if nothing recovers)."""
    import ast
    try:
        ast.parse(content)
        return content
    except SyntaxError:
        pass
    lines = content.split("\n")
    if len(lines) < 2:
        return content
    min_lines = max(1, int(len(lines) * 0.5))
    for cut in range(len(lines) - 1, min_lines - 1, -1):
        candidate = "\n".join(lines[:cut]).rstrip() + "\n"
        try:
            ast.parse(candidate)
            return candidate
        except SyntaxError:
            continue
    return content

def fix_test_import_module_name(test_code: str, app_code: str, correct_module: str) -> str:
    """Local models sometimes get the test file's link to the app module wrong in one of
    two ways: (1) inventing their own conceptual module name (e.g. 'from
    student_details_manager import ...') instead of the file it's actually saved as
    ('generated_app'), or (2) omitting the import line entirely while still calling the
    app's functions directly, both causing NameError/ModuleNotFoundError at test time.
    Only ever touches names that demonstrably match real functions/classes defined in
    app_code, so real third-party imports (pytest, unittest, etc.) are never disturbed,
    and nothing is invented for names that don't actually exist in the app."""
    import re, ast
    try:
        app_tree = ast.parse(app_code)
    except SyntaxError:
        return test_code
    app_names = {n.name for n in ast.walk(app_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    if not app_names:
        return test_code

    try:
        test_tree = ast.parse(test_code)
    except SyntaxError:
        test_tree = None

    pattern = re.compile(r"^from\s+([\w.]+)\s+import\s+(.+)$", re.MULTILINE)
    matches = list(pattern.finditer(test_code))

    for m in matches:
        mod_name, imported = m.group(1), m.group(2)
        imported_names = {tok.strip().split(" as ")[0].strip() for tok in imported.split(",")}
        if imported_names & app_names:
            # This is the self-referencing import line — fix the module name if wrong, and
            # merge in any app names the test actually calls but that got left off the list.
            needed = imported_names.copy()
            if test_tree is not None:
                referenced = {n.id for n in ast.walk(test_tree) if isinstance(n, ast.Name)}
                needed |= (referenced & app_names)
            new_line = f"from {correct_module} import {', '.join(sorted(needed))}"
            return test_code[:m.start()] + new_line + test_code[m.end():]

    # No self-referencing import line exists at all. If the test references real app
    # names anyway (a model that forgot the import but still called the functions),
    # insert one rather than leaving it to fail with NameError.
    if test_tree is not None:
        referenced = {n.id for n in ast.walk(test_tree) if isinstance(n, ast.Name)}
        needed = referenced & app_names
        if needed:
            return f"from {correct_module} import {', '.join(sorted(needed))}\n" + test_code

    return test_code

_COMMON_TEST_IMPORTS = [
    ("unittest.mock", ["patch", "Mock", "MagicMock", "mock_open", "ANY", "call", "PropertyMock"]),
    ("io", ["StringIO", "BytesIO"]),
    ("contextlib", ["redirect_stdout", "redirect_stderr"]),
]

def ensure_java_test_imports(test_code: str) -> str:
    """Add the java.util imports a generated JUnit suite forgot.

    The model writes logically correct tests — `GeneratedApp.addTask(tasks, "x")`, correct
    assertions — then declares `private List<String> tasks = new ArrayList<>();` without ever
    importing List/ArrayList. That single omission fails the whole compile with "cannot find
    symbol", so a perfectly good suite got discarded and Java fell back to a placeholder test.
    Deterministic to fix here rather than hoping the model remembers."""
    java_util = ("List", "ArrayList", "Map", "HashMap", "Set", "HashSet",
                 "Arrays", "Collections", "Optional", "LinkedList", "Deque", "ArrayDeque")
    if re.search(r"^\s*import\s+java\.util\.\*\s*;", test_code, re.M):
        return test_code
    body = strip_comments_and_strings(test_code, "java")
    needed = [t for t in java_util
              if re.search(rf"(?<![\w.]){t}\b", body)
              and not re.search(rf"^\s*import\s+java\.util\.{t}\s*;", test_code, re.M)]
    if not needed:
        return test_code
    # Imports must follow any package statement; these files have none, so prepend.
    return "import java.util.*;\n" + test_code

def ensure_cpp_test_includes(test_code: str) -> str:
    """Same idea for Catch2 suites: the test re-declares prototypes using std::vector /
    std::string but sometimes omits the corresponding <vector> / <string> include, which
    fails the compile before a single assertion runs."""
    additions = []
    body = strip_comments_and_strings(test_code, "cpp")
    for sym, header in (("std::vector", "vector"), ("std::string", "string"), ("std::map", "map")):
        if sym in body and not re.search(rf"^\s*#include\s*<{header}>", test_code, re.M):
            additions.append(f"#include <{header}>")
    if not additions:
        return test_code
    # Must land after the CATCH_CONFIG_MAIN define / catch.hpp include, not before them.
    lines = test_code.split("\n")
    insert_at = 0
    for i, line in enumerate(lines):
        if "catch.hpp" in line or "CATCH_CONFIG_MAIN" in line:
            insert_at = i + 1
    return "\n".join(lines[:insert_at] + additions + lines[insert_at:])

def ensure_common_test_imports(test_code: str) -> str:
    """Weak models frequently reference unittest.mock.patch/Mock/etc., io.StringIO, or
    contextlib.redirect_stdout in a test without ever importing them, causing a plain
    NameError even though the test's actual logic is fine. Detect the common cases and
    prepend whatever's missing rather than let the pipeline burn a retry on it."""
    import ast
    try:
        tree = ast.parse(test_code)
    except SyntaxError:
        return test_code

    referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    bound = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".")[0])

    missing_lines = []
    for module, symbols in _COMMON_TEST_IMPORTS:
        needed = {s for s in symbols if s in referenced and s not in bound}
        if needed:
            missing_lines.append(f"from {module} import {', '.join(sorted(needed))}")

    if not missing_lines:
        return test_code
    return "\n".join(missing_lines) + "\n" + test_code

def is_regressive_python_rewrite(old_code: str, new_code: str) -> bool:
    """Guards against a weak model "fixing" one specific bug by discarding most of the
    existing app and replacing it with a trivial stub (observed in practice: a real 4-function
    to-do list app collapsed into a single `def my_function(): return "Hello, World!"` after a
    few retry iterations). Compares the number of top-level functions/classes before and after
    — if the "fix" loses more than half of them, it's a regression, not progress."""
    import ast
    try:
        old_names = {n.name for n in ast.walk(ast.parse(old_code)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        new_names = {n.name for n in ast.walk(ast.parse(new_code)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    except SyntaxError:
        return False
    if len(old_names) < 2:
        return False
    return len(new_names) < len(old_names) * 0.5

def has_repetition_loop(code: str) -> bool:
    """Small local models occasionally fall into a decoding loop and repeat the same short
    phrase dozens of times in a row — e.g. a real observed case where a test function name
    degenerated into `test_empty_task_name_and_description_and_description_and_description...`
    repeated across 40+ near-duplicate test functions, bloating a test file to 20KB. This is
    dangerous specifically because the file's TEXT keeps changing on every retry (new garbage
    each time), so the regular "AI returned unchanged code" stagnation guard never catches it
    and the pipeline burns its whole loop budget on an ever-growing garbage file. Detect the
    signature directly: any short chunk (4-40 chars) immediately repeated 5+ times in a row —
    legitimate code just doesn't do this, regardless of language. Punctuation-only repeats
    (a "====" banner comment, "----" divider, etc.) are excluded — those are normal style,
    not a decoding loop — by requiring the repeated chunk to contain an actual word character."""
    for m in re.finditer(r"(.{4,40}?)\1{4,}", code, re.DOTALL):
        if re.search(r"\w", m.group(1)):
            return True
    return False

def repair_markdown_escapes(code: str) -> str:
    """Some models emit their code with markdown escaping still applied — underscores and
    asterisks come through backslash-escaped (`len(_todo\\_list)`, `\\*args`), which is a
    guaranteed SyntaxError. Only used as a repair attempt on code that already failed to
    parse, so correct code containing legitimate backslashes is never touched."""
    return re.sub(r"\\([_*`\[\]#])", r"\1", code)

def is_usable_source(code: str, language: str) -> bool:
    """Gate every piece of AI-written code before it is allowed to overwrite what's on disk.

    Observed in practice: a model answered a fix request with a plain English preamble
    ("Here's the updated APP CODE and TEST CODE...") and that sentence got written to
    generated_app.py as the entire program, destroying the previously working app. Nothing
    checked that the "fix" was even parseable, so the pipeline then spent every remaining
    loop trying to fix a file containing one line of prose.

    is_regressive_python_rewrite() could not catch this: it ast.parse()s both versions inside
    a try block and returns False (= "not a regression, accept it") the moment either side
    raises SyntaxError — so syntactically broken rewrites sailed straight through the guard
    that was supposed to stop bad rewrites."""
    if not code or not code.strip():
        return False
    if language == "python":
        import ast
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    # No cheap parser for C++/Java (the compiler runs a moment later and its error is fed
    # back to the model), so just reject output that plainly isn't source: prose has no
    # braces, and real code in these languages always carries a balanced-looking block.
    return "{" in code and "}" in code

def _enclosing_body(src: str, open_brace_idx: int) -> str:
    """Return the {...} block starting at open_brace_idx, via brace matching."""
    depth, i, n = 0, open_brace_idx, len(src)
    while i < n:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_brace_idx:i + 1]
        i += 1
    return src[open_brace_idx:]

def app_has_untestable_input_api(code: str, language: str) -> bool:
    """True when a non-main function reads user input, directly or via a reader parameter.

    Two shapes both make an app impossible to unit test, and models produce both despite the
    prompt forbidding them:
      1. `static boolean addTask(List<String> tasks, Scanner scanner)` — tests must pass either
         null (NullPointerException) or a real reader that blocks forever on stdin.
      2. `static boolean addTask()` with no parameters at all, reading a Scanner field and
         mutating `private static List<String> tasks` — tests can't reach the private state
         ("cannot find symbol") and can't supply input.
    Checking parameters alone missed case 2 entirely, so this inspects each non-main function's
    BODY for input reads as well. Catching it here makes the Coder re-roll into a shape that
    can actually be tested, instead of shipping an app whose test suite can never work."""
    body = strip_comments_and_strings(code, language)
    if language == "java":
        reads = re.compile(r"\.next(?:Line|Int|Double|Boolean)?\s*\(|\breadLine\s*\(")
        for m in re.finditer(r"\b(?:static|public|private|protected)[\w\s<>,\[\]]*?\b(\w+)\s*\(([^)]*)\)\s*\{", body):
            name, params = m.group(1), m.group(2)
            if name == "main":
                continue
            if re.search(r"\bScanner\b|\bBufferedReader\b", params):
                return True
            brace = body.find("{", m.end() - 1)
            if brace != -1 and reads.search(_enclosing_body(body, brace)):
                return True
        return False
    if language == "cpp":
        skip = ("main", "if", "for", "while", "switch", "catch", "return", "sizeof")
        for m in re.finditer(r"\b(\w+)\s*\(([^)]*)\)\s*\{", body):
            name, params = m.group(1), m.group(2)
            if name in skip:
                continue
            if re.search(r"\bistream\b|\bcin\b", params):
                return True
            brace = body.find("{", m.end() - 1)
            if brace != -1 and re.search(r"\bcin\s*>>|getline\s*\(", _enclosing_body(body, brace)):
                return True
        return False
    return False

async def app_source_compiles(language: str, cwd: str, app_filename: str):
    """For C++/Java, confirm the generated APP actually compiles before accepting it.

    is_usable_source() can only do a brace sanity-check for these languages, which let real
    compile errors straight through the Coder gate — observed: a `switch` with a variable
    declared inside a case ("jump to case label crosses initialization"). Every test suite
    built against that app then failed to compile too, and the failure was misattributed to
    the tests. Compiling here means the Coder re-rolls a broken app instead.

    Returns (ok, reason)."""
    if language == "cpp":
        code, out, err = await run_cmd(
            f'g++ -std=c++17 -Dmain=__app_main_disabled__ -I "{TOOLS_DIR}" -c "{app_filename}" -o _probe_appchk.o',
            cwd=cwd)
        try: os.remove(os.path.join(cwd, "_probe_appchk.o"))
        except OSError: pass
        if code != 0:
            first = next((l for l in (out + err).splitlines() if "error:" in l), "compile error")
            return False, first.strip()[:120]
        return True, ""
    if language == "java":
        code, out, err = await run_cmd(f'javac -cp "{JAVA_CLASSPATH}" "{app_filename}"', cwd=cwd)
        if code != 0:
            first = next((l for l in (out + err).splitlines() if "error:" in l), "compile error")
            return False, first.strip()[:120]
        return True, ""
    return True, ""

async def test_file_is_runnable(language: str, cwd: str, test_filename: str):
    """Parsing isn't enough for a TEST file — it also has to be collectable by the runner.

    Observed failures that all parse fine but abort the whole suite before a single assertion
    executes: a malformed @pytest.mark.parametrize (1 name vs 2 values), and an import of a
    function the app doesn't define. Worse, models keep putting input() inside tests despite
    being told not to, which hangs pytest with 'reading from stdin while output is captured'.
    Catching these here lets the Coder re-roll instead of handing the Tester a suite that can
    never pass no matter how many fix loops it burns.

    Returns (ok, reason)."""
    path = os.path.join(cwd, test_filename)
    if language == "python":
        try:
            with open(path, "r", encoding="utf-8") as f:
                body = f.read()
        except OSError as e:
            return False, str(e)
        if has_dangerous_call(strip_comments_and_strings(body, "python"), "input"):
            return False, "test calls input(), which hangs the runner"
        code, out, err = await run_cmd(
            f"{sys.executable} -m pytest {test_filename} --collect-only -q", cwd=cwd)
        if code != 0:
            tail = (out + err).strip().splitlines()
            detail = next((l for l in reversed(tail) if l.strip()), "collection failed")
            return False, f"pytest could not collect the suite ({detail[:110]})"
        return True, ""

    # C++/Java: build the suite now rather than waiting for the Tester. Models routinely
    # invent helpers that don't exist (CaptureStream(...), MockScanner, captureOutput(...))
    # when the app's functions return void, and emit malformed imports — none of which any
    # number of fix loops recovers from. Compiling here lets the Coder re-roll instead.
    app_filename = test_filename.replace("test_", "", 1)
    if language == "cpp":
        code, out, err = await run_cmd(
            f'g++ -std=c++17 -Dmain=__app_main_disabled__ -I "{TOOLS_DIR}" -c "{app_filename}" -o _probe_app.o', cwd=cwd)
        if code != 0:
            return False, "app does not compile"
        code, out, err = await run_cmd(
            f'g++ -std=c++17 -I "{TOOLS_DIR}" -c "{test_filename}" -o _probe_test.o', cwd=cwd)
        if code != 0:
            first = next((l for l in (out + err).splitlines() if "error:" in l), "compile error")
            return False, f"test suite does not compile ({first.strip()[:110]})"
        code, out, err = await run_cmd("g++ -o _probe_tests.exe _probe_app.o _probe_test.o -static", cwd=cwd)
        if code != 0:
            first = next((l for l in (out + err).splitlines() if "undefined" in l.lower()), "link error")
            return False, f"test suite does not link ({first.strip()[:110]})"
        for junk in ("_probe_app.o", "_probe_test.o", "_probe_tests.exe"):
            try: os.remove(os.path.join(cwd, junk))
            except OSError: pass
        return True, ""

    if language == "java":
        code, out, err = await run_cmd(
            f'javac -cp "{JAVA_CLASSPATH}" "{app_filename}" "{test_filename}"', cwd=cwd)
        if code != 0:
            first = next((l for l in (out + err).splitlines() if "error:" in l), "compile error")
            return False, f"test suite does not compile ({first.strip()[:110]})"
        return True, ""

    return True, ""

SAST_TOOL_NAME = {"python": "Bandit", "cpp": "Cppcheck", "java": "Semgrep"}
TEST_TOOL_NAME = {"python": "Pytest", "cpp": "Catch2", "java": "JUnit"}

STUB_TEST_CODE = {
    "python": "# Dynamic tests omitted to speed up demo\nimport pytest\n\ndef test_pass():\n    assert True\n",
    "cpp": '#define CATCH_CONFIG_MAIN\n#include "catch.hpp"\n\nTEST_CASE("placeholder") {\n    REQUIRE(true);\n}\n',
    "java": (
        "import org.junit.jupiter.api.Test;\n"
        "import static org.junit.jupiter.api.Assertions.assertTrue;\n\n"
        "class GeneratedAppTest {\n"
        "    @Test\n"
        "    void placeholder() {\n"
        "        assertTrue(true);\n"
        "    }\n"
        "}\n"
    ),
}

CODER_PROMPTS = {
    "python": CODER_SYSTEM_PROMPT,
    "cpp": (
        "You are a Senior Security-Focused C++ Architect. Build a highly professional, production-ready C++17 console "
        "application solving this requirement: '{prompt_text}'. Requirements:\n"
        "- Single file only, delimited exactly as $$FILE: generated_app.cpp$$\n"
        "- All core logic MUST live in free functions or classes declared OUTSIDE of main() so they can be unit tested directly.\n"
        "- Provide a normal 'int main() {{ ... }}' with an interactive std::cin loop calling your functions.\n"
        "- You MUST also provide a Catch2 test file, delimited as $$FILE: test_generated_app.cpp$$ using '#define CATCH_CONFIG_MAIN' + '#include \"catch.hpp\"' + TEST_CASE(...) macros, declaring the functions under test with a matching prototype (do not re-include generated_app.cpp). "
        "This is NOT optional and the tests must NOT be trivial placeholders like REQUIRE(true) — each TEST_CASE must call your actual functions with representative inputs and REQUIRE the exact expected output/behavior (e.g. REQUIRE(evaluate(\"5+5\") == 10)), covering the core functionality described in the requirement plus at least one edge case.\n"
        "- Use robust error handling and input validation. Do NOT hardcode test data.\n"
        "- If the requirement needs JSON, the nlohmann/json single-header library is available: #include \"nlohmann/json.hpp\" (use nlohmann::json).\n"
        "- Output ONLY the raw delimited code, absolutely no markdown fences."
    ),
    "java": (
        "You are a Senior Security-Focused Java Architect. Build a highly professional, production-ready Java (JDK 17+) "
        "console application solving this requirement: '{prompt_text}'. Requirements:\n"
        "- Single file only, delimited exactly as $$FILE: generated_app.java$$\n"
        # {{ }} renders as literal { } — this template is passed through .format(prompt_text=...),
        # and the single braces that used to be here made format() raise ValueError, so selecting
        # Java with ANY cloud model (Gemini/Claude/OpenRouter) crashed the Coder instantly,
        # before a single request was made. The C++ template had already been escaped; this one
        # was missed.
        "- The top-level class MUST be named exactly GeneratedApp and declared WITHOUT the 'public' modifier (i.e. 'class GeneratedApp {{ ... }}') "
        "so the file can be saved as generated_app.java without Java's public-class-filename rule.\n"
        "- All core logic MUST live in static methods on GeneratedApp (e.g. GeneratedApp.methodName(...)) so they can be unit tested directly.\n"
        "- The 'public static void main(String[] args)' method with the interactive Scanner-based loop MUST be defined directly inside the GeneratedApp class itself — do NOT create a separate Main/Launcher/App class to hold it.\n"
        "- You MUST also provide a JUnit 5 test file, delimited as $$FILE: test_generated_app.java$$ with a non-public class named exactly GeneratedAppTest. "
        "This is NOT optional and the tests must NOT be trivial placeholders like assertTrue(true) — each @Test method must call your actual static methods with representative inputs and assertEquals the exact expected output/behavior (e.g. assertEquals(10, GeneratedApp.evaluate(\"5+5\"))), covering the core functionality described in the requirement plus at least one edge case.\n"
        "- Use robust error handling and input validation. Do NOT hardcode test data.\n"
        "- If the requirement needs JSON, the Gson library is available: import com.google.gson.Gson;\n"
        "- Output ONLY the raw delimited code, absolutely no markdown fences."
    ),
}

OLLAMA_CODER_PROMPTS = {
    "python": (
        "Write a complete, working Python script for: {prompt}\n\n"
        "Rules:\n"
        "- All core logic in standalone functions that take their data as PARAMETERS (not by calling input() themselves) so they're independently unit-testable without any stdin/mocking.\n"
        "- Only the main() CLI loop may call input() to collect user data — it then passes that data into the core functions.\n"
        "- Main menu with while True loop so user can keep using it\n"
        "- try/except error handling on every operation\n"
        "- Clean readable code under 120 lines\n"
        "- You MUST also write a pytest test file. Do NOT use trivial placeholders like 'assert True' — each test must call your actual functions with representative inputs and assert the exact expected output (e.g. assert evaluate('5+5') == 10), covering the core functionality plus at least one edge case.\n"
        "- Output using exactly this format, nothing else, no markdown fences:\n"
        "$$FILE: generated_app.py$$\n<app code>\n$$FILE: test_generated_app.py$$\n<test code>"
    ),
    "cpp": (
        "Write a complete, working C++17 console program for: {prompt}\n\n"
        "Rules:\n"
        "- All logic in free functions declared OUTSIDE main() so they're independently testable\n"
        "- Provide a normal int main() {{ ... }} with an interactive std::cin-based loop so the user can keep using it\n"
        "- try/catch and input validation on every operation\n"
        "- Clean readable code under 150 lines\n"
        "- You MUST also write a Catch2 test file ('#define CATCH_CONFIG_MAIN' + '#include \"catch.hpp\"' + TEST_CASE(...) macros, redeclaring the tested function prototypes, do not re-include the app file). Do NOT use trivial placeholders like REQUIRE(true) — each TEST_CASE must call your actual functions with representative inputs and REQUIRE the exact expected output (e.g. REQUIRE(evaluate(\"5+5\") == 10)), covering the core functionality plus at least one edge case.\n"
        "- If you need JSON, the nlohmann/json single-header library is available: #include \"nlohmann/json.hpp\" (use nlohmann::json)\n"
        "- Output using exactly this format, nothing else, no markdown fences:\n"
        "$$FILE: generated_app.cpp$$\n<app code>\n$$FILE: test_generated_app.cpp$$\n<test code>"
    ),
    "java": (
        "Write a complete, working Java (JDK 17+) console program for: {prompt}\n\n"
        "Rules:\n"
        "- Top-level class named exactly GeneratedApp, declared WITHOUT the 'public' modifier\n"
        "- All logic in static methods on GeneratedApp so they're independently testable\n"
        "- 'public static void main(String[] args)' defined directly inside the GeneratedApp class itself (do NOT create a separate Main/Launcher class for it), with an interactive Scanner-based loop\n"
        "- try/catch and input validation on every operation\n"
        "- Clean readable code under 150 lines\n"
        "- You MUST also write a JUnit 5 test file with a non-public class named exactly GeneratedAppTest. Do NOT use trivial placeholders like assertTrue(true) — each @Test method must call your actual static methods with representative inputs and assertEquals the exact expected output (e.g. assertEquals(10, GeneratedApp.evaluate(\"5+5\"))), covering the core functionality plus at least one edge case.\n"
        "- If you need JSON, the Gson library is available: import com.google.gson.Gson;\n"
        "- Output using exactly this format, nothing else, no markdown fences:\n"
        "$$FILE: generated_app.java$$\n<app code>\n$$FILE: test_generated_app.java$$\n<test code>"
    ),
}

# ── Two-stage local-model prompts ─────────────────────────────────────────────
# OLLAMA_CODER_PROMPTS above asks for the app AND its tests in a single response, using a
# custom $$FILE:$$ delimiter. Three things went wrong with that on small local models:
#   1. One response, two files, ~10 constraints — far too much for a 3B model to hold.
#   2. They ignore the $$FILE: delimiter and emit ```fenced``` blocks anyway (measured).
#   3. Worst: the tests get invented at the same moment as the app, so they routinely assert
#      behaviour the finished code doesn't have (e.g. asserting evaluate("5 + 5") == 10 when
#      the app parses a different format). The Tester then "fails" on a mismatch that was
#      baked in at generation time, and burns the whole fix budget on it.
# Splitting into two focused calls fixes all three: each call is small, fenced output is
# expected rather than fought, and the tests are written against the REAL finished code.

OLLAMA_APP_PROMPTS = {
    "python": (
        "Write a complete, working Python program for: {prompt}\n\n"
        "Requirements:\n"
        "- Put all core logic in top-level functions that take their data as ARGUMENTS and RETURN a result.\n"
        "- Never call input() inside those functions — only inside main().\n"
        "- Include `def main():` with a while-True menu loop that calls those functions.\n"
        "- End with `if __name__ == \"__main__\": main()`.\n"
        "- Use try/except for error handling. Under 120 lines.\n\n"
        "Output ONLY the Python code. No explanation before or after it."
    ),
    # The "must RETURN a value, must not print" rule is the load-bearing part for the compiled
    # languages. When the model wrote void functions that print to stdout instead, the test
    # stage had nothing it could assert on — so it invented output-capture helpers that don't
    # exist (CaptureStream(cerr).str(), captureOutput(...), MockScanner) and the suite failed
    # to compile every single time, which no amount of fix loops could recover.
    "cpp": (
        "Write a complete, working C++17 console program for: {prompt}\n\n"
        "Requirements:\n"
        "- Put all core logic in free functions declared OUTSIDE main().\n"
        "- Every core function MUST RETURN a value (bool, int, std::string, std::vector<...>).\n"
        "  Do NOT write `void` core functions. Do NOT print inside them. Do NOT read std::cin inside them.\n"
        "  Example shape: `bool addTask(std::vector<std::string>& tasks, const std::string& task)`\n"
        "  — it changes the vector and returns whether it succeeded.\n"
        "- ALL printing and ALL std::cin reading happens only inside main().\n"
        "- Include a normal `int main()` with an interactive std::cin menu loop that calls those functions.\n"
        "- Include every header you use (<vector>, <string>, <iostream>). Under 150 lines.\n\n"
        "Output ONLY the C++ code. No explanation before or after it."
    ),
    "java": (
        "Write a complete, working Java (JDK 17+) console program for: {prompt}\n\n"
        "Requirements:\n"
        "- One top-level class named exactly GeneratedApp, declared WITHOUT the 'public' modifier.\n"
        "- Put all core logic in static methods on GeneratedApp.\n"
        "- Every core method MUST take the data it works on as PARAMETERS and MUST RETURN a value.\n"
        "  No no-arg core methods. No `void` core methods. No Scanner/BufferedReader parameter.\n"
        "  Never call scanner.nextLine() or System.out inside a core method.\n"
        "- Do NOT keep the data in a private static field that the methods mutate — pass it in.\n"
        "- ALL printing and ALL Scanner reading happens only inside main().\n"
        # Braces in this worked example are doubled: the string goes through .format() to
        # inject {prompt}, and a single { in the sample code makes format() try to parse a
        # field name and raise ValueError — which crashed the Coder before it ever reached
        # the model. {{ and }} render as literal { and }.
        "- Follow this exact shape:\n\n"
        "    import java.util.ArrayList;\n"
        "    import java.util.List;\n"
        "    import java.util.Scanner;\n\n"
        "    class GeneratedApp {{\n"
        "        static boolean addTask(List<String> tasks, String task) {{\n"
        "            if (task == null || task.isEmpty()) return false;\n"
        "            tasks.add(task);\n"
        "            return true;\n"
        "        }}\n\n"
        "        public static void main(String[] args) {{\n"
        "            List<String> tasks = new ArrayList<>();\n"
        "            Scanner scanner = new Scanner(System.in);\n"
        "            // menu loop: read here, then call addTask(tasks, value) and print the result\n"
        "        }}\n"
        "    }}\n\n"
        "- Import everything you use. Under 150 lines.\n\n"
        "Output ONLY the Java code. No explanation before or after it."
    ),
}

OLLAMA_TEST_PROMPTS = {
    "python": (
        "Here is a Python program saved as `generated_app.py`:\n\n"
        "```python\n{app_code}\n```\n\n"
        "Write a pytest test file for it.\n\n"
        "Rules:\n"
        "- Start with an import of the functions you test, e.g. `from generated_app import foo, bar`.\n"
        "- ONLY test functions that appear in the code above, using their EXACT names and argument counts.\n"
        "- Base every expected value on what the code above actually does — read it carefully.\n"
        "- Write PLAIN test functions only: `def test_xxx():` with direct calls and asserts.\n"
        "- Do NOT use pytest fixtures, @pytest.mark.parametrize, mocks, or classes. They are banned.\n"
        "- NEVER call input() anywhere. Pass values directly as arguments instead.\n"
        "- Never test main(). Never use 'assert True'.\n"
        "- Write 3-5 small test functions covering normal cases plus one edge case.\n\n"
        "Output ONLY the Python test code. No explanation before or after it."
    ),
    "cpp": (
        "Here is a C++17 program saved as `generated_app.cpp`:\n\n"
        "```cpp\n{app_code}\n```\n\n"
        "Write a Catch2 test file for it.\n\n"
        "Rules:\n"
        "- Start with `#define CATCH_CONFIG_MAIN`, then `#include \"catch.hpp\"`, then <vector>/<string> as needed.\n"
        "- Re-declare the prototype of each function you test (do NOT #include generated_app.cpp).\n"
        "- ONLY test functions that appear above, using their EXACT names and signatures.\n"
        "- Assert ONLY on returned values and on data you passed in (e.g. the vector's size/contents).\n"
        "- NEVER capture or assert on printed output. There is no CaptureStream, no cout/cerr .str().\n"
        "  Do not invent helper functions or mocks — only call what exists in the code above.\n"
        "- Base every REQUIRE on what the code above actually does. No REQUIRE(true).\n"
        "- Write 3-5 TEST_CASEs covering normal cases plus one edge case.\n\n"
        "Output ONLY the C++ test code. No explanation before or after it."
    ),
    "java": (
        "Here is a Java class saved as `generated_app.java`:\n\n"
        "```java\n{app_code}\n```\n\n"
        "Write a JUnit 5 test file for it.\n\n"
        "Rules:\n"
        "- One non-public class named exactly GeneratedAppTest.\n"
        "- The imports must be exactly these two lines, in this order, and nothing unusual:\n"
        "    import org.junit.jupiter.api.Test;\n"
        "    import static org.junit.jupiter.api.Assertions.*;\n"
        "  (plus java.util imports if you need List/ArrayList). Never write 'static import'.\n"
        "- ONLY test static methods that appear above, called as GeneratedApp.method(...), using their EXACT names and signatures.\n"
        "- Assert ONLY on returned values and on data you passed in (e.g. the list's size/contents).\n"
        "- NEVER capture or assert on printed output, and NEVER use a Scanner or a mock.\n"
        "  Do not invent helper classes or methods — only call what exists in the code above.\n"
        "- Base every assertion on what the code above actually does. No assertTrue(true).\n"
        "- Write 3-5 @Test methods covering normal cases plus one edge case.\n\n"
        "Output ONLY the Java test code. No explanation before or after it."
    ),
}

def strip_comments_and_strings(code: str, language: str) -> str:
    """Blank out comment bodies and string literals (replacing them with spaces, so line and
    column positions — and therefore reported line numbers — are preserved).

    Without this, the dangerous-call scan matched the word `eval()` inside a DOCSTRING. The
    synthesizer's own verified-secure reference implementation documents itself with
    "...using structured JSON parsing without eval()", so the Hacker Agent flagged the
    correctly-patched, genuinely-secure code as still vulnerable, sent it back to the Patcher,
    and the two agents ping-ponged forever over a vulnerability that had already been fixed.
    Only used for call-shaped patterns; the SQL-injection patterns (f"SELECT ...) are
    intrinsically about string contents and still scan the raw source."""
    lines = code.split("\n")
    if language == "python":
        import io, tokenize
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return code  # unparseable mid-generation; scanning raw is the safe fallback
        for tok in tokens:
            if tok.type not in (tokenize.COMMENT, tokenize.STRING):
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            for row in range(srow, erow + 1):
                idx = row - 1
                if idx >= len(lines):
                    break
                line = lines[idx]
                start = scol if row == srow else 0
                end = ecol if row == erow else len(line)
                lines[idx] = line[:start] + " " * max(0, end - start) + line[end:]
        return "\n".join(lines)

    # C/C++/Java: line comments, block comments, and string/char literals.
    pattern = r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''
    return re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m.group(0)), code, flags=re.DOTALL)

def has_dangerous_call(code: str, func_name: str) -> bool:
    """Match `func_name(` as a standalone call, not as the tail end of a longer identifier
    (e.g. the substring 'eval(' inside ast.literal_eval(, or 'gets(' inside a perfectly
    innocent calculate_budgets(). A plain substring check flagged those as if they were the
    dangerous call — which meant the Patcher's own fix (swapping eval() for the recommended-
    safe ast.literal_eval()) got immediately re-flagged as still vulnerable on the next scan,
    so the Hacker/Patcher loop never converged even after the code was actually secure."""
    return re.search(rf'(?<![\w.]){re.escape(func_name)}\s*\(', code) is not None

VULN_HEURISTICS = {
    "python": lambda c: has_dangerous_call(strip_comments_and_strings(c, "python"), "eval") or ('f"SELECT' in c) or ("f'SELECT" in c) or ('f"./uploads' in c),
    "cpp": lambda c: any(has_dangerous_call(strip_comments_and_strings(c, "cpp"), fn) for fn in ("strcpy", "system", "gets", "sprintf")),
    "java": lambda c: has_dangerous_call(strip_comments_and_strings(c, "java"), "Runtime.getRuntime().exec") or ("createStatement()" in c and "+" in c),
}

async def run_compile_and_test(language: str, cwd: str, app_filename: str, test_filename: str):
    """Returns (passed: bool, output: str)."""
    if language == "python":
        cmd = f"{sys.executable} -m pytest {test_filename} -v --tb=short"
        code, out, err = await run_cmd(cmd, cwd=cwd)
        return code == 0, f"$ pytest {test_filename} -v\n{out}{err}"

    if language == "cpp":
        # Rename the app's main() away during test compilation so it never conflicts with
        # Catch2's own main() (CATCH_CONFIG_MAIN) — works regardless of how the app's main() is written.
        app_obj_cmd = f'g++ -std=c++17 -Dmain=__app_main_disabled__ -I "{TOOLS_DIR}" -c "{app_filename}" -o app_under_test.o'
        code, out, err = await run_cmd(app_obj_cmd, cwd=cwd)
        if code != 0:
            return False, f"$ {app_obj_cmd}\n[COMPILE ERROR]\n{out}{err}"
        test_obj_cmd = f'g++ -std=c++17 -I "{TOOLS_DIR}" -c "{test_filename}" -o test_under_test.o'
        code, out, err = await run_cmd(test_obj_cmd, cwd=cwd)
        if code != 0:
            return False, f"$ {test_obj_cmd}\n[COMPILE ERROR]\n{out}{err}"
        # -static is essential, not an optimisation. Without it the test binary links against
        # the compiler's libstdc++-6.dll / libgcc_s_seh-1.dll, which are NOT on the server
        # process's PATH (only Git's incompatible copies are). The exe then builds perfectly
        # but dies on startup with exit code 127, which the pipeline read as "tests failed" —
        # so every C++ run asked the model to repair code that was already correct, and no
        # C++ suite could ever pass regardless of quality.
        link_cmd = "g++ -o tests.exe app_under_test.o test_under_test.o -static"
        code, out, err = await run_cmd(link_cmd, cwd=cwd)
        if code != 0:
            return False, f"$ {link_cmd}\n[LINK ERROR]\n{out}{err}"
        run_code, run_out, run_err = await run_cmd(".\\tests.exe", cwd=cwd)
        return run_code == 0, f"$ {app_obj_cmd}\n$ {test_obj_cmd}\n$ {link_cmd}\n$ .\\tests.exe\n{run_out}{run_err}"

    if language == "java":
        compile_cmd = f'javac -cp "{JAVA_CLASSPATH}" "{app_filename}" "{test_filename}"'
        code, out, err = await run_cmd(compile_cmd, cwd=cwd)
        if code != 0:
            return False, f"$ {compile_cmd}\n[COMPILE ERROR]\n{out}{err}"
        run_cmd_str = f'java -jar "{JUNIT_JAR}" -cp ".;{GSON_JAR}" --select-class GeneratedAppTest --disable-banner --disable-ansi-colors'
        run_code, run_out, run_err = await run_cmd(run_cmd_str, cwd=cwd)
        return run_code == 0, f"$ {compile_cmd}\n$ {run_cmd_str}\n{run_out}{run_err}"

    return True, "[No test runner configured for this language]"

async def run_sast(language: str, cwd: str, app_filename: str, sec_report_file: str):
    """Returns list of {issue_text, severity, confidence, line} dicts.
    Only includes findings severe enough to be genuine security/correctness concerns —
    pure code-style/performance nits are excluded so the Patcher loop doesn't get stuck
    trying to "fix" non-security suggestions."""
    vulnerabilities = []
    if language == "python":
        cmd = f"{sys.executable} -m bandit -f json -o security_report.json {app_filename}"
        await run_cmd(cmd, cwd=cwd)
        if os.path.exists(sec_report_file):
            try:
                with open(sec_report_file, "r") as f:
                    data = json.load(f)
                for item in data.get("results", []):
                    if (item.get("issue_severity") or "").upper() == "LOW":
                        continue
                    vulnerabilities.append({
                        "issue_text": item.get("issue_text"),
                        "severity": item.get("issue_severity"),
                        "confidence": item.get("issue_confidence"),
                        "line": item.get("line_number"),
                    })
            except Exception:
                pass

    elif language == "cpp":
        cmd = f'cppcheck --enable=warning,style,performance,portability --xml --xml-version=2 "{app_filename}"'
        code, out, err = await run_cmd(cmd, cwd=cwd)
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(err if "<results" in err else out)
            for err_el in root.findall(".//error"):
                severity = err_el.get("severity")
                if severity not in ("error", "warning"):
                    continue
                loc = err_el.find("location")
                vulnerabilities.append({
                    "issue_text": err_el.get("msg"),
                    "severity": severity,
                    "confidence": "MEDIUM",
                    "line": loc.get("line") if loc is not None else None,
                })
        except Exception:
            pass

    elif language == "java":
        cmd = f'semgrep --config=p/security-audit --json -o security_report.json "{app_filename}"'
        await run_cmd(cmd, cwd=cwd)
        if os.path.exists(sec_report_file):
            try:
                with open(sec_report_file, "r") as f:
                    data = json.load(f)
                for item in data.get("results", []):
                    severity = (item.get("extra", {}).get("severity") or "").upper()
                    if severity == "INFO":
                        continue
                    vulnerabilities.append({
                        "issue_text": item.get("check_id"),
                        "severity": severity,
                        "confidence": "MEDIUM",
                        "line": item.get("start", {}).get("line"),
                    })
            except Exception:
                pass
    app_file_path = os.path.join(cwd, app_filename)
    if os.path.exists(app_file_path):
        with open(app_file_path, "r", encoding="utf-8") as f:
            raw_source = f.read()
        lines = raw_source.split("\n")
        # Strip once over the WHOLE file (not per-line — a single line taken out of context
        # can't be tokenized correctly, e.g. a line sitting inside a multi-line docstring).
        # Line structure is preserved, so indexes stay aligned with `lines` above.
        code_only_lines = strip_comments_and_strings(raw_source, language).split("\n")

        heuristics = {
            "python": [("eval(", "eval() is dangerous"), ('f"SELECT', "SQL Injection"), ("f'SELECT", "SQL Injection"), ('f"./uploads', "Path traversal")],
            "cpp": [("strcpy(", "Buffer overflow risk (strcpy)"), ("system(", "Command injection (system)"), ("gets(", "Buffer overflow risk (gets)"), ("sprintf(", "Buffer overflow risk (sprintf)")],
            "java": [("Runtime.getRuntime().exec(", "Command injection"), ("createStatement(", "SQL Injection risk")]
        }
        for i, line in enumerate(lines):
            code_line = code_only_lines[i] if i < len(code_only_lines) else line
            for pattern, desc in heuristics.get(language, []):
                # Call-shaped patterns (end in "(") must match as a standalone call, not as
                # the tail of a longer identifier — see has_dangerous_call for why — and must
                # be matched against the comment/string-stripped line so a docstring merely
                # MENTIONING eval() isn't reported as a live vulnerability.
                matched = has_dangerous_call(code_line, pattern[:-1]) if pattern.endswith("(") else pattern in line
                if matched:
                    vulnerabilities.append({
                        "issue_text": f"{desc} -> found '{pattern}'",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "line": i + 1,
                    })

    return vulnerabilities

def find_java_main_class(code: str) -> str:
    """LLMs don't always put `main` inside the class we asked for (GeneratedApp) — sometimes
    they add a separate 'Main' class instead, despite instructions. Detect whichever top-level
    class actually contains `static void main` rather than assuming, so the run command targets
    the real entry point. Falls back to GeneratedApp if none found.

    Uses proper brace-depth matching (not naive slicing between `class` keywords) so a nested
    class defined before main() inside the same top-level class doesn't get misattributed."""
    import re
    n = len(code)
    i = 0
    depth = 0
    top_level_bodies = []  # (name, full_body_including_braces)
    class_kw_re = re.compile(r"\bclass\s+(\w+)")
    while i < n:
        if depth == 0:
            m = class_kw_re.match(code, i)
            if m:
                brace_start = code.find("{", m.end())
                if brace_start == -1:
                    break
                j = brace_start
                d = 0
                while j < n:
                    if code[j] == "{":
                        d += 1
                    elif code[j] == "}":
                        d -= 1
                        if d == 0:
                            break
                    j += 1
                top_level_bodies.append((m.group(1), code[brace_start:j + 1]))
                i = j + 1
                continue
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
        i += 1
    for name, body in top_level_bodies:
        if re.search(r"\bstatic\s+void\s+main\s*\(", body):
            return name
    return "GeneratedApp"

async def compile_for_run(language: str, cwd: str, app_filename: str):
    """Compiles (if needed) and returns (ok, argv_to_spawn, error_output)."""
    if language == "cpp":
        # Unique output name per compile: a previous run's .exe can still be locked by
        # Windows (process still alive, antivirus scan, etc.), which fails a fixed-name
        # rebuild with "Permission Denied" even though the source itself is fine.
        exe_name = f"app_run_{uuid.uuid4().hex[:8]}.exe"
        # -static for the same reason as the test binary: a dynamically linked exe cannot find
        # the compiler's runtime DLLs from the server process and dies with exit code 127.
        compile_cmd = f'g++ -std=c++17 -I "{TOOLS_DIR}" -o {exe_name} "{app_filename}" -static'
        code, out, err = await run_cmd(compile_cmd, cwd=cwd)
        if code != 0:
            return False, None, f"$ {compile_cmd}\n[COMPILE ERROR]\n{out}{err}"
        return True, [os.path.join(cwd, exe_name)], ""

    if language == "java":
        compile_cmd = f'javac -cp "{GSON_JAR}" "{app_filename}"'
        code, out, err = await run_cmd(compile_cmd, cwd=cwd)
        if code != 0:
            return False, None, f"$ {compile_cmd}\n[COMPILE ERROR]\n{out}{err}"
        try:
            with open(os.path.join(cwd, app_filename), "r", encoding="utf-8") as f:
                main_class = find_java_main_class(f.read())
        except Exception:
            main_class = "GeneratedApp"
        return True, ["java", "-cp", f"{cwd};{GSON_JAR}", main_class], ""

    return True, [sys.executable, "-u", app_filename], ""

def generate_domain_code(prompt: str, language: str = "python"):
    # These are the safety net used when the model can't produce usable code, so they must be
    # the most reliable thing in the system. Both were previously broken in ways that
    # guaranteed failure: the Java app was `public class generated_app` (the runner requires a
    # non-public `GeneratedApp`), its test class was `test_generated_app` rather than
    # `GeneratedAppTest`, and it imported JUnit 4 (org.junit) while the runner is JUnit 5
    # (org.junit.jupiter.api) — so the fallback could never compile, let alone pass. Both also
    # put every statement inside main(), leaving nothing a unit test could call.
    # Each now exposes a real testable function, keeps the deliberate vulnerability for the
    # Hacker to find, and ships a patched variant that still satisfies the same tests.
    if language == "cpp":
        initial_code = (
            '#include <iostream>\n#include <string>\n#include <vector>\n\n'
            'bool addTask(std::vector<std::string>& tasks, const std::string& task) {\n'
            '    if (task.empty()) return false;\n'
            '    tasks.push_back(task);\n'
            '    return true;\n}\n\n'
            'size_t taskCount(const std::vector<std::string>& tasks) { return tasks.size(); }\n\n'
            'int main() {\n'
            '    std::vector<std::string> tasks;\n'
            '    addTask(tasks, "demo task");\n'
            '    std::cout << "Tasks: " << taskCount(tasks) << "\\n";\n'
            '    system("echo vulnerable");\n'
            '    return 0;\n}\n'
        )
        test_code = (
            '#define CATCH_CONFIG_MAIN\n#include "catch.hpp"\n#include <string>\n#include <vector>\n\n'
            'bool addTask(std::vector<std::string>& tasks, const std::string& task);\n'
            'size_t taskCount(const std::vector<std::string>& tasks);\n\n'
            'TEST_CASE("addTask stores a task") {\n'
            '    std::vector<std::string> tasks;\n'
            '    REQUIRE(addTask(tasks, "write report"));\n'
            '    REQUIRE(taskCount(tasks) == 1);\n}\n\n'
            'TEST_CASE("addTask rejects an empty task") {\n'
            '    std::vector<std::string> tasks;\n'
            '    REQUIRE_FALSE(addTask(tasks, ""));\n'
            '    REQUIRE(taskCount(tasks) == 0);\n}\n'
        )
        patched_code = initial_code.replace('    system("echo vulnerable");\n', '')
        return initial_code, test_code, patched_code, "Command Injection", "Usage of system() detected."
    if language == "java":
        initial_code = (
            'import java.util.ArrayList;\nimport java.util.List;\n\n'
            'class GeneratedApp {\n'
            '    static boolean addTask(List<String> tasks, String task) {\n'
            '        if (task == null || task.isEmpty()) return false;\n'
            '        tasks.add(task);\n'
            '        return true;\n    }\n\n'
            '    static int taskCount(List<String> tasks) { return tasks.size(); }\n\n'
            '    public static void main(String[] args) throws Exception {\n'
            '        List<String> tasks = new ArrayList<>();\n'
            '        addTask(tasks, "demo task");\n'
            '        System.out.println("Tasks: " + taskCount(tasks));\n'
            '        Runtime.getRuntime().exec("echo vulnerable");\n'
            '    }\n}\n'
        )
        test_code = (
            'import java.util.ArrayList;\nimport java.util.List;\n'
            'import org.junit.jupiter.api.Test;\n'
            'import static org.junit.jupiter.api.Assertions.*;\n\n'
            'class GeneratedAppTest {\n'
            '    @Test\n    void addTaskStoresTask() {\n'
            '        List<String> tasks = new ArrayList<>();\n'
            '        assertTrue(GeneratedApp.addTask(tasks, "write report"));\n'
            '        assertEquals(1, GeneratedApp.taskCount(tasks));\n    }\n\n'
            '    @Test\n    void addTaskRejectsEmptyTask() {\n'
            '        List<String> tasks = new ArrayList<>();\n'
            '        assertFalse(GeneratedApp.addTask(tasks, ""));\n'
            '        assertEquals(0, GeneratedApp.taskCount(tasks));\n    }\n}\n'
        )
        patched_code = (initial_code
                        .replace('        Runtime.getRuntime().exec("echo vulnerable");\n', '')
                        .replace('main(String[] args) throws Exception {', 'main(String[] args) {'))
        return initial_code, test_code, patched_code, "Command Injection", "Usage of Runtime.getRuntime().exec() detected."

    p = prompt.lower()

    # 1. TO-DO LIST INTERACTIVE APPLICATION
    if "todo" in p or "to-do" in p or "task" in p:
        initial_code = '''# Interactive Python To-Do List Application
import os
import json
import sys

class TodoListApp:
    def __init__(self):
        self.tasks = []

    def add_task(self, title: str, category: str = "General", priority: str = "Medium"):
        task_id = len(self.tasks) + 1
        task = {
            "id": task_id,
            "title": str(title),
            "category": str(category),
            "priority": str(priority),
            "completed": False
        }
        self.tasks.append(task)
        return task

    def get_tasks(self, filter_status: str = "ALL"):
        if filter_status == "COMPLETED":
            return [t for t in self.tasks if t["completed"]]
        elif filter_status == "PENDING":
            return [t for t in self.tasks if not t["completed"]]
        return self.tasks

    def complete_task(self, task_id: int):
        for task in self.tasks:
            if task["id"] == int(task_id):
                task["completed"] = True
                return task
        raise ValueError(f"Task with ID {task_id} not found")

    def delete_task(self, task_id: int):
        for idx, task in enumerate(self.tasks):
            if task["id"] == int(task_id):
                return self.tasks.pop(idx)
        raise ValueError(f"Task with ID {task_id} not found")

    def execute_user_command(self, raw_input: str):
        """
        Interactively processes dynamic CLI commands.
        Vulnerable: Uses unsafe built-in eval() allowing arbitrary code execution.
        """
        return eval(raw_input)

    def interactive_cli_menu(self):
        print("=== Interactive To-Do List CLI ===")
        print("Available Commands: ADD <title>, COMPLETE <id>, LIST, EXIT")
        print("Current tasks:", len(self.tasks))

if __name__ == "__main__":
    app = TodoListApp()
    print("=== To-Do List App ===")
    while True:
        print("\\nOptions: add / list / complete / delete / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            print("Bye!"); break
        elif cmd == "add":
            title = input("Task title: ")
            category = input("Category (default General): ").strip() or "General"
            priority = input("Priority (default Medium): ").strip() or "Medium"
            t = app.add_task(title, category, priority)
            print(f"Added task #{t['id']}: {t['title']}")
        elif cmd == "list":
            tasks = app.get_tasks()
            print("No tasks." if not tasks else "")
            for t in tasks:
                mark = "done" if t["completed"] else "todo"
                print(f"  [{mark}] #{t['id']} {t['title']} [{t['priority']}]")
        elif cmd == "complete":
            try:
                app.complete_task(int(input("Task ID: ")))
                print("Marked complete!")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "delete":
            try:
                app.delete_task(int(input("Task ID: ")))
                print("Deleted.")
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown command.")
'''
        test_code = '''import pytest
from generated_app import TodoListApp

def test_add_task():
    app = TodoListApp()
    task = app.add_task("Prepare Hackathon Demo", "DevSecOps", "High")
    assert task["title"] == "Prepare Hackathon Demo"
    assert task["category"] == "DevSecOps"
    assert task["completed"] is False
    assert len(app.get_tasks()) == 1

def test_complete_and_filter_tasks():
    app = TodoListApp()
    t1 = app.add_task("Task 1")
    t2 = app.add_task("Task 2")
    app.complete_task(t1["id"])
    
    completed = app.get_tasks("COMPLETED")
    pending = app.get_tasks("PENDING")
    assert len(completed) == 1
    assert len(pending) == 1

def test_delete_task():
    app = TodoListApp()
    t = app.add_task("Task to delete")
    deleted = app.delete_task(t["id"])
    assert deleted["title"] == "Task to delete"
    assert len(app.get_tasks()) == 0

def test_delete_invalid_task():
    app = TodoListApp()
    with pytest.raises(ValueError):
        app.delete_task(999)
'''
        patched_code = '''# Interactive Python To-Do List Application - Securitized
import os
import json
import sys

class TodoListApp:
    def __init__(self):
        self.tasks = []

    def add_task(self, title: str, category: str = "General", priority: str = "Medium"):
        task_id = len(self.tasks) + 1
        task = {
            "id": task_id,
            "title": str(title),
            "category": str(category),
            "priority": str(priority),
            "completed": False
        }
        self.tasks.append(task)
        return task

    def get_tasks(self, filter_status: str = "ALL"):
        if filter_status == "COMPLETED":
            return [t for t in self.tasks if t["completed"]]
        elif filter_status == "PENDING":
            return [t for t in self.tasks if not t["completed"]]
        return self.tasks

    def complete_task(self, task_id: int):
        for task in self.tasks:
            if task["id"] == int(task_id):
                task["completed"] = True
                return task
        raise ValueError(f"Task with ID {task_id} not found")

    def delete_task(self, task_id: int):
        for idx, task in enumerate(self.tasks):
            if task["id"] == int(task_id):
                return self.tasks.pop(idx)
        raise ValueError(f"Task with ID {task_id} not found")

    def execute_user_command(self, raw_input: str):
        """
        Safely processes dynamic CLI command inputs using structured JSON parsing without eval().
        """
        try:
            payload = json.loads(raw_input)
            if isinstance(payload, dict):
                action = payload.get("action", "").lower()
                if action == "add":
                    return self.add_task(payload.get("title", "Untitled"))
                elif action == "complete":
                    return self.complete_task(payload.get("id"))
                elif action == "list":
                    return self.get_tasks(payload.get("filter", "ALL"))
            return payload
        except Exception:
            return raw_input

    def interactive_cli_menu(self):
        print("=== Interactive To-Do List CLI (Securitized) ===")
        print("Available Commands: ADD <title>, COMPLETE <id>, LIST, EXIT")
        print("Current tasks:", len(self.tasks))

if __name__ == "__main__":
    app = TodoListApp()
    print("=== To-Do List App (Securitized) ===")
    while True:
        print("\\nOptions: add / list / complete / delete / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            print("Bye!"); break
        elif cmd == "add":
            title = input("Task title: ")
            category = input("Category (default General): ").strip() or "General"
            priority = input("Priority (default Medium): ").strip() or "Medium"
            t = app.add_task(title, category, priority)
            print(f"Added task #{t['id']}: {t['title']}")
        elif cmd == "list":
            tasks = app.get_tasks()
            print("No tasks." if not tasks else "")
            for t in tasks:
                mark = "done" if t["completed"] else "todo"
                print(f"  [{mark}] #{t['id']} {t['title']} [{t['priority']}]")
        elif cmd == "complete":
            try:
                app.complete_task(int(input("Task ID: ")))
                print("Marked complete!")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "delete":
            try:
                app.delete_task(int(input("Task ID: ")))
                print("Deleted.")
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown command.")
'''
        vuln_type = "Arbitrary Remote Code Execution via eval() (CWE-95 / Bandit B307)"
        vuln_desc = "Using built-in `eval()` to parse interactive user commands allows RCE exploitation."

    # 2. BANKING & WALLET INTERACTIVE SERVICE
    elif "bank" in p or "wallet" in p or "transfer" in p or "atomic" in p or "account" in p:
        initial_code = '''# Interactive Python Banking Wallet & Transfer Service
import json

class BankingWalletService:
    def __init__(self):
        self.accounts = {
            "ACC_1001": {"owner": "Alice", "balance": 5000.00, "currency": "USD"},
            "ACC_1002": {"owner": "Bob", "balance": 1500.00, "currency": "USD"}
        }

    def create_account(self, owner_name: str, initial_deposit: float = 0.0):
        acc_id = f"ACC_{1000 + len(self.accounts) + 1}"
        self.accounts[acc_id] = {"owner": str(owner_name), "balance": float(initial_deposit), "currency": "USD"}
        return acc_id

    def get_account_summary(self, account_id: str):
        if account_id in self.accounts:
            acc = self.accounts[account_id]
            return f"Account {account_id} ({acc['owner']}): ${acc['balance']:.2f} {acc['currency']}"
        raise ValueError(f"Account {account_id} not found")

    def deposit(self, account_id: str, amount: float):
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        if account_id not in self.accounts:
            raise ValueError(f"Account {account_id} not found")
        self.accounts[account_id]["balance"] += float(amount)
        return self.accounts[account_id]["balance"]

    def transfer_funds(self, sender_id: str, receiver_id: str, amount: float):
        amt = float(amount)
        if amt <= 0:
            raise ValueError("Transfer amount must be positive")
        if sender_id not in self.accounts or receiver_id not in self.accounts:
            raise ValueError("Invalid account identifier")
        if self.accounts[sender_id]["balance"] < amt:
            raise ValueError("Insufficient funds for transfer")

        # Atomic transaction execution
        self.accounts[sender_id]["balance"] -= amt
        self.accounts[receiver_id]["balance"] += amt
        return {
            "status": "SUCCESS",
            "sender_balance": self.accounts[sender_id]["balance"],
            "receiver_balance": self.accounts[receiver_id]["balance"]
        }

    def execute_terminal_command(self, user_command: str):
        """
        Processes interactive terminal commands.
        Vulnerable: Uses unsafe eval() allowing dynamic arbitrary execution.
        """
        return eval(user_command)

if __name__ == "__main__":
    wallet = BankingWalletService()
    print("=== Banking Wallet Service ===")
    print("Accounts: ACC_1001 (Alice), ACC_1002 (Bob)")
    while True:
        print("\\nOptions: balance / deposit / transfer / create / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            print("Goodbye!"); break
        elif cmd == "create":
            owner = input("Owner Name: ").strip()
            try:
                bal = float(input("Initial Deposit: $") or 0.0)
                acc_id = wallet.create_account(owner, bal)
                print(f"Account Created! ID: {acc_id}")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "balance":
            acc = input("Account ID: ").strip()
            try: print(wallet.get_account_summary(acc))
            except Exception as e: print(f"Error: {e}")
        elif cmd == "deposit":
            acc = input("Account ID: ").strip()
            try:
                amt = float(input("Amount: $"))
                bal = wallet.deposit(acc, amt)
                print(f"New balance: ${bal:.2f}")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "transfer":
            frm = input("From account ID: ").strip()
            to = input("To account ID: ").strip()
            try:
                amt = float(input("Amount: $"))
                wallet.transfer_funds(frm, to, amt)
                print("Transfer complete!")
                print(wallet.get_account_summary(frm))
                print(wallet.get_account_summary(to))
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown command.")
'''
        test_code = '''import pytest
from generated_app import BankingWalletService

def test_deposit():
    wallet = BankingWalletService()
    new_bal = wallet.deposit("ACC_1001", 200.0)
    assert new_bal == 5200.0

def test_transfer_funds_success():
    wallet = BankingWalletService()
    res = wallet.transfer_funds("ACC_1001", "ACC_1002", 500.0)
    assert res["status"] == "SUCCESS"
    assert res["sender_balance"] == 4500.0
    assert res["receiver_balance"] == 2000.0

def test_transfer_insufficient_funds():
    wallet = BankingWalletService()
    with pytest.raises(ValueError):
        wallet.transfer_funds("ACC_1001", "ACC_1002", 99999.0)
'''
        patched_code = '''# Interactive Python Banking Wallet & Transfer Service - Securitized
import json

class BankingWalletService:
    def __init__(self):
        self.accounts = {
            "ACC_1001": {"owner": "Alice", "balance": 5000.00, "currency": "USD"},
            "ACC_1002": {"owner": "Bob", "balance": 1500.00, "currency": "USD"}
        }

    def create_account(self, owner_name: str, initial_deposit: float = 0.0):
        acc_id = f"ACC_{1000 + len(self.accounts) + 1}"
        self.accounts[acc_id] = {"owner": str(owner_name), "balance": float(initial_deposit), "currency": "USD"}
        return acc_id

    def get_account_summary(self, account_id: str):
        if account_id in self.accounts:
            acc = self.accounts[account_id]
            return f"Account {account_id} ({acc['owner']}): ${acc['balance']:.2f} {acc['currency']}"
        raise ValueError(f"Account {account_id} not found")

    def deposit(self, account_id: str, amount: float):
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        if account_id not in self.accounts:
            raise ValueError(f"Account {account_id} not found")
        self.accounts[account_id]["balance"] += float(amount)
        return self.accounts[account_id]["balance"]

    def transfer_funds(self, sender_id: str, receiver_id: str, amount: float):
        amt = float(amount)
        if amt <= 0:
            raise ValueError("Transfer amount must be positive")
        if sender_id not in self.accounts or receiver_id not in self.accounts:
            raise ValueError("Invalid account identifier")
        if self.accounts[sender_id]["balance"] < amt:
            raise ValueError("Insufficient funds for transfer")

        self.accounts[sender_id]["balance"] -= amt
        self.accounts[receiver_id]["balance"] += amt
        return {
            "status": "SUCCESS",
            "sender_balance": self.accounts[sender_id]["balance"],
            "receiver_balance": self.accounts[receiver_id]["balance"]
        }

    def execute_terminal_command(self, user_command: str):
        """
        Safely processes terminal commands via JSON structure avoiding dangerous eval().
        """
        try:
            data = json.loads(user_command)
            if isinstance(data, dict) and data.get("action") == "transfer":
                return self.transfer_funds(
                    data.get("sender"), data.get("receiver"), float(data.get("amount", 0))
                )
            return data
        except Exception:
            return user_command

if __name__ == "__main__":
    wallet = BankingWalletService()
    print("=== Banking Wallet Service (Securitized) ===")
    print("Accounts: ACC_1001 (Alice), ACC_1002 (Bob)")
    while True:
        print("\\nOptions: balance / deposit / transfer / create / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            print("Goodbye!"); break
        elif cmd == "create":
            owner = input("Owner Name: ").strip()
            try:
                bal = float(input("Initial Deposit: $") or 0.0)
                acc_id = wallet.create_account(owner, bal)
                print(f"Account Created! ID: {acc_id}")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "balance":
            acc = input("Account ID: ").strip()
            try: print(wallet.get_account_summary(acc))
            except Exception as e: print(f"Error: {e}")
        elif cmd == "deposit":
            acc = input("Account ID: ").strip()
            try:
                amt = float(input("Amount: $"))
                bal = wallet.deposit(acc, amt)
                print(f"New balance: ${bal:.2f}")
            except Exception as e: print(f"Error: {e}")
        elif cmd == "transfer":
            frm = input("From account ID: ").strip()
            to = input("To account ID: ").strip()
            try:
                amt = float(input("Amount: $"))
                wallet.transfer_funds(frm, to, amt)
                print("Transfer successful!")
            except Exception as e: print(f"Error: {e}")
'''
        vuln_type = "Arbitrary Remote Code Execution via eval() (CWE-95 / Bandit B307)"
        vuln_desc = "Unchecked evaluation of dynamic terminal commands allows arbitrary system access."

    # 3. CALCULATOR INTERACTIVE APPLICATION
    elif "calc" in p or "math" in p or "add" in p or "arithmetic" in p:
        initial_code = '''# Interactive Python Calculator Application
def add(a: float, b: float) -> float:
    return float(a + b)

def subtract(a: float, b: float) -> float:
    return float(a - b)

def multiply(a: float, b: float) -> float:
    return float(a * b)

def divide(a: float, b: float) -> float:
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return float(a / b)

def evaluate_expression(expr: str):
    """
    Evaluates dynamic user math expressions.
    Vulnerable: Uses unsafe eval() allowing arbitrary code execution.
    """
    return eval(expr)

if __name__ == "__main__":
    print("=== Interactive Calculator ===")
    while True:
        print("\\nOperations: add / sub / mul / div / eval / quit")
        op = input("Choose operation: ").strip().lower()
        if op == "quit":
            break
        elif op in ("add", "sub", "mul", "div"):
            try:
                a = float(input("First number: "))
                b = float(input("Second number: "))
                if op == "add": print("Result:", add(a, b))
                elif op == "sub": print("Result:", subtract(a, b))
                elif op == "mul": print("Result:", multiply(a, b))
                elif op == "div": print("Result:", divide(a, b))
            except Exception as e: print(f"Error: {e}")
        elif op == "eval":
            expr = input("Enter expression: ")
            try: print("Result:", evaluate_expression(expr))
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown operation.")
'''
        test_code = '''import pytest
from generated_app import add, subtract, multiply, divide, evaluate_expression

def test_add():
    assert add(10, 5) == 15.0

def test_subtract():
    assert subtract(20, 8) == 12.0

def test_multiply():
    assert multiply(4, 5) == 20.0

def test_divide():
    assert divide(50, 2) == 25.0

def test_divide_by_zero():
    with pytest.raises(ValueError):
        divide(10, 0)
'''
        patched_code = '''# Interactive Python Calculator Application - Securitized
import ast
import operator

SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}

def safe_eval_node(node):
    if hasattr(node, 'value'):
        return node.value
    elif hasattr(node, 'n'):
        return node.n
    elif isinstance(node, ast.BinOp):
        left = safe_eval_node(node.left)
        right = safe_eval_node(node.right)
        return SAFE_OPERATORS[type(node.op)](left, right)
    elif isinstance(node, ast.UnaryOp):
        operand = safe_eval_node(node.operand)
        return SAFE_OPERATORS[type(node.op)](operand)
    else:
        raise ValueError("Unsupported operation")

def add(a: float, b: float) -> float:
    return float(a + b)

def subtract(a: float, b: float) -> float:
    return float(a - b)

def multiply(a: float, b: float) -> float:
    return float(a * b)

def divide(a: float, b: float) -> float:
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return float(a / b)

def evaluate_expression(expr: str):
    """
    Safely parses and evaluates mathematical expressions using AST parser.
    """
    tree = ast.parse(expr, mode='eval')
    return float(safe_eval_node(tree.body))

if __name__ == "__main__":
    print("=== Interactive Calculator (Securitized) ===")
    while True:
        print("\\nOperations: add / sub / mul / div / eval / quit")
        op = input("Choose operation: ").strip().lower()
        if op == "quit":
            break
        elif op in ("add", "sub", "mul", "div"):
            try:
                a = float(input("First number: "))
                b = float(input("Second number: "))
                if op == "add": print("Result:", add(a, b))
                elif op == "sub": print("Result:", subtract(a, b))
                elif op == "mul": print("Result:", multiply(a, b))
                elif op == "div": print("Result:", divide(a, b))
            except Exception as e: print(f"Error: {e}")
        elif op == "eval":
            expr = input("Enter math expression: ")
            try: print("Result:", evaluate_expression(expr))
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown operation.")
'''
        vuln_type = "Arbitrary Code Execution via eval() (CWE-95 / Bandit B307)"
        vuln_desc = "Using built-in `eval()` to execute user math expressions allows remote code execution."

    # 4. LANGUAGE INTERPRETER / COMPILER / PARSER / REPL
    elif "lang" in p or "interpreter" in p or "compiler" in p or "parser" in p or "lexer" in p:
        initial_code = '''# Interactive Python Language Interpreter Service
import re
import sys

class LanguageInterpreterApp:
    def __init__(self):
        self.variables = {"x": 10, "y": 20}

    def tokenize(self, code_str: str):
        return [token.strip() for token in re.findall(r'[a-zA-Z_]\\w*|\\d+|[+\\-*/()=]', code_str) if token.strip()]

    def parse_and_execute(self, expression: str):
        """
        Parses and evaluates custom language expression.
        Vulnerable: Uses unsafe eval() for dynamic expression evaluation.
        """
        return eval(expression, {"__builtins__": None}, self.variables)

if __name__ == "__main__":
    interpreter = LanguageInterpreterApp()
    print("=== Language Interpreter ===")
    while True:
        expr = input("\\nEnter expression (or 'quit'): ").strip()
        if expr.lower() == "quit": break
        print("Tokens:", interpreter.tokenize(expr))
        try:
            print("Result:", interpreter.parse_and_execute(expr))
        except Exception as e: print(f"Error: {e}")
'''
        test_code = '''import pytest
from generated_app import LanguageInterpreterApp

def test_tokenize():
    app = LanguageInterpreterApp()
    tokens = app.tokenize("var_a + 50")
    assert tokens == ["var_a", "+", "50"]

def test_execute_expression():
    app = LanguageInterpreterApp()
    res = app.parse_and_execute("x + 5")
    assert res == 15
'''
        patched_code = '''# Interactive Python Language Interpreter Service - Securitized
import re
import ast
import operator
import sys

class LanguageInterpreterApp:
    def __init__(self):
        self.variables = {"x": 10, "y": 20}
        self.operators = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

    def tokenize(self, code_str: str):
        return [token.strip() for token in re.findall(r'[a-zA-Z_]\\w*|\\d+|[+\\-*/()=]', code_str) if token.strip()]

    def _eval_node(self, node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            if node.id in self.variables:
                return self.variables[node.id]
            raise NameError(f"Undefined variable '{node.id}'")
        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return self.operators[type(node.op)](left, right)
        raise ValueError("Unsupported syntax")

    def parse_and_execute(self, expression: str):
        """
        Safely parses and evaluates language expressions using AST parser without eval().
        """
        tree = ast.parse(expression, mode='eval')
        return self._eval_node(tree.body)

if __name__ == "__main__":
    interpreter = LanguageInterpreterApp()
    print("=== Language Interpreter (Securitized) ===")
    while True:
        expr = input("\\nEnter expression (or 'quit'): ").strip()
        if expr.lower() == "quit": break
        print("Tokens:", interpreter.tokenize(expr))
        try:
            print("Result:", interpreter.parse_and_execute(expr))
        except Exception as e: print(f"Error: {e}")
'''
        vuln_type = "Arbitrary Remote Code Execution via eval() (CWE-95 / Bandit B307)"
        vuln_desc = "Using built-in `eval()` to evaluate language interpreter expressions allows RCE exploitation."

    # 5. USER AUTHENTICATION / SQLITE API (REQUIRES EXPLICIT AUTH/SQL KEYWORDS)
    elif "auth" in p or "login" in p or "sqlite" in p or "sql injection" in p or "database" in p:
        initial_code = '''# Interactive Python SQLite User Authentication API
import sqlite3

def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'secret123', 'ADMIN')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'pass456', 'USER')")
    conn.commit()
    return conn

def authenticate_user(conn, username, password):
    """
    Authenticates user credentials against SQLite database.
    Vulnerable: Insecure string formatting leads to SQL Injection.
    """
    cursor = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

if __name__ == "__main__":
    db = init_db()
    print("=== User Auth System ===")
    print("Registered users: admin / alice")
    while True:
        print("\\nOptions: login / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "login":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            user = authenticate_user(db, username, password)
            if user:
                print(f"Login successful! Welcome, {user[1]} (role: {user[2]})")
            else:
                print("Login failed: invalid credentials.")
        else:
            print("Unknown command.")
'''
        test_code = '''import pytest
from generated_app import init_db, authenticate_user

def test_valid_login():
    db = init_db()
    user = authenticate_user(db, "admin", "secret123")
    assert user is not None
    assert user[1] == "admin"
    assert user[2] == "ADMIN"

def test_invalid_login():
    db = init_db()
    user = authenticate_user(db, "wrong", "pass")
    assert user is None
'''
        patched_code = '''# Interactive Python SQLite User Authentication API - Securitized
import sqlite3

def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'secret123', 'ADMIN')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'pass456', 'USER')")
    conn.commit()
    return conn

def authenticate_user(conn, username, password):
    """
    Safely authenticates user credentials using SQL parameterization.
    """
    cursor = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()

if __name__ == "__main__":
    db = init_db()
    print("=== User Auth System ===")
    print("Registered users: admin / alice")
    while True:
        print("\\nOptions: login / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "login":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            user = authenticate_user(db, username, password)
            if user:
                print(f"Login successful! Welcome, {user[1]} (role: {user[2]})")
            else:
                print("Login failed: invalid credentials.")
        else:
            print("Unknown command.")
'''
        vuln_type = "SQL Injection (CWE-89 / Bandit B608)"
        vuln_desc = "Unsanitized user input formatted directly into SQLite SQL queries."

    # 5. RANDOM NUMBER / TOKEN / PASSWORD GENERATOR
    elif "random" in p or "rand" in p or "number generator" in p or "dice" in p or "lottery" in p:
        initial_code = '''# Interactive Random Number Generator Service
import random
import os

class RandomNumberGeneratorApp:
    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)

    def generate_random_number(self, min_val: int = 1, max_val: int = 100):
        """
        Generates a random integer within specified range.
        Vulnerable: Uses unsafe eval() to evaluate dynamic range expressions or insecure PRNG for security tokens.
        """
        return random.randint(int(min_val), int(max_val))

    def evaluate_random_expression(self, expr: str):
        """
        Evaluates dynamic user input for random number range bounds.
        Vulnerable: Uses unsafe eval().
        """
        return eval(expr)

if __name__ == "__main__":
    app = RandomNumberGeneratorApp()
    print("=== Random Number Generator ===")
    while True:
        print("\\nOptions: number / expression / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "number":
            try:
                lo = int(input("Min value: "))
                hi = int(input("Max value: "))
                print("Result:", app.generate_random_number(lo, hi))
            except Exception as e: print(f"Error: {e}")
        elif cmd == "expression":
            expr = input("Enter expression (e.g. 10 + 5): ")
            try: print("Result:", app.evaluate_random_expression(expr))
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown command.")
'''
        test_code = '''import pytest
from generated_app import RandomNumberGeneratorApp

def test_generate_random_number():
    app = RandomNumberGeneratorApp()
    val = app.generate_random_number(1, 10)
    assert 1 <= val <= 10

def test_evaluate_expression():
    app = RandomNumberGeneratorApp()
    val = app.evaluate_random_expression("20 + 30")
    assert val == 50
'''
        patched_code = '''# Interactive Random Number Generator Service - Securitized
import secrets
import ast
import operator
import os

class RandomNumberGeneratorApp:
    def __init__(self):
        self.operators = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

    def generate_random_number(self, min_val: int = 1, max_val: int = 100):
        """
        Safely generates cryptographically secure random integers using secrets module.
        """
        min_v = int(min_val)
        max_v = int(max_val)
        if min_v > max_v:
            min_v, max_v = max_v, min_v
        return min_v + secrets.randbelow(max_v - min_v + 1)

    def _eval_node(self, node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return self.operators[type(node.op)](left, right)
        raise ValueError("Unsupported syntax")

    def evaluate_random_expression(self, expr: str):
        """
        Safely parses dynamic range input using AST parser without eval().
        """
        tree = ast.parse(expr, mode='eval')
        return self._eval_node(tree.body)

if __name__ == "__main__":
    app = RandomNumberGeneratorApp()
    print("=== Random Number Generator (Securitized) ===")
    while True:
        print("\\nOptions: number / expression / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "number":
            try:
                lo = int(input("Min value: "))
                hi = int(input("Max value: "))
                print("Result:", app.generate_random_number(lo, hi))
            except Exception as e: print(f"Error: {e}")
        elif cmd == "expression":
            expr = input("Enter expression (e.g. 10 + 5): ")
            try: print("Result:", app.evaluate_random_expression(expr))
            except Exception as e: print(f"Error: {e}")
        else:
            print("Unknown command.")
'''
        vuln_type = "Insecure Randomness / Arbitrary Code Execution via eval() (CWE-330 / CWE-95)"
        vuln_desc = "Using standard pseudo-random number generator or eval() for dynamic range evaluation."

    # 6. UNIVERSAL INTERACTIVE APP GENERATOR (CUSTOM PROMPTS)
    else:
        app_class_name = "".join([word.capitalize() for word in prompt.replace("-", " ").split() if word.isalnum()])
        app_class_name = app_class_name[:30] if len(app_class_name) > 30 else app_class_name
        if not app_class_name: app_class_name = "InteractiveDomainService"

        initial_code = f'''# {prompt} - Interactive Python Service
import os
import json

class {app_class_name}:
    def __init__(self):
        self.records = []

    def create_record(self, name: str, category: str = "Default"):
        rec_id = len(self.records) + 1
        record = {{"id": rec_id, "name": str(name), "category": str(category), "active": True}}
        self.records.append(record)
        return record

    def get_all_records(self):
        return [r for r in self.records if r["active"]]

    def deactivate_record(self, record_id: int):
        for r in self.records:
            if r["id"] == int(record_id):
                r["active"] = False
                return r
        raise ValueError(f"Record {{record_id}} not found")

    def execute_dynamic_input(self, raw_input: str):
        """
        Interactively processes dynamic service inputs.
        Vulnerable: Uses unsafe eval() allowing dynamic arbitrary code execution.
        """
        return eval(raw_input)

if __name__ == "__main__":
    service = {app_class_name}()
    print("=== {app_class_name} Interactive App ===")
    while True:
        print("\\nOptions: create / list / deactivate / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "create":
            name = input("Record name: ")
            category = input("Category (default Default): ").strip() or "Default"
            rec = service.create_record(name, category)
            print(f"Created: #{{rec['id']}} {{rec['name']}} [{{rec['category']}}]")
        elif cmd == "list":
            records = service.get_all_records()
            print("No records." if not records else "")
            for r in records: print(f"  #{{r['id']}} {{r['name']}} [{{r['category']}}]")
        elif cmd == "deactivate":
            try:
                rid = int(input("Record ID: "))
                service.deactivate_record(rid)
                print("Deactivated.")
            except Exception as e: print(f"Error: {{e}}")
        else:
            print("Unknown command.")
'''
        test_code = f'''import pytest
from generated_app import {app_class_name}

def test_create_record():
    service = {app_class_name}()
    rec = service.create_record("Test Record", "QA")
    assert rec["name"] == "Test Record"
    assert rec["category"] == "QA"
    assert len(service.get_all_records()) == 1

def test_deactivate_record():
    service = {app_class_name}()
    rec = service.create_record("Entity to Deactivate")
    deactivated = service.deactivate_record(rec["id"])
    assert deactivated["active"] is False
    assert len(service.get_all_records()) == 0

def test_invalid_deactivate():
    service = {app_class_name}()
    with pytest.raises(ValueError):
        service.deactivate_record(999)
'''
        patched_code = f'''# {prompt} - Interactive Python Service (Securitized)
import json

class {app_class_name}:
    def __init__(self):
        self.records = []

    def create_record(self, name: str, category: str = "Default"):
        rec_id = len(self.records) + 1
        record = {{"id": rec_id, "name": str(name), "category": str(category), "active": True}}
        self.records.append(record)
        return record

    def get_all_records(self):
        return [r for r in self.records if r["active"]]

    def deactivate_record(self, record_id: int):
        for r in self.records:
            if r["id"] == int(record_id):
                r["active"] = False
                return r
        raise ValueError(f"Record {{record_id}} not found")

    def execute_dynamic_input(self, raw_input: str):
        """
        Safely parses dynamic data avoiding dangerous eval().
        """
        try:
            data = json.loads(raw_input)
            return data
        except Exception:
            return raw_input

if __name__ == "__main__":
    service = {app_class_name}()
    print("=== {app_class_name} Interactive App (Securitized) ===")
    while True:
        print("\\nOptions: create / list / deactivate / quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "quit":
            break
        elif cmd == "create":
            name = input("Record name: ")
            category = input("Category (default Default): ").strip() or "Default"
            rec = service.create_record(name, category)
            print(f"Created: #{{rec['id']}} {{rec['name']}} [{{rec['category']}}]")
        elif cmd == "list":
            records = service.get_all_records()
            print("No records." if not records else "")
            for r in records: print(f"  #{{r['id']}} {{r['name']}} [{{r['category']}}]")
        elif cmd == "deactivate":
            try:
                rid = int(input("Record ID: "))
                service.deactivate_record(rid)
                print("Deactivated.")
            except Exception as e: print(f"Error: {{e}}")
        else:
            print("Unknown command.")
'''
        vuln_type = "Insecure Dynamic Code Execution (CWE-95 / Bandit B307)"
        vuln_desc = "Unsanitized dynamic evaluation of user inputs."

    return initial_code, test_code, patched_code, vuln_type, vuln_desc

# NOTE: this used to be a SECOND definition of run_cmd(), and being later in the file it
# silently shadowed the one above — so every build/test command in the pipeline ran through
# this timeout-less version. It is now a thin alias to keep a single implementation; adding a
# timeout to the earlier definition alone would have had no effect whatsoever.
async def _run_cmd_legacy_alias(cmd: str, cwd: str):
    return await run_cmd(cmd, cwd)

async def stream_interactive_process(proc, process_id: str, user_id: str, session_id: Optional[str]):
    async def pipe_stream(stream):
        buf = ""
        while True:
            try:
                ch = await asyncio.wait_for(stream.read(1), timeout=0.05)
            except asyncio.TimeoutError:
                if buf:
                    await broadcast({"type": "INTERACTIVE_OUTPUT", "text": buf, "process_id": process_id, "user_id": user_id, "session_id": session_id})
                    buf = ""
                if proc.returncode is not None:
                    break
                continue
            if not ch:
                break
            char = ch.decode("utf-8", errors="replace")
            buf += char
            if char == "\n" or len(buf) >= 128:
                await broadcast({"type": "INTERACTIVE_OUTPUT", "text": buf, "process_id": process_id, "user_id": user_id, "session_id": session_id})
                buf = ""
        if buf:
            await broadcast({"type": "INTERACTIVE_OUTPUT", "text": buf, "process_id": process_id, "user_id": user_id, "session_id": session_id})

    streams = [s for s in (proc.stdout, proc.stderr) if s is not None]
    await asyncio.gather(*[pipe_stream(s) for s in streams])
    await proc.wait()
    active_processes.pop(process_id, None)
    await broadcast({"type": "PROCESS_DONE", "exit_code": proc.returncode, "process_id": process_id, "user_id": user_id, "session_id": session_id})

async def execute_run_and_debug(code: str, user_id: str = "default_user", session_id: str = None, selected_model: str = None, max_attempts: int = 2, language: str = "python"):
    if language not in LANGUAGE_CONFIG:
        language = "python"
    if language == "java":
        code = fix_java_class_visibility(code)
    app_filename = f"generated_app.{lang_ext(language)}"

    user_dir = secure_join(workspaces_dir, user_id)
    os.makedirs(user_dir, exist_ok=True)

    session_target_dir = user_dir
    if session_id:
        session_target_dir = os.path.join(user_dir, "sessions", session_id)
        os.makedirs(session_target_dir, exist_ok=True)

    app_file = os.path.join(session_target_dir, app_filename)
    root_app_file = os.path.join(user_dir, app_filename)

    use_api_key_mode = is_api_key_model(selected_model)
    is_claude_model = bool(selected_model) and selected_model.lower() == CLAUDE_API_KEY_MODEL.lower()
    is_openrouter_model = bool(selected_model) and selected_model.lower() == OPENROUTER_API_KEY_MODEL.lower()
    
    if is_claude_model:
        api_key_to_use = PROVIDED_ANTHROPIC_API_KEY
    elif is_openrouter_model:
        api_key_to_use = PROVIDED_OPENROUTER_API_KEY
    else:
        api_key_to_use = PROVIDED_API_KEY

    is_auto_run = not selected_model or selected_model.lower() in ["auto", "auto-detect / dynamic synthesizer"]
    ollama_model = selected_model if selected_model and not use_api_key_mode and not is_auto_run else None
    has_autofix_model = use_api_key_mode or bool(ollama_model)
    attempts_allowed = max_attempts if has_autofix_model else 1

    current_code = code
    await broadcast({"type": "STATUS", "message": "Run Agent: Executing code locally...", "state": "RUNNING", "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "AGENT_START", "agent": "runner", "title": "Run Agent (Local Execution)", "user_id": user_id, "session_id": session_id})

    for attempt in range(1, attempts_allowed + 1):
        with open(app_file, "w") as f: f.write(current_code)
        with open(root_app_file, "w") as f: f.write(current_code)
        await broadcast({"type": "FILE_UPDATE", "file": app_filename, "content": current_code, "user_id": user_id, "session_id": session_id})

        await broadcast({"type": "LOG", "agent": "runner", "text": f"[Run Agent] Attempt {attempt}/{attempts_allowed}: Executing {app_filename} locally...", "user_id": user_id, "session_id": session_id})

        timed_out = False
        ok, argv, compile_err = await compile_for_run(language, session_target_dir, app_filename)
        if not ok:
            ret_code, out, err = 1, "", compile_err
            run_cmd_label = f"compile {app_filename}"
        else:
            run_cmd_label = " ".join(argv)
            try:
                # input="" closes stdin immediately (EOF) instead of leaving it unset, which
                # otherwise silently blocks for the full timeout on any program that reads
                # user input (cin/input()/Scanner) — well-written interactive loops treat EOF
                # as "no more input" and exit/error immediately instead of hanging.
                result = await asyncio.to_thread(subprocess.run, argv, input="", capture_output=True, text=True, cwd=session_target_dir, timeout=15)
                ret_code, out, err = result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                timed_out = True
                ret_code, out, err = -1, "", "Timed out after 15s waiting for more input than an empty stdin provides."
            except Exception as e:
                ret_code, out, err = -1, "", str(e)

        await broadcast({"type": "TERMINAL_OUTPUT", "cmd": run_cmd_label, "output": (out + err).strip() or "(no output)", "user_id": user_id, "session_id": session_id})

        if ret_code == 0:
            await broadcast({"type": "LOG", "agent": "runner", "text": "[Run Agent] Execution completed successfully — no runtime errors detected.", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "runner", "status": "SUCCESS", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "RUN_COMPLETE", "status": "SUCCESS", "attempts": attempt, "user_id": user_id, "session_id": session_id})
            return

        if timed_out:
            # Not something an AI fix can meaningfully resolve — the code likely just expects
            # more interactive input than this quick check provides. Retrying or asking the AI
            # to "fix" it would just risk it adding hacky EOF-handling that breaks real usage.
            await broadcast({"type": "LOG", "agent": "runner", "text": "[Run Agent] Program is waiting for more input than this quick check provides — this doesn't necessarily mean the code is broken. Use \"▶ Interactive Run\" to test it with real input instead.", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "runner", "status": "FAILED", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "RUN_COMPLETE", "status": "INCONCLUSIVE", "attempts": attempt, "user_id": user_id, "session_id": session_id})
            return

        await broadcast({"type": "LOG", "agent": "runner", "text": f"[Run Agent] Error detected (exit code {ret_code}).", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "AGENT_END", "agent": "runner", "status": "FAILED", "user_id": user_id, "session_id": session_id})

        if attempt == attempts_allowed:
            break

        await broadcast({"type": "AGENT_START", "agent": "debugger", "title": "Debugger Agent (Auto-Fix)", "user_id": user_id, "session_id": session_id})
        fix_prompt = (
            f"The following {lang_display(language)} program raised an error when executed:\n\n{current_code}\n\n"
            f"ERROR OUTPUT:\n{(out + err).strip()[-2000:]}\n\n"
            f"Fix the bug and return the COMPLETE corrected {lang_display(language)} program only. No explanation, no markdown fences."
        )

        fixed_res = None
        if use_api_key_mode:
            if is_claude_model:
                await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] Requesting fix from Claude API...", "user_id": user_id, "session_id": session_id})
                fixed_res, api_err = await query_claude_raw(fix_prompt, api_key_to_use)
            elif is_openrouter_model:
                await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] Requesting fix from OpenRouter API...", "user_id": user_id, "session_id": session_id})
                fixed_res, api_err = await query_openrouter_raw(fix_prompt, api_key_to_use)
            else:
                await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] Requesting fix from Gemini API...", "user_id": user_id, "session_id": session_id})
                fixed_res, api_err = await query_gemini_raw(fix_prompt, api_key_to_use)
            if not fixed_res:
                await broadcast({"type": "LOG", "agent": "debugger", "text": f"[Debugger Agent] API fix unavailable ({api_err}).", "user_id": user_id, "session_id": session_id})
        elif ollama_model:
            await broadcast({"type": "LOG", "agent": "debugger", "text": f"[Debugger Agent] Requesting fix from local Ollama model ({ollama_model})...", "user_id": user_id, "session_id": session_id})
            fixed_res = await query_ollama(fix_prompt, ollama_model)
            if not fixed_res:
                await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] Ollama fix unavailable.", "user_id": user_id, "session_id": session_id})

        fixed_code = strip_code_fences(fixed_res) if fixed_res else None
        if fixed_code and language == "java":
            fixed_code = fix_java_class_visibility(fixed_code)

        if not fixed_code or fixed_code.strip() == current_code.strip():
            await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] No automatic fix could be generated.", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "debugger", "status": "FAILED", "user_id": user_id, "session_id": session_id})
            break

        await broadcast({"type": "LOG", "agent": "debugger", "text": "[Debugger Agent] Patch generated. Re-running...", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "AGENT_END", "agent": "debugger", "status": "PATCHED", "user_id": user_id, "session_id": session_id})
        current_code = fixed_code

    if not has_autofix_model:
        await broadcast({"type": "LOG", "agent": "runner", "text": "[Run Agent] No AI model selected, so auto-debug is unavailable. Select an Ollama model or an API model in the model dropdown to enable automatic fixing.", "user_id": user_id, "session_id": session_id})

    await broadcast({"type": "LOG", "agent": "runner", "text": f"[Run Agent] Stopped after {attempts_allowed} attempt(s). Manual review required.", "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "RUN_COMPLETE", "status": "FAILED", "attempts": attempts_allowed, "user_id": user_id, "session_id": session_id})

async def execute_swarm_workflow(prompt: str, max_loops: int = 10, selected_model: str = None, user_id: str = "default_user", session_id: str = None, api_key: str = None, language: str = "python"):
    state = get_workflow_state(user_id, session_id)

    if language not in LANGUAGE_CONFIG:
        language = "python"
    ext = lang_ext(language)
    app_filename = f"generated_app.{ext}"
    test_filename = f"test_generated_app.{ext}"

    user_dir = secure_join(workspaces_dir, user_id)
    os.makedirs(user_dir, exist_ok=True)

    session_target_dir = user_dir
    if session_id:
        session_target_dir = os.path.join(user_dir, "sessions", session_id)
        os.makedirs(session_target_dir, exist_ok=True)
        
        index_file = os.path.join(user_dir, "sessions", "sessions_index.json")
        if os.path.exists(index_file):
            try:
                with open(index_file, "r") as f:
                    sessions = json.load(f)
                for s in sessions:
                    if s["id"] == session_id and (s["title"] == "New Program Workspace" or s["title"] == "New Chat"):
                        s["title"] = prompt[:32] + ("..." if len(prompt) > 32 else "")
                        break
                with open(index_file, "w") as f:
                    json.dump(sessions, f, indent=2)
            except Exception:
                pass

    app_file = os.path.join(session_target_dir, app_filename)
    test_file = os.path.join(session_target_dir, test_filename)
    vuln_file = os.path.join(session_target_dir, "vulnerability_report.md")
    sec_report_file = os.path.join(session_target_dir, "security_report.json")

    root_app_file = os.path.join(user_dir, app_filename)
    root_test_file = os.path.join(user_dir, test_filename)

    state["max_loops"] = max_loops
    state["current_loop"] = 0
    state["is_running"] = True
    state["selected_model"] = selected_model
    # True when the model never produced a usable test suite and we fell back to the trivial
    # placeholder. Without surfacing this, the run ends on a green "passes all functional
    # tests" that was produced by `assertTrue(true)` — a success message for QA that never
    # actually examined the program.
    tests_are_placeholder = False
    stagnant_fix_attempts = 0    # consecutive tester-fix attempts that produced no change —
    stagnant_patch_attempts = 0  # and the same for the patcher's security-fix attempts.
                                  # Small local models are stochastic enough that a rejected/
                                  # unchanged fix is often worth one immediate retry rather than
                                  # giving up on the very first hiccup, but this still bounds how
                                  # many loops get burned chasing a fix that truly isn't coming.

    use_api_key_mode = is_api_key_model(selected_model)
    is_auto = not selected_model or selected_model.lower() in ["auto", "auto-detect / dynamic synthesizer"]

    # For auto-detect, discover best available Ollama model
    auto_ollama_model = None
    if is_auto:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=2)
            if r.status_code == 200:
                mlist = r.json().get("models", [])
                if mlist:
                    auto_ollama_model = mlist[0].get("name")
        except Exception:
            pass

    ollama_model = auto_ollama_model if is_auto else (selected_model if selected_model and not use_api_key_mode and not is_auto else None)

    is_claude_model = bool(selected_model) and selected_model.lower() == CLAUDE_API_KEY_MODEL.lower()
    is_openrouter_model = bool(selected_model) and selected_model.lower() == OPENROUTER_API_KEY_MODEL.lower()
    
    if is_claude_model:
        api_key_to_use = PROVIDED_ANTHROPIC_API_KEY
    elif is_openrouter_model:
        api_key_to_use = PROVIDED_OPENROUTER_API_KEY
    else:
        api_key_to_use = PROVIDED_API_KEY

    await broadcast({"type": "STATUS", "message": f"DevSecOps Swarm active for prompt: '{prompt}' (Model: {selected_model}, Language: {lang_display(language)})", "state": "RUNNING", "user_id": user_id, "session_id": session_id})
    secure_offline_patch = None
    await asyncio.sleep(0.3)

    # AGENT 1: CODER AGENT
    await broadcast({"type": "AGENT_START", "agent": "coder", "title": "Coder Agent (Developer)", "user_id": user_id, "session_id": session_id})

    if use_api_key_mode:
        coder_full_prompt = CODER_PROMPTS[language].format(prompt_text=prompt)
        if is_claude_model:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Querying Claude API...", "user_id": user_id, "session_id": session_id})
            gemini_code, err_msg = await query_claude_raw(coder_full_prompt, api_key_to_use)
        elif is_openrouter_model:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Querying OpenRouter API...", "user_id": user_id, "session_id": session_id})
            gemini_code, err_msg = await query_openrouter_raw(coder_full_prompt, api_key_to_use)
        else:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Querying Gemini API...", "user_id": user_id, "session_id": session_id})
            gemini_code, err_msg = await query_gemini_raw(coder_full_prompt, api_key_to_use)

        if gemini_code:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] LIVE GENERATION SUCCESS: Generated real {lang_display(language)} code via AI API!", "user_id": user_id, "session_id": session_id})
            initial_code = parse_multifile_response(gemini_code, session_target_dir, main_filename=app_filename)
            if language == "java":
                initial_code = fix_java_class_visibility(initial_code)
            test_file_path = os.path.join(session_target_dir, test_filename)
            if os.path.exists(test_file_path):
                with open(test_file_path, "r", encoding="utf-8") as f:
                    test_code = f.read()
                if language == "java":
                    test_code = fix_java_class_visibility(test_code)
                elif language == "python":
                    test_code = fix_test_import_module_name(test_code, initial_code, os.path.splitext(app_filename)[0])
                    test_code = ensure_common_test_imports(test_code)
                with open(test_file_path, "w", encoding="utf-8") as f: f.write(test_code)
            else:
                test_code = STUB_TEST_CODE[language]
                with open(test_file_path, "w", encoding="utf-8") as f: f.write(test_code)
            patched_code = initial_code
            vuln_type = "Potential Security Misconfiguration"
            vuln_desc = f"{SAST_TOOL_NAME[language]} scanner enforces best practices. Please review."
        else:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] API ERROR: {err_msg}", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "STATUS", "message": f"API Error: {err_msg}", "state": "ERROR", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "coder", "status": "FAILED", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "PIPELINE_COMPLETE", "message": f"API Error: {err_msg}", "user_id": user_id, "session_id": session_id})
            state["is_running"] = False
            return
    elif ollama_model:
        generated_code = None
        initial_code = ""
        already_reported_generation_failure = False

        # Small local models are stochastic: measured on qwen2.5-coder:3b, roughly one
        # generation in five comes back as prose or otherwise unparseable. A single attempt
        # therefore dropped the user into the canned template surprisingly often — they'd pick
        # a local model and silently get the built-in reference app instead of generated code,
        # while the run still reported SUCCESS. Re-rolling a couple of times turns a ~20%
        # per-attempt failure into ~1% overall, because each attempt is an independent sample.
        MAX_CODER_ATTEMPTS = 3
        test_file_path = os.path.join(session_target_dir, test_filename)

        for attempt in range(1, MAX_CODER_ATTEMPTS + 1):
            suffix = f" (attempt {attempt}/{MAX_CODER_ATTEMPTS})" if attempt > 1 else ""
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Querying local Ollama model ({ollama_model}) for prompt: '{prompt}'...{suffix}", "user_id": user_id, "session_id": session_id})

            # Clear any partial files a rejected attempt wrote, so this attempt can't silently
            # inherit the previous one's broken test file.
            if attempt > 1:
                try:
                    if os.path.exists(test_file_path):
                        os.remove(test_file_path)
                except OSError:
                    pass

            # STAGE 1 — the app on its own. One file, few constraints: far more likely to come
            # back as clean code than the old "app + tests + custom delimiter" mega-prompt.
            candidate = await query_ollama(OLLAMA_APP_PROMPTS[language].format(prompt=prompt), ollama_model)

            if not candidate:
                reason = "returned an empty response or crashed"
            elif has_repetition_loop(candidate):
                reason = "response degenerated into a repeated-phrase loop"
            else:
                # Models emit ```fenced``` blocks regardless of what we ask, so accept that
                # rather than fight it; fall back to the multi-file parser if they did use
                # the $$FILE:$$ form.
                parsed = strip_code_fences(candidate)
                if "$$FILE:" in candidate:
                    parsed = parse_multifile_response(candidate, session_target_dir, main_filename=app_filename)
                if language == "java":
                    parsed = fix_java_class_visibility(parsed)
                if language == "python":
                    parsed = sanitize_python_trailing_garbage(parsed)
                if not is_usable_source(parsed, language):
                    repaired_initial = repair_markdown_escapes(parsed)
                    if is_usable_source(repaired_initial, language):
                        parsed = repaired_initial
                if is_usable_source(parsed, language):
                    # For C++/Java the brace check above proves very little, so actually build
                    # the app. Accepting one that doesn't compile poisons everything after it:
                    # the test suite is compiled against it and fails too, and the failure gets
                    # blamed on the tests rather than the app.
                    with open(os.path.join(session_target_dir, app_filename), "w", encoding="utf-8") as f:
                        f.write(parsed)
                    compiles, compile_why = await app_source_compiles(language, session_target_dir, app_filename)
                    if compiles and app_has_untestable_input_api(parsed, language):
                        reason = ("core functions take a Scanner/cin parameter and read input internally, "
                                  "so they cannot be unit tested")
                    elif compiles:
                        generated_code, initial_code = candidate, parsed
                        break
                    else:
                        reason = f"generated {lang_display(language)} does not compile ({compile_why})"
                else:
                    # Never report "GENERATION SUCCESS" over something that isn't parseable code —
                    # that hands the Tester a file it cannot even import and burns the whole run
                    # fighting a broken program instead of the user's actual requirement.
                    reason = f"returned prose or unparseable {lang_display(language)}, not code"

            if attempt < MAX_CODER_ATTEMPTS:
                await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Model Notice ({reason}) — re-rolling generation...", "user_id": user_id, "session_id": session_id})
            else:
                await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Model Notice ({reason}) on all {MAX_CODER_ATTEMPTS} attempts. Switching to High-Reliability Code Synthesizer.", "user_id": user_id, "session_id": session_id})
                already_reported_generation_failure = True

        if generated_code:
            # Re-write app file in case fix_java_class_visibility changed it after parse_multifile_response already wrote it
            with open(os.path.join(session_target_dir, app_filename), "w", encoding="utf-8") as f:
                f.write(initial_code)

            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] LIVE GENERATION SUCCESS: Generated real {lang_display(language)} code via Ollama!", "user_id": user_id, "session_id": session_id})

            # STAGE 2 — tests written AGAINST the finished app. Generating them in the same
            # breath as the app was the single biggest source of Tester failures: the model
            # would assert behaviour the final code didn't have, so the very first test run
            # failed on a mismatch baked in at generation time. Showing it the real code first
            # means the assertions describe functions that actually exist.
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Writing {TEST_TOOL_NAME[language]} tests against the generated code...", "user_id": user_id, "session_id": session_id})
            test_code = None
            test_file_path = os.path.join(session_target_dir, test_filename)
            MAX_TEST_ATTEMPTS = 3
            for test_attempt in range(1, MAX_TEST_ATTEMPTS + 1):
                raw_tests = await query_ollama(
                    OLLAMA_TEST_PROMPTS[language].format(app_code=initial_code), ollama_model)
                if not raw_tests or has_repetition_loop(raw_tests):
                    continue
                candidate_tests = strip_code_fences(raw_tests)
                if language == "java":
                    candidate_tests = fix_java_class_visibility(candidate_tests)
                    candidate_tests = ensure_java_test_imports(candidate_tests)
                elif language == "cpp":
                    candidate_tests = ensure_cpp_test_includes(candidate_tests)
                elif language == "python":
                    candidate_tests = sanitize_python_trailing_garbage(candidate_tests)
                    candidate_tests = fix_test_import_module_name(
                        candidate_tests, initial_code, os.path.splitext(app_filename)[0])
                    candidate_tests = ensure_common_test_imports(candidate_tests)
                if not is_usable_source(candidate_tests, language):
                    continue
                # Write it, then confirm the runner can actually collect it — a suite that
                # aborts during collection can never pass, and the Tester would spend every
                # fix loop on it.
                with open(test_file_path, "w", encoding="utf-8") as f:
                    f.write(candidate_tests)
                runnable, why = await test_file_is_runnable(language, session_target_dir, test_filename)
                if runnable:
                    test_code = candidate_tests
                    break
                if test_attempt < MAX_TEST_ATTEMPTS:
                    await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Generated test suite rejected ({why}) — rewriting tests...", "user_id": user_id, "session_id": session_id})

            if test_code is None:
                tests_are_placeholder = True
                # A trivial stub keeps the pipeline moving to the security audit, but it proves
                # nothing about the app — say so plainly instead of letting a green "tests
                # passed" imply the code was actually verified.
                await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Model could not produce a usable {TEST_TOOL_NAME[language]} suite — falling back to a placeholder test (QA stage will not meaningfully verify this app).", "user_id": user_id, "session_id": session_id})
                test_code = STUB_TEST_CODE[language]

            test_file_path = os.path.join(session_target_dir, test_filename)
            with open(test_file_path, "w", encoding="utf-8") as f:
                f.write(test_code)
            patched_code = initial_code
            vuln_type = "Potential Security Misconfiguration"
            vuln_desc = f"{SAST_TOOL_NAME[language]} scanner enforces best practices. Please review."
        else:
            # Only report the generic "empty response" reason when that's genuinely what
            # happened. The repetition-loop and unparseable-output guards above already
            # explained themselves and set generated_code = None, so repeating a second,
            # different-sounding notice here made one rejection look like two separate
            # failures and pointed debugging at Ollama's health instead of the real cause.
            if not already_reported_generation_failure:
                await broadcast({"type": "LOG", "agent": "coder", "text": "[Coder Agent] Ollama Model Notice (returned an empty response or crashed). Switching to High-Reliability Code Synthesizer.", "user_id": user_id, "session_id": session_id})
            initial_code, test_code, secure_offline_patch, vuln_type, vuln_desc = generate_domain_code(prompt, language)
            patched_code = initial_code
            ext = lang_ext(language); app_filename = f"generated_app.{ext}"; test_filename = f"test_generated_app.{ext}"
            app_file = os.path.join(session_target_dir, app_filename)
            test_file = os.path.join(session_target_dir, test_filename)
            root_app_file = os.path.join(user_dir, app_filename)
            root_test_file = os.path.join(user_dir, test_filename)
    else:
        await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] [Autonomous Code Synthesizer] Synthesizing functional {lang_display(language)} code for: '{prompt}'...", "user_id": user_id, "session_id": session_id})
        initial_code, test_code, secure_offline_patch, vuln_type, vuln_desc = generate_domain_code(prompt, language)
        patched_code = initial_code
        ext = lang_ext(language); app_filename = f"generated_app.{ext}"; test_filename = f"test_generated_app.{ext}"
        app_file = os.path.join(session_target_dir, app_filename)
        test_file = os.path.join(session_target_dir, test_filename)
        root_app_file = os.path.join(user_dir, app_filename)
        root_test_file = os.path.join(user_dir, test_filename)

    # Stream code in chunks of 10 lines for fast display
    lines = initial_code.split("\n")
    for i in range(0, len(lines), 10):
        chunk = "\n".join(lines[:i+10]) + "\n"
        await broadcast({"type": "FILE_STREAM", "file": app_filename, "content": chunk, "user_id": user_id, "session_id": session_id})
        await asyncio.sleep(0.02)

    with open(app_file, "w", encoding="utf-8") as f: f.write(initial_code)
    with open(test_file, "w", encoding="utf-8") as f: f.write(test_code)
    with open(root_app_file, "w", encoding="utf-8") as f: f.write(initial_code)
    with open(root_test_file, "w", encoding="utf-8") as f: f.write(test_code)

    await broadcast({"type": "FILE_UPDATE", "file": app_filename, "content": initial_code, "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "FILE_UPDATE", "file": test_filename, "content": test_code, "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "LOG", "agent": "coder", "text": f"[Coder Agent] Code for '{prompt}' successfully generated and saved.", "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "AGENT_END", "agent": "coder", "status": "SUCCESS", "user_id": user_id, "session_id": session_id})

    # Loop count alone doesn't bound wall-clock time — a handful of slow AI calls can still add
    # up to several minutes even within a small loop budget. Time the Tester/Hacker/Patcher loop
    # from here (after the one-time Coder generation) and stop making new AI calls once this
    # budget is spent, so the whole pipeline reliably wraps up in roughly two minutes instead of
    # grinding through its full loop allowance.
    loop_start_time = time.time()
    # The check only gates STARTING a new AI call, not interrupting one already in flight, so
    # the real worst case is this budget plus however long that last in-flight call takes (up to
    # its own 75s timeout). Set low enough that even a worst-case overshoot lands close to the
    # ~2-minute target once the Coder's one-time generation time is added on top.
    FIX_LOOP_TIME_BUDGET_SECONDS = 70

    async def _time_budget_exceeded() -> bool:
        return (time.time() - loop_start_time) > FIX_LOOP_TIME_BUDGET_SECONDS

    async def _stop_for_time_budget(agent: str):
        state["is_running"] = False
        elapsed = time.time() - loop_start_time
        report = (
            f"# Security Audit Report (User: {user_id[:8]}...)\n\n"
            f"### Result: NOT COMPLETED\n"
            f"- **Status**: Stopped after ~{elapsed:.0f}s of fix attempts to keep the pipeline inside "
            f"its time budget, instead of grinding through every remaining loop.\n"
            f"- **Reason**: The AI model needed more attempts than fit in that window for this prompt.\n"
            f"- **Next step**: Click 'Extend +5 Loops' to keep going, or try a faster/stronger model.\n"
        )
        with open(vuln_file, "w") as f:
            f.write(report)
        await broadcast({"type": "FILE_UPDATE", "file": "vulnerability_report.md", "content": report, "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "AGENT_END", "agent": agent, "status": "FAILED", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "PIPELINE_COMPLETE", "status": "TIME_LIMIT", "message": f"Stopped after ~{elapsed:.0f}s to stay within the pipeline's time budget. Click '+5 Iterations' to keep going.", "user_id": user_id, "session_id": session_id})

    while state["current_loop"] < state["max_loops"]:
        state["current_loop"] += 1
        current_loop = state["current_loop"]
        max_loops_curr = state["max_loops"]

        await broadcast({"type": "LOOP_START", "loop": current_loop, "max_loops": max_loops_curr, "user_id": user_id, "session_id": session_id})

        # AGENT 2: TESTER AGENT
        await broadcast({"type": "AGENT_START", "agent": "tester", "title": "Tester Agent (QA Verification)", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "LOG", "agent": "tester", "text": f"[Tester Agent] Executing {TEST_TOOL_NAME[language]} test suite against {app_filename}...", "user_id": user_id, "session_id": session_id})

        tests_passed, test_output = await run_compile_and_test(language, session_target_dir, app_filename, test_filename)

        await broadcast({"type": "TERMINAL_OUTPUT", "cmd": f"{TEST_TOOL_NAME[language]} run", "output": test_output, "user_id": user_id, "session_id": session_id})

        if not tests_passed:
            await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] Unit tests failed! Requesting AI fix for the specific error...", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "tester", "status": "FAILED", "user_id": user_id, "session_id": session_id})

            # The failure can originate in the APP code or in the TEST code itself (e.g. a
            # syntax error in the test file, or a mismatch between what the test expects and
            # what the app provides) — send both so the model can fix whichever is actually broken.
            current_test_code = test_code
            if os.path.exists(test_file):
                with open(test_file, "r", encoding="utf-8") as f:
                    current_test_code = f.read()

            failure_hint = ""
            if language == "python" and "reading from stdin" in test_output.lower():
                failure_hint = (
                    "The error is 'reading from stdin while output is captured' — a test is calling a function "
                    "that itself calls input(). Fix this by changing the core function(s) to accept the data as "
                    "parameters instead of calling input() internally, and have the tests call them directly with "
                    "sample arguments (no input() in the test, no input() inside the tested functions themselves).\n\n"
                )
            elif language == "python" and "does not have the attribute" in test_output.lower() and "patch(" in current_test_code:
                failure_hint = (
                    "The error is an AttributeError from an invalid unittest.mock.patch() target — likely something "
                    f"like patch('__main__.{os.path.splitext(app_filename)[0]}') which doesn't exist. Fix by patching the "
                    f"actual function directly, e.g. patch('{os.path.splitext(app_filename)[0]}.function_name'), or by "
                    "removing the unnecessary patch entirely if the test doesn't need it.\n\n"
                )
            fix_prompt = (
                f"You are fixing a bug in an existing {lang_display(language)} program. The ORIGINAL REQUIREMENT this "
                f"program must satisfy is: '{prompt}' — do not lose sight of this. The code below already implements "
                f"most of that requirement; it just failed to compile or pass its test suite on one specific error.\n\n"
                f"The bug may be in the APP code or the TEST code — inspect both.\n\n"
                f"{failure_hint}"
                f"APP CODE ({app_filename}):\n{patched_code}\n\n"
                f"TEST CODE ({test_filename}):\n{current_test_code}\n\n"
                f"ERROR OUTPUT:\n{test_output.strip()[-2500:]}\n\n"
                f"Fix ONLY the specific bug shown in the error output. Make the MINIMAL change needed — do not rewrite, "
                f"simplify, or replace unrelated working functions. Every function present in the APP CODE above that "
                f"is unrelated to this error MUST still be present, working, and satisfying the original requirement "
                f"in your output — never collapse the program down to a trivial placeholder/stub.\n"
                f"Output using exactly this format, nothing else, no explanations, no markdown fences:\n"
                f"$$FILE: {app_filename}$$\n<complete fixed app code>\n$$FILE: {test_filename}$$\n<complete fixed test code>"
            )
            if await _time_budget_exceeded():
                await _stop_for_time_budget("tester")
                return
            fixed_res = None
            if ollama_model:
                fixed_res = await query_ollama(fix_prompt, ollama_model)
            elif use_api_key_mode:
                if is_claude_model:
                    fixed_res, _ = await query_claude_raw(fix_prompt, api_key_to_use)
                elif is_openrouter_model:
                    fixed_res, _ = await query_openrouter_raw(fix_prompt, api_key_to_use)
                else:
                    fixed_res, _ = await query_gemini_raw(fix_prompt, api_key_to_use)

            made_progress = False
            if fixed_res:
                fixed_app_code = parse_multifile_response(fixed_res, session_target_dir, main_filename=app_filename)
                fixed_test_code = current_test_code
                if os.path.exists(test_file):
                    with open(test_file, "r", encoding="utf-8") as f:
                        fixed_test_code = f.read()
                # Last-ditch repair before judging the response: un-escape markdown artifacts
                # (`len(_todo\_list)`) that some models leave in, but only if that actually makes
                # otherwise-broken code parse.
                if not is_usable_source(fixed_app_code, language):
                    repaired = repair_markdown_escapes(fixed_app_code)
                    if is_usable_source(repaired, language):
                        fixed_app_code = repaired
                if not is_usable_source(fixed_test_code, language):
                    repaired_test = repair_markdown_escapes(fixed_test_code)
                    if is_usable_source(repaired_test, language):
                        fixed_test_code = repaired_test

                app_is_usable = is_usable_source(fixed_app_code, language)
                test_is_usable = is_usable_source(fixed_test_code, language)

                if has_repetition_loop(fixed_app_code) or has_repetition_loop(fixed_test_code):
                    # A weak model occasionally decodes into a repeated-phrase loop (e.g. a test
                    # name degenerating into "..._and_description_and_description..." dozens of
                    # times), bloating the file with garbage. The text is DIFFERENT every retry,
                    # so the plain "unchanged code" stagnation check below would never catch it —
                    # reject it explicitly instead of ever writing it to disk.
                    await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] AI fix degenerated into a repeated-phrase loop — rejecting this response and keeping the previous code.", "user_id": user_id, "session_id": session_id})
                    fixed_app_code = patched_code
                    fixed_test_code = current_test_code
                elif not app_is_usable or not test_is_usable:
                    # The model replied with prose, a truncated fragment, or otherwise unparseable
                    # text instead of code. Writing that over the working app is strictly
                    # destructive — it replaces a program that failed ONE test with a file that
                    # cannot even be imported, and every later loop then fights that instead of
                    # the original bug. Keep whichever side is still good.
                    broken = " and ".join(p for p, ok in ((app_filename, app_is_usable), (test_filename, test_is_usable)) if not ok)
                    await broadcast({"type": "LOG", "agent": "tester", "text": f"[Tester Agent] AI fix returned unparseable content for {broken} (prose or a truncated fragment, not code) — rejecting it and keeping the previous working version.", "user_id": user_id, "session_id": session_id})
                    if not app_is_usable:
                        fixed_app_code = patched_code
                    if not test_is_usable:
                        fixed_test_code = current_test_code
                elif language == "java":
                    fixed_app_code = fix_java_class_visibility(fixed_app_code)
                    fixed_test_code = fix_java_class_visibility(fixed_test_code)
                elif language == "python" and fixed_app_code.strip():
                    if is_regressive_python_rewrite(patched_code, fixed_app_code):
                        await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] AI fix discarded most of the existing app instead of fixing the specific bug — rejecting this rewrite and keeping the previous code.", "user_id": user_id, "session_id": session_id})
                        fixed_app_code = patched_code
                    else:
                        fixed_test_code = fix_test_import_module_name(fixed_test_code, fixed_app_code, os.path.splitext(app_filename)[0])
                        fixed_test_code = ensure_common_test_imports(fixed_test_code)

                app_changed = bool(fixed_app_code.strip()) and fixed_app_code.strip() != patched_code.strip()
                test_changed = fixed_test_code.strip() != current_test_code.strip()
                if app_changed or test_changed:
                    if fixed_app_code.strip():
                        patched_code = fixed_app_code
                    test_code = fixed_test_code
                    made_progress = True
                    await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] AI fix generated. Retrying...", "user_id": user_id, "session_id": session_id})
                else:
                    await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] AI returned unchanged code — no further fix possible, stopping early to save API calls.", "user_id": user_id, "session_id": session_id})
            else:
                await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] No AI model available to auto-fix this error.", "user_id": user_id, "session_id": session_id})

            with open(app_file, "w", encoding="utf-8") as f: f.write(patched_code)
            with open(root_app_file, "w", encoding="utf-8") as f: f.write(patched_code)
            with open(test_file, "w", encoding="utf-8") as f: f.write(test_code)
            with open(root_test_file, "w", encoding="utf-8") as f: f.write(test_code)
            await broadcast({"type": "FILE_UPDATE", "file": app_filename, "content": patched_code, "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "FILE_UPDATE", "file": test_filename, "content": test_code, "user_id": user_id, "session_id": session_id})

            if not made_progress:
                stagnant_fix_attempts += 1
            else:
                stagnant_fix_attempts = 0

            # A single rejected/unchanged fix is often just a weak model having an off attempt —
            # small local models are stochastic enough (temperature 0.2) that immediately retrying
            # the same error frequently succeeds on the next try. Only give up once it's stagnated
            # on the SAME error twice in a row, or there's genuinely no model to ask at all.
            no_model_available = not ollama_model and not use_api_key_mode
            if not made_progress and (stagnant_fix_attempts >= 2 or no_model_available) and state["current_loop"] < state["max_loops"]:
                state["is_running"] = False
                stuck_report = (
                    f"# Security Audit Report (User: {user_id[:8]}...)\n\n"
                    f"### Result: NOT COMPLETED\n"
                    f"- **Status**: The pipeline stopped before reaching the security audit stage.\n"
                    f"- **Reason**: The Tester Agent could not get the test suite passing — the AI ran out of fix attempts "
                    f"on this error and made no further progress.\n"
                    f"- **Last error**:\n```\n{test_output.strip()[-1200:]}\n```\n"
                )
                with open(vuln_file, "w") as f:
                    f.write(stuck_report)
                await broadcast({"type": "FILE_UPDATE", "file": "vulnerability_report.md", "content": stuck_report, "user_id": user_id, "session_id": session_id})
                await broadcast({"type": "PIPELINE_COMPLETE", "status": "STUCK", "message": "Stopped early: the AI could not generate a working fix for this error. Review the code manually or try a different/stronger model.", "user_id": user_id, "session_id": session_id})
                return
            continue

        await broadcast({"type": "LOG", "agent": "tester", "text": "[Tester Agent] ALL UNIT TESTS PASSED CLEANLY!", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "AGENT_END", "agent": "tester", "status": "SUCCESS", "user_id": user_id, "session_id": session_id})

        with open(app_file, "r", encoding="utf-8") as f:
            curr_content = f.read()

        is_vulnerable = VULN_HEURISTICS[language](curr_content)

        # AGENT 3: HACKER AGENT
        await broadcast({"type": "AGENT_START", "agent": "hacker", "title": "Hacker Agent (Red Team Audit)", "user_id": user_id, "session_id": session_id})
        await broadcast({"type": "LOG", "agent": "hacker", "text": f"[Hacker Agent] Running {SAST_TOOL_NAME[language]} security analyzer on project workspace...", "user_id": user_id, "session_id": session_id})

        vulnerabilities = await run_sast(language, session_target_dir, app_filename, sec_report_file)

        if vulnerabilities or is_vulnerable:
            await broadcast({"type": "LOG", "agent": "hacker", "text": f"[Hacker Agent] SECURITY VULNERABILITY DETECTED! ({vuln_type})", "user_id": user_id, "session_id": session_id})
            
            report_text = f"# Security Audit Report (User: {user_id[:8]}...)\n\n"
            report_text += f"### Critical Finding:\n"
            report_text += f"- **Type**: {vuln_type}\n"
            report_text += f"- **Severity**: HIGH\n"
            report_text += f"- **Details**: {vuln_desc}\n\n"
            report_text += f"### {SAST_TOOL_NAME[language]} Analysis Summary:\n"
            if vulnerabilities:
                for v in vulnerabilities:
                    report_text += f"- **[{v['severity']}]** Line {v['line']}: {v['issue_text']}\n"
            else:
                report_text += f"- **[HIGH]** Insecure pattern detected in application source.\n"

            with open(vuln_file, "w") as f:
                f.write(report_text)

            await broadcast({"type": "FILE_UPDATE", "file": "vulnerability_report.md", "content": report_text, "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "TERMINAL_OUTPUT", "cmd": f"{SAST_TOOL_NAME[language]} scan", "output": f"[SECURITY ALERT] {vuln_type}\nAudit report written to vulnerability_report.md", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "hacker", "status": "VULNERABLE", "user_id": user_id, "session_id": session_id})

            # AGENT 4: PATCHER AGENT
            await broadcast({"type": "AGENT_START", "agent": "patcher", "title": "Patcher Agent (AppSec Remediation)", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Reading security audit and refactoring code to securitized pattern...", "user_id": user_id, "session_id": session_id})

            before_code = curr_content

            if vulnerabilities:
                findings_text = "\n".join(f"- Line {v['line']}: {v['issue_text']} (severity: {v['severity']})" for v in vulnerabilities)
            else:
                findings_text = f"- {vuln_desc}"

            patch_prompt = (
                f"Fix this {lang_display(language)} code to remove these specific security issues found by {SAST_TOOL_NAME[language]}:\n"
                f"{findings_text}\n\n"
                f"Make the MINIMAL change needed to resolve exactly these findings — do not rewrite unrelated code.\n"
                f"Return ONLY the fixed {lang_display(language)} code, no explanations, no markdown fences:\n\n{before_code}"
            )
            if await _time_budget_exceeded():
                await _stop_for_time_budget("patcher")
                return
            patched_res = None
            if ollama_model:
                patched_res = await query_ollama(patch_prompt, ollama_model)
            elif use_api_key_mode:
                if is_claude_model:
                    patched_res, _ = await query_claude_raw(patch_prompt, api_key_to_use)
                elif is_openrouter_model:
                    patched_res, _ = await query_openrouter_raw(patch_prompt, api_key_to_use)
                else:
                    patched_res, _ = await query_gemini_raw(patch_prompt, api_key_to_use)

            made_progress = False
            accepted_patch = None
            if patched_res:
                new_code = strip_code_fences(patched_res)
                if language == "java":
                    new_code = fix_java_class_visibility(new_code)
                if not is_usable_source(new_code, language):
                    repaired_patch = repair_markdown_escapes(new_code)
                    if is_usable_source(repaired_patch, language):
                        new_code = repaired_patch
                if has_repetition_loop(new_code):
                    await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Security fix degenerated into a repeated-phrase loop — rejecting this response and keeping the previous code.", "user_id": user_id, "session_id": session_id})
                elif not is_usable_source(new_code, language):
                    # Never let a security "fix" replace working code with prose or a broken
                    # fragment — that turns a vulnerable-but-working app into a dead one.
                    await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Security fix returned unparseable content (prose or a truncated fragment, not code) — rejecting it and keeping the previous working version.", "user_id": user_id, "session_id": session_id})
                elif new_code.strip() and new_code.strip() != before_code.strip():
                    accepted_patch = new_code

            if accepted_patch:
                patched_code = accepted_patch
                made_progress = True
            elif secure_offline_patch and secure_offline_patch.strip() != before_code.strip():
                # The AI either returned nothing usable or was rejected above — but when the app
                # came from the deterministic synthesizer, that synthesizer also ships a known-good
                # secure variant of the very same program. Previously this fallback was only
                # reachable when the model returned an empty response, so a model that replied with
                # prose (weak local models do this constantly) left the run permanently STUCK on a
                # vulnerability we already had the correct fix for. Use it.
                await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Applying the verified secure reference implementation instead of the model's unusable response.", "user_id": user_id, "session_id": session_id})
                patched_code = secure_offline_patch
                made_progress = True

            if not made_progress:
                stagnant_patch_attempts += 1
            else:
                stagnant_patch_attempts = 0

            no_model_available = not ollama_model and not use_api_key_mode
            if not made_progress and (stagnant_patch_attempts >= 2 or no_model_available):
                await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] No further fix could be generated — stopping early to save API calls.", "user_id": user_id, "session_id": session_id})
                await broadcast({"type": "AGENT_END", "agent": "patcher", "status": "FAILED", "user_id": user_id, "session_id": session_id})
                state["is_running"] = False
                await broadcast({"type": "PIPELINE_COMPLETE", "status": "STUCK", "message": "Stopped early: the AI could not generate a further security fix. Review the code manually or try a different/stronger model.", "user_id": user_id, "session_id": session_id})
                return

            if not made_progress:
                await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Fix attempt produced no usable change — retrying with the same findings.", "user_id": user_id, "session_id": session_id})
                await broadcast({"type": "AGENT_END", "agent": "patcher", "status": "FAILED", "user_id": user_id, "session_id": session_id})
                continue

            # Chunk stream patched code
            patch_lines = patched_code.split("\n")
            for i in range(0, len(patch_lines), 10):
                chunk = "\n".join(patch_lines[:i+10]) + "\n"
                await broadcast({"type": "FILE_STREAM", "file": app_filename, "content": chunk, "user_id": user_id, "session_id": session_id})
                await asyncio.sleep(0.02)

            with open(app_file, "w") as f: f.write(patched_code)
            with open(root_app_file, "w") as f: f.write(patched_code)

            diff_file = os.path.join(session_target_dir, "patch_diff.json")
            with open(diff_file, "w") as f:
                json.dump({"before": before_code, "after": patched_code}, f)

            await broadcast({"type": "LOG", "agent": "patcher", "text": "[Patcher Agent] Refactored code with secure pattern. Re-routing to Tester Agent for validation.", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "FILE_UPDATE", "file": app_filename, "content": patched_code, "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "DIFF_UPDATE", "before": before_code, "after": patched_code, "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "patcher", "status": "PATCHED", "user_id": user_id, "session_id": session_id})
            continue
        else:
            state["is_running"] = False
            secure_report_text = (
                f"# Security Audit Report (User: {user_id[:8]}...)\n\n"
                f"### Result: VERIFIED SECURE\n"
                f"- **Status**: PASSED\n"
                f"- **Details**: {SAST_TOOL_NAME[language]} static analysis found zero vulnerabilities in the current codebase.\n"
            )
            with open(vuln_file, "w") as f:
                f.write(secure_report_text)
            await broadcast({"type": "FILE_UPDATE", "file": "vulnerability_report.md", "content": secure_report_text, "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "LOG", "agent": "hacker", "text": "[Hacker Agent] CODEBASE VERIFIED SECURE! Zero vulnerabilities detected.", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "hacker", "status": "VERIFIED_SECURE", "user_id": user_id, "session_id": session_id})
            if tests_are_placeholder:
                done_msg = ("Security audit passed, but the model could not write a real test suite — "
                            "QA ran only a placeholder test, so the app's behaviour is NOT verified.")
                done_status = "SUCCESS_UNVERIFIED"
            else:
                done_msg = "App passes all functional tests & static security audits!"
                done_status = "SUCCESS"
            await broadcast({"type": "PIPELINE_COMPLETE", "status": done_status, "message": done_msg, "user_id": user_id, "session_id": session_id})
            return

    state["is_running"] = False
    # Reaching here always means the pipeline never converged this run (the vulnerable/patched
    # path always loops back via `continue`, and the give-up paths above `return` directly) —
    # so any pre-existing report on disk is stale and must be overwritten, not left in place.
    maxloop_report = (
        f"# Security Audit Report (User: {user_id[:8]}...)\n\n"
        f"### Result: NOT COMPLETED\n"
        f"- **Status**: The pipeline reached its max loop limit ({state['max_loops']}) before the code ever "
        f"reached a stable, passing state — the security audit stage (Hacker Agent) never ran.\n"
        f"- **Next step**: Click 'Extend +5 Loops' to give it more attempts, or try a different/stronger model.\n"
    )
    with open(vuln_file, "w") as f:
        f.write(maxloop_report)
    await broadcast({"type": "FILE_UPDATE", "file": "vulnerability_report.md", "content": maxloop_report, "user_id": user_id, "session_id": session_id})
    await broadcast({"type": "PIPELINE_COMPLETE", "status": "MAX_LOOPS_REACHED", "message": f"Reached max loop limit ({state['max_loops']}). Click '+5 Iterations' to extend.", "user_id": user_id, "session_id": session_id})

async def _safe_execute_swarm_workflow(prompt, max_loops, selected_model, user_id, session_id, api_key, language="python"):
    try:
        await execute_swarm_workflow(prompt, max_loops, selected_model, user_id, session_id, api_key, language)
    except Exception as e:
        get_workflow_state(user_id, session_id)["is_running"] = False
        err_text = f"Unexpected swarm error: {type(e).__name__}: {e}"
        try:
            await broadcast({"type": "LOG", "agent": "coder", "text": f"[System] {err_text}", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "STATUS", "message": err_text, "state": "ERROR", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "AGENT_END", "agent": "coder", "status": "FAILED", "user_id": user_id, "session_id": session_id})
            await broadcast({"type": "PIPELINE_COMPLETE", "status": "ERROR", "message": err_text, "user_id": user_id, "session_id": session_id})
        except Exception:
            pass

@app.post("/api/swarm/execute")
async def trigger_swarm(req: PromptRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    # Guard against two overlapping runs for the same session — e.g. a client-side watchdog
    # falsely timing out (button re-enables) while the previous run is still genuinely active
    # on the backend, and the user clicks Execute again. Without this, both coroutines would
    # run concurrently, racing to write the same app/test/report files and doubling up on the
    # same local Ollama instance, corrupting state and making failures much more likely.
    # Setting the flag here (synchronously, before create_task/any await) is atomic with
    # respect to other requests since asyncio is single-threaded, so this fully closes the race.
    state = get_workflow_state(req.user_id, req.session_id)
    if state.get("is_running"):
        return {"status": "already_running", "message": "A swarm run is already active for this session — wait for it to finish (or give up) before starting another.", "user_id": req.user_id, "session_id": req.session_id, "language": req.language}
    state["is_running"] = True
    asyncio.create_task(_safe_execute_swarm_workflow(req.prompt, req.max_loops, req.selected_model, req.user_id, req.session_id, req.api_key, req.language))
    return {"status": "started", "prompt": req.prompt, "max_loops": req.max_loops, "user_id": req.user_id, "session_id": req.session_id, "language": req.language}

@app.post("/api/swarm/extend")
async def extend_iterations(req: ExtendRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    state = get_workflow_state(req.user_id, req.session_id)
    state["max_loops"] += 5
    await broadcast({"type": "STATUS", "message": f"Extended max iterations to {state['max_loops']}", "state": "EXTENDED", "user_id": req.user_id, "session_id": req.session_id})
    await broadcast({"type": "LOOP_START", "loop": state["current_loop"], "max_loops": state["max_loops"], "user_id": req.user_id, "session_id": req.session_id})
    return {"status": "extended", "new_max_loops": state["max_loops"]}

@app.post("/api/save-code")
async def save_code(req: CustomCodeRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    user_dir = secure_join(workspaces_dir, req.user_id)
    os.makedirs(user_dir, exist_ok=True)
    
    session_target_dir = user_dir
    if req.session_id:
        session_target_dir = os.path.join(user_dir, "sessions", req.session_id)
        os.makedirs(session_target_dir, exist_ok=True)

    app_file = os.path.join(session_target_dir, req.filename)
    with open(app_file, "w", encoding="utf-8") as f:
        f.write(req.code)

    return {"status": "success", "message": "Code saved successfully."}

@app.post("/api/swarm/audit-custom-code")
async def audit_custom_code(req: CustomCodeRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    user_dir = secure_join(workspaces_dir, req.user_id)
    os.makedirs(user_dir, exist_ok=True)

    session_target_dir = user_dir
    if req.session_id:
        session_target_dir = os.path.join(user_dir, "sessions", req.session_id)
        os.makedirs(session_target_dir, exist_ok=True)

    app_file = os.path.join(session_target_dir, req.filename)
    root_app_file = os.path.join(user_dir, req.filename)

    with open(app_file, "w", encoding="utf-8") as f: f.write(req.code)
    with open(root_app_file, "w", encoding="utf-8") as f: f.write(req.code)

    detected_ext = os.path.splitext(req.filename)[1].lstrip(".")
    detected_language = next((lang for lang, cfg in LANGUAGE_CONFIG.items() if cfg["ext"] == detected_ext), "python")

    await broadcast({"type": "STATUS", "message": "Auditing User Custom Code Edits...", "state": "RUNNING", "user_id": req.user_id, "session_id": req.session_id})
    await broadcast({"type": "FILE_UPDATE", "file": req.filename, "content": req.code, "user_id": req.user_id, "session_id": req.session_id})

    asyncio.create_task(_safe_execute_swarm_workflow(prompt="User Custom Code Edit Audit", max_loops=5, selected_model=None, user_id=req.user_id, session_id=req.session_id, api_key=None, language=detected_language))
    return {"status": "started", "message": "Auditing custom user code edits"}

@app.post("/api/swarm/run-code")
async def run_code(req: RunCodeRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    asyncio.create_task(execute_run_and_debug(req.code, req.user_id, req.session_id, req.selected_model, req.max_attempts, req.language))
    return {"status": "started", "message": "Running code locally"}

@app.post("/api/run/start")
async def start_interactive(req: RunInteractiveRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    user_dir = secure_join(workspaces_dir, req.user_id)
    os.makedirs(user_dir, exist_ok=True)
    session_target_dir = user_dir
    if req.session_id:
        session_target_dir = os.path.join(user_dir, "sessions", req.session_id)
        os.makedirs(session_target_dir, exist_ok=True)

    language = req.language if req.language in LANGUAGE_CONFIG else "python"
    code_to_run = fix_java_class_visibility(req.code) if language == "java" else req.code
    app_filename = f"generated_app.{lang_ext(language)}"
    app_file = os.path.join(session_target_dir, app_filename)
    with open(app_file, "w", encoding="utf-8") as f: f.write(code_to_run)
    with open(os.path.join(user_dir, app_filename), "w", encoding="utf-8") as f: f.write(code_to_run)

    ok, argv, compile_err = await compile_for_run(language, session_target_dir, app_filename)
    if not ok:
        await broadcast({"type": "INTERACTIVE_OUTPUT", "text": compile_err, "process_id": req.process_id, "user_id": req.user_id, "session_id": req.session_id})
        await broadcast({"type": "PROCESS_DONE", "exit_code": 1, "process_id": req.process_id, "user_id": req.user_id, "session_id": req.session_id})
        return {"status": "error", "message": "Compile failed", "process_id": req.process_id}

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=session_target_dir,
    )
    active_processes[req.process_id] = proc
    asyncio.create_task(stream_interactive_process(proc, req.process_id, req.user_id, req.session_id))
    return {"status": "started", "process_id": req.process_id}

@app.post("/api/run/input")
async def send_input(req: SendInputRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    proc = active_processes.get(req.process_id)
    if not proc or proc.stdin is None or proc.stdin.is_closing():
        return {"status": "error", "message": "No active process"}
    try:
        proc.stdin.write((req.text + "\n").encode())
        await proc.stdin.drain()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/run/kill")
async def kill_process(req: SendInputRequest, auth_user: str = Depends(current_user)):
    req.user_id = assert_owns(req.user_id, auth_user)
    proc = active_processes.pop(req.process_id, None)
    if proc:
        try: proc.kill()
        except Exception: pass
    return {"status": "ok"}

@app.get("/api/swarm/export/{user_id}")
async def export_package(user_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    user_dir = secure_join(workspaces_dir, user_id)
    zip_buffer = io.BytesIO()

    app_filename, test_filename = detect_session_app_files(user_dir)
    files_to_zip = [app_filename, test_filename, "vulnerability_report.md", "security_report.json"]

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for fname in files_to_zip:
            fpath = os.path.join(user_dir, fname)
            if os.path.exists(fpath):
                zip_file.write(fpath, arcname=fname)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=devsecops_workspace_{user_id[:8]}.zip"}
    )

@app.get("/api/workspace-files")
async def get_workspace_files(user_id: str, session_id: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    target_dir = secure_join(workspaces_dir, user_id, "sessions", session_id)
    if not os.path.exists(target_dir):
        return {"files": []}
    
    files = []
    for root, dirs, filenames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        for f in filenames:
            if f.startswith('.') or f.endswith(".pyc") or f == ".DS_Store" or f.endswith(".json") or f.endswith(".o") or f.endswith(".exe") or f.endswith(".class"): continue
            rel_path = os.path.relpath(os.path.join(root, f), target_dir)
            files.append(rel_path.replace("\\", "/"))
    return {"files": sorted(files)}

@app.get("/api/file-content")
async def get_file_content(user_id: str, session_id: str, filename: str, auth_user: str = Depends(current_user)):
    user_id = assert_owns(user_id, auth_user)
    target_file = secure_join(workspaces_dir, user_id, "sessions", session_id, filename)
    if not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail="File not found")
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        content = "[Binary file cannot be displayed in text editor]"
    return {"content": content}


def parse_multifile_response(resp_text: str, target_dir: str, main_filename: str = "generated_app.py") -> str:
    # Extracts $$FILE: name$$ and writes them. Returns main code for fallback testing.
    import re
    # [^\n]+? rather than .+? : with re.DOTALL a plain .+? lets the FILENAME group run across
    # newlines, so when a model omitted the closing $$ the "filename" swallowed the entire file
    # body up to the next delimiter. That was then handed to open() as a path and blew up with
    # WinError 123 (invalid filename). A filename never spans lines, so bound it to one.
    pattern = re.compile(r"\$\$FILE:\s*([^\n]+?)\$\$(.*?)(?=\$\$FILE:|\Z)", re.DOTALL)
    matches = pattern.findall(resp_text)

    if not matches:
        # Some models ignore the $$FILE$$ delimiter format entirely and reply with normal
        # markdown instead: a preamble, separate ```fenced``` blocks per file (often under a
        # "### filename" heading), then a trailing explanation. Dumping resp_text raw in that
        # case writes the ENTIRE markdown document — headings, prose and all — as the .py file,
        # guaranteeing a syntax error. Try to recover per-file fenced blocks before giving up.
        test_filename_guess = f"test_{main_filename}"
        fence_pattern = re.compile(r"```[a-zA-Z0-9+]*\n(.*?)```", re.DOTALL)
        fences = list(fence_pattern.finditer(resp_text))

        if fences:
            matches = []
            test_name_lower = test_filename_guess.lower()
            main_name_lower = main_filename.lower()
            for idx, fm in enumerate(fences):
                # Only check the single heading line right above the fence (e.g. "### test_generated_app.py")
                # for the exact filename — scanning further back risks false-matching an unrelated
                # mention of "test" in the preamble prose (e.g. "...along with a pytest test file").
                preceding_lines = resp_text[max(0, fm.start() - 200):fm.start()].strip().splitlines()
                nearby = preceding_lines[-1].lower() if preceding_lines else ""
                if test_name_lower in nearby:
                    fname = test_filename_guess
                elif main_name_lower in nearby:
                    fname = main_filename
                elif idx == 0:
                    fname = main_filename
                elif len(fences) == 2:
                    fname = test_filename_guess
                else:
                    fname = main_filename
                matches.append((fname, fm.group(1)))
        else:
            # No fences either — nothing to salvage but the raw dump.
            fallback_code = resp_text.strip()
            if main_filename.endswith(".py"):
                fallback_code = sanitize_python_trailing_garbage(fallback_code)
            app_file = os.path.join(target_dir, main_filename)
            with open(app_file, "w", encoding="utf-8") as f:
                f.write(fallback_code)
            return fallback_code

    main_code = ""
    for filename, content in matches:
        filename = filename.strip()
        content = content.strip()

        # The filename here comes straight from model output, so treat it as untrusted: it is
        # about to be used as a path. Reject anything that isn't a plain relative filename —
        # absolute paths, drive letters, .. traversal, or characters Windows cannot open — and
        # fall back to the expected name rather than writing outside the session directory.
        if (not filename
                or filename in (".", "..")
                or os.path.isabs(filename)
                or ":" in filename
                or ".." in filename.replace("\\", "/").split("/")
                or re.search(r'[<>:"|?*\x00-\x1f]', filename)):
            filename = main_filename
        # Strip markdown fences regardless of language/extension. Models sometimes wrap the
        # WHOLE multi-file response in one big fence (rather than per-file), which leaves a
        # stray ``` marker line stuck in the middle of a file's content — a guaranteed compile
        # error since ``` is never valid source. Strip any such line, not just leading/trailing.
        content = re.sub(r"^```[a-zA-Z0-9+]*\n?", "", content)
        content = re.sub(r"\n?```$", "", content)
        content = re.sub(r"(?m)^```[a-zA-Z0-9+]*\s*$\n?", "", content).strip()

        # Some local/small models append a trailing plain-English note after the code
        # with no fence separating it, which would otherwise guarantee a SyntaxError.
        if filename.endswith(".py"):
            content = sanitize_python_trailing_garbage(content)

        if filename == main_filename or not main_code:
            main_code = content

        file_path = os.path.join(target_dir, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    return main_code

