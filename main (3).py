"""
Enterprise AI Assistant — All-in-one MCP-based backend
Tasks 1-16: API, MCP routing, context, tools, RBAC, security, error handling
"""

import os, uuid, json, smtplib, sqlite3, re
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Optional
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import openai

load_dotenv()

app = FastAPI(title="Enterprise AI Assistant", version="1.0.0")

# ─────────────────────────────────────────────
# TASK 4 & 11: Session-based context store (in-memory)
# ─────────────────────────────────────────────
SESSIONS: dict[str, dict] = {}

MASKED_KEYS = {"password", "token", "secret", "credit_card", "ssn"}

def mask_sensitive(data: dict) -> dict:
    """Task 11: Mask sensitive fields before storing/returning."""
    return {
        k: "***MASKED***" if k.lower() in MASKED_KEYS else v
        for k, v in data.items()
    }

def get_session(session_id: str) -> dict:
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {"history": [], "user": None, "role": "user"}
    return SESSIONS[session_id]

def append_history(session_id: str, role: str, content: str):
    session = get_session(session_id)
    session["history"].append({"role": role, "content": content, "ts": datetime.utcnow().isoformat()})
    # keep last 20 turns
    session["history"] = session["history"][-20:]

# ─────────────────────────────────────────────
# TASK 12: Role-Based Access Control
# ─────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": ["database", "email", "file", "report"],
    "user":  ["database", "file"],
    "guest": []
}

# Simulated user registry  {api_key: {name, role}}
USER_REGISTRY = {
    "admin-key-123": {"name": "Alice", "role": "admin"},
    "user-key-456":  {"name": "Bob",   "role": "user"},
    "guest-key-789": {"name": "Guest", "role": "guest"},
}

def resolve_user(api_key: Optional[str]) -> dict:
    if not api_key or api_key not in USER_REGISTRY:
        return {"name": "anonymous", "role": "guest"}
    return USER_REGISTRY[api_key]

def check_permission(role: str, tool: str):
    allowed = ROLE_PERMISSIONS.get(role, [])
    if tool not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role}' is not permitted to use tool '{tool}'"
        )


# ─────────────────────────────────────────────
# TASK 6: Database Tool (SQLite in-memory with seed data)
# ─────────────────────────────────────────────
def init_db():
    con = sqlite3.connect("enterprise.db")
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY,
            product TEXT,
            region TEXT,
            amount REAL,
            date TEXT
        )
    """)
    cur.execute("SELECT COUNT(*) FROM sales")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO sales VALUES (?,?,?,?,?)", [
            (1, "Widget A", "North", 15000, "2024-01-15"),
            (2, "Widget B", "South", 22000, "2024-02-10"),
            (3, "Gadget X", "East",  18500, "2024-03-05"),
            (4, "Gadget Y", "West",  31000, "2024-03-20"),
            (5, "Widget A", "East",  12000, "2024-04-01"),
        ])
    con.commit()
    con.close()

init_db()

def tool_database(payload: dict) -> dict:
    """Fetch business data from SQLite."""
    query = payload.get("query", "SELECT * FROM sales LIMIT 10")
    # safety: only allow SELECT
    if not re.match(r"^\s*SELECT", query, re.IGNORECASE):
        return {"error": "Only SELECT queries are allowed"}
    try:
        con = sqlite3.connect("enterprise.db")
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(query)
        rows = [dict(r) for r in cur.fetchall()]
        con.close()
        return {"rows": rows, "count": len(rows)}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# TASK 7: Email Tool
# ─────────────────────────────────────────────
def tool_email(payload: dict) -> dict:
    """Send an email via SMTP."""
    to      = payload.get("to", "")
    subject = payload.get("subject", "No Subject")
    body    = payload.get("body", "")

    if not to or "@" not in to:
        return {"error": "Invalid or missing recipient email"}
    if not body:
        return {"error": "Email body cannot be empty"}

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        # Simulate success in dev mode
        return {"status": "simulated", "message": f"Email to {to} simulated (no SMTP config)"}

    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to, msg.as_string())

        return {"status": "sent", "message": f"Email successfully sent to {to}"}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# TASK 8: File Tool
# ─────────────────────────────────────────────
def tool_file(payload: dict) -> dict:
    """Read a file and return its content."""
    path = payload.get("path", "")
    if not path:
        return {"error": "No file path provided"}
    # Security: restrict to current working directory
    abs_path = os.path.realpath(path)
    cwd      = os.path.realpath(".")
    if not abs_path.startswith(cwd):
        return {"error": "Access denied: path outside working directory"}
    if not os.path.exists(abs_path):
        return {"error": f"File not found: {path}"}
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"path": path, "content": content, "size": len(content)}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# TASK 3 & 5: MCP Tool Registry + Connector
# ─────────────────────────────────────────────
TOOL_REGISTRY = {
    "database": tool_database,
    "email":    tool_email,
    "file":     tool_file,
}

def mcp_invoke(tool_name: str, payload: dict, role: str) -> dict:
    """Task 5: Reusable MCP connector — routes to the correct tool."""
    check_permission(role, tool_name)
    handler = TOOL_REGISTRY.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    return handler(payload)

# ─────────────────────────────────────────────
# TASK 2: MCP Message Structure
# ─────────────────────────────────────────────
def build_mcp_request(tool: str, payload: dict, session_id: str) -> dict:
    return {
        "mcp_version": "1.0",
        "request_id":  str(uuid.uuid4()),
        "session_id":  session_id,
        "tool":        tool,
        "payload":     payload,
        "timestamp":   datetime.utcnow().isoformat()
    }

def build_mcp_response(request_id: str, session_id: str, tool: str, result: Any, status: str = "success") -> dict:
    return {
        "mcp_version": "1.0",
        "request_id":  request_id,
        "session_id":  session_id,
        "tool":        tool,
        "status":      status,
        "result":      result,
        "timestamp":   datetime.utcnow().isoformat()
    }

# ─────────────────────────────────────────────
# TASK 9: Intelligent Tool Detection via LLM
# ─────────────────────────────────────────────
TOOL_DETECTION_PROMPT = """
You are an enterprise AI assistant. Given a user query, decide:
1. Which tool(s) to call (database, email, file) — or none if answerable directly.
2. The payload for each tool.

Respond ONLY with valid JSON in this format:
{
  "tools": [
    {"tool": "<tool_name>", "payload": {<tool_specific_params>}}
  ],
  "direct_answer": "<answer if no tool needed, else null>"
}

Tool payloads:
- database: {"query": "SELECT ..."}
- email:    {"to": "...", "subject": "...", "body": "..."}
- file:     {"path": "..."}

User query: {query}
"""

def detect_tools(query: str) -> dict:
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))
    if not os.getenv("OPENAI_API_KEY"):
        # Fallback: keyword-based detection when no API key
        return keyword_tool_detection(query)
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": TOOL_DETECTION_PROMPT.format(query=query)}],
            temperature=0
        )
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return keyword_tool_detection(query)

def keyword_tool_detection(query: str) -> dict:
    """Fallback rule-based tool detection."""
    q = query.lower()
    tools = []
    if any(w in q for w in ["sales", "data", "database", "revenue", "report", "fetch", "query"]):
        tools.append({"tool": "database", "payload": {"query": "SELECT * FROM sales LIMIT 10"}})
    if any(w in q for w in ["email", "send", "mail", "notify"]):
        # extract email if present
        match = re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", query)
        to = match.group() if match else "recipient@example.com"
        tools.append({"tool": "email", "payload": {"to": to, "subject": "Enterprise Notification", "body": query}})
    if any(w in q for w in ["file", "read", "open", "content"]):
        match = re.search(r'["\']([^"\']+\.\w+)["\']', query)
        path = match.group(1) if match else "data.txt"
        tools.append({"tool": "file", "payload": {"path": path}})
    if not tools:
        return {"tools": [], "direct_answer": None}
    return {"tools": tools, "direct_answer": None}


# ─────────────────────────────────────────────
# TASK 10: Multi-step execution + AI synthesis
# ─────────────────────────────────────────────
def synthesize_response(query: str, tool_results: list, history: list) -> str:
    """Use LLM to produce a final answer combining all tool outputs."""
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))
    if not os.getenv("OPENAI_API_KEY"):
        return f"Processed {len(tool_results)} tool(s). Results: " + json.dumps(tool_results)

    context = "\n".join([f"{h['role']}: {h['content']}" for h in history[-6:]])
    system  = "You are an enterprise AI assistant. Synthesize tool results into a clear, professional response."
    user_msg = f"Conversation so far:\n{context}\n\nUser query: {query}\n\nTool results:\n{json.dumps(tool_results, indent=2)}\n\nProvide a concise final answer."

    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user_msg}],
            temperature=0.3
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Tool results retrieved. Summary unavailable: {str(e)}"

# ─────────────────────────────────────────────
# TASK 16: Standardized response builder
# ─────────────────────────────────────────────
def std_response(status: str, message: str, result: Any = None, session_id: str = "", request_id: str = "") -> dict:
    return {
        "status":     status,
        "message":    message,
        "result":     result,
        "session_id": session_id,
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp":  datetime.utcnow().isoformat()
    }

# ─────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────
class QueryRequest(BaseModel):
    query: str
    session_id: Optional[str] = None

class DirectToolRequest(BaseModel):
    tool: str
    payload: dict
    session_id: Optional[str] = None

# ─────────────────────────────────────────────
# TASK 1: POST /query — main AI endpoint
# TASK 13: Enterprise use case execution
# TASK 14: Error handling
# ─────────────────────────────────────────────
@app.post("/query")
async def query_endpoint(
    body: QueryRequest,
    x_api_key: Optional[str] = Header(default=None)
):
    request_id = str(uuid.uuid4())
    session_id = body.session_id or str(uuid.uuid4())
    user       = resolve_user(x_api_key)
    role       = user["role"]

    session = get_session(session_id)
    session["user"] = user["name"]
    session["role"] = role

    append_history(session_id, "user", body.query)

    try:
        # Detect which tools are needed
        detection = detect_tools(body.query)

        # Direct answer — no tools needed
        if detection.get("direct_answer"):
            answer = detection["direct_answer"]
            append_history(session_id, "assistant", answer)
            return JSONResponse(std_response("success", "Direct response", answer, session_id, request_id))

        tool_calls   = detection.get("tools", [])
        tool_results = []

        for tc in tool_calls:
            tool_name = tc.get("tool")
            payload   = tc.get("payload", {})

            # Build MCP request
            mcp_req = build_mcp_request(tool_name, payload, session_id)

            # Check permission & invoke
            try:
                result = mcp_invoke(tool_name, payload, role)
                status = "error" if "error" in result else "success"
            except HTTPException as e:
                result = {"error": e.detail}
                status = "forbidden"

            mcp_resp = build_mcp_response(mcp_req["request_id"], session_id, tool_name, result, status)
            tool_results.append(mcp_resp)

        # Synthesize final answer
        final = synthesize_response(body.query, tool_results, session["history"])
        append_history(session_id, "assistant", final)

        return JSONResponse(std_response(
            "success", "Query processed",
            {"answer": final, "tool_calls": tool_results},
            session_id, request_id
        ))

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content=std_response("error", str(e), None, session_id, request_id)
        )


# ─────────────────────────────────────────────
# TASK 15: Additional test/utility endpoints
# ─────────────────────────────────────────────

@app.post("/tool/invoke")
async def invoke_tool_directly(
    body: DirectToolRequest,
    x_api_key: Optional[str] = Header(default=None)
):
    """Directly invoke a specific MCP tool by name."""
    request_id = str(uuid.uuid4())
    session_id = body.session_id or str(uuid.uuid4())
    user       = resolve_user(x_api_key)
    role       = user["role"]

    mcp_req = build_mcp_request(body.tool, body.payload, session_id)
    try:
        result = mcp_invoke(body.tool, body.payload, role)
        status = "error" if "error" in result else "success"
    except HTTPException as e:
        return JSONResponse(
            status_code=403,
            content=std_response("forbidden", e.detail, None, session_id, request_id)
        )

    mcp_resp = build_mcp_response(mcp_req["request_id"], session_id, body.tool, result, status)
    return JSONResponse(std_response(status, "Tool invoked", mcp_resp, session_id, request_id))


@app.get("/session/{session_id}")
async def get_session_info(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None)
):
    """Retrieve session history (admin only)."""
    user = resolve_user(x_api_key)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    session = SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return JSONResponse(std_response("success", "Session retrieved", mask_sensitive(session)))


@app.get("/health")
async def health():
    return {"status": "ok", "tools": list(TOOL_REGISTRY.keys()), "timestamp": datetime.utcnow().isoformat()}


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
