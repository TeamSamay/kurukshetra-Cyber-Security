"""
Web Honeypot Application built with FastAPI.
Presents deceptive enterprise login portals, administrative consoles, and decoy resources.
Tracks attacker sessions, logs HTTP metadata, and emits real-time telemetry.
"""

import os
from typing import Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, Form, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from honeypot.common.event_schema import generate_session_id
from honeypot.common.telemetry import emit_event
from honeypot.decoys.decoy_manager import decoy_manager
from honeypot.config.settings import settings
from honeypot.api.api_server import api_router


templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

web_app = FastAPI(
    title="Corporate Enterprise Security Portal",
    docs_url=None,       # Custom deceptive docs endpoint handled manually
    redoc_url=None,
    openapi_url=None
)

# Mount API deception router
web_app.include_router(api_router)


def get_client_ip(request: Request) -> str:
    """Extracts actual client IP address, respecting reverse proxies, Cloudflare, and load balancers."""
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"



def get_or_create_session_id(request: Request, response: Optional[Response] = None) -> str:
    """Extracts session ID from cookie or generates and sets a new one."""
    session_id = request.cookies.get("deception_session_id")
    if not session_id:
        ip = get_client_ip(request)
        session_id = generate_session_id(prefix="ATK-WEB", ip=ip)
        if response:
            response.set_cookie(key="deception_session_id", value=session_id, httponly=True)
    return session_id


@web_app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    """
    Middleware intercepting EVERY incoming HTTP request to record
    source IP, HTTP method, endpoint, User-Agent, headers, and status code.
    """
    client_ip = get_client_ip(request)
    session_id = request.cookies.get("deception_session_id") or generate_session_id(prefix="ATK-WEB", ip=client_ip)
    path = request.url.path
    method = request.method

    response = await call_next(request)
    status_code = response.status_code

    # Ensure session cookie is attached to response
    if not request.cookies.get("deception_session_id"):
        response.set_cookie(key="deception_session_id", value=session_id, httponly=True)

    # Collect metadata
    headers_dict = dict(request.headers)
    # Remove large/noisy headers for cleanliness while keeping threat intel
    user_agent = headers_dict.get("user-agent", "Unknown")
    
    metadata = {
        "method": method,
        "path": path,
        "status_code": status_code,
        "user_agent": user_agent,
        "query_params": str(request.query_params),
        "content_type": headers_dict.get("content-type", ""),
    }

    # Prevent duplicate telemetry: let dedicated route handlers emit rich decoy/auth events
    handled_by_route = (
        (method == "POST" and path == "/login") or
        path.startswith("/fake-") or
        path in ("/admin", "/dashboard", "/.env", "/config", "/users", "/backup", "/credentials", "/favicon.ico")
    )

    if not handled_by_route and path != "/favicon.ico":
        # Emit structured http_request telemetry for general probes, scans, and crawler hits
        emit_event(
            service="web",
            event_type="http_request",
            event=f"{method} {path} HTTP/{request.scope.get('http_version', '1.1')} -> {status_code}",
            source_ip=client_ip,
            session_id=session_id,
            metadata=metadata,
        )

    return response


# ===================================================================
# Web Deception Routes
# ===================================================================

@web_app.api_route("/", methods=["GET", "POST", "HEAD"], response_class=HTMLResponse)
async def index_route(request: Request):
    return RedirectResponse(url="/login", status_code=303 if request.method == "POST" else 307)


@web_app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    client_ip = get_client_ip(request)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "portal_title": settings.WEB_TITLE,
            "hostname": settings.HONEYPOT_HOSTNAME,
            "target_ip": settings.HONEYPOT_TARGET_IP,
            "port": settings.WEB_PORT,
            "error": None
        }
    )


@web_app.post("/login")
async def login_post(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    username = "unknown"
    password = "unknown"

    # 1. Try reading as Form data
    try:
        form_data = await request.form()
        if "username" in form_data:
            username = str(form_data.get("username", ""))
        if "password" in form_data:
            password = str(form_data.get("password", ""))
    except Exception:
        pass

    # 2. If not found in form, try JSON body
    if username == "unknown":
        try:
            json_data = await request.json()
            if isinstance(json_data, dict):
                username = json_data.get("username", json_data.get("user", "unknown"))
                password = json_data.get("password", json_data.get("pass", "unknown"))
        except Exception:
            pass

    # 3. If still unknown, check query parameters
    if username == "unknown":
        username = request.query_params.get("username", request.query_params.get("user", "unknown"))
        password = request.query_params.get("password", request.query_params.get("pass", "unknown"))

    # Telemetry: Record login credential probe
    emit_event(
        service="web",
        event_type="auth_attempt",
        event=f"Web login attempt: user='{username}', pass='{password}'",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"username": username, "password": password, "endpoint": "/login"}
    )

    # Deceptive behavior: grant access for admin credentials to trap them in admin portal
    if str(username).lower() in ("admin", "admin@corp.internal", "root", "superadmin") or "admin" in str(username).lower():
        response = RedirectResponse(url="/admin", status_code=303)
        response.set_cookie(key="deception_session_id", value=session_id, httponly=True)
        response.set_cookie(key="auth_token", value=f"jwt_decoy_{session_id}", httponly=True)
        return response

    # Otherwise display simulated MFA/auth error
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "portal_title": settings.WEB_TITLE,
            "hostname": settings.HONEYPOT_HOSTNAME,
            "target_ip": settings.HONEYPOT_TARGET_IP,
            "port": settings.WEB_PORT,
            "error": "Invalid Enterprise credentials or MFA token expired."
        },
        status_code=401
    )


@web_app.get("/admin", response_class=HTMLResponse)
@web_app.get("/dashboard", response_class=HTMLResponse)
async def admin_portal(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    # Trigger decoy alarm
    decoy_manager.check_and_trigger(
        target_str="fake-admin",
        service="web",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"route": "/admin"}
    )

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "username": "superadmin",
            "hostname": settings.HONEYPOT_HOSTNAME,
            "target_ip": settings.HONEYPOT_TARGET_IP
        }
    )


# ===================================================================
# Decoy Resource Endpoints (Direct Web Probes)
# ===================================================================

@web_app.get("/fake-config")
@web_app.get("/config")
@web_app.get("/.env")
async def fake_config_decoy(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    # Trigger decoy event
    _, synthetic_data = decoy_manager.check_and_trigger(
        target_str="fake-config",
        service="web",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"url": str(request.url)}
    ) or ("fake-config", {})

    return JSONResponse(content=synthetic_data, status_code=200)


@web_app.get("/fake-users")
@web_app.get("/users")
async def fake_users_decoy(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    _, synthetic_data = decoy_manager.check_and_trigger(
        target_str="fake-users",
        service="web",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"url": str(request.url)}
    ) or ("fake-users", [])

    return JSONResponse(content=synthetic_data, status_code=200)


@web_app.get("/fake-backup")
@web_app.get("/backup")
@web_app.get("/backup.sql")
async def fake_backup_decoy(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    _, synthetic_data = decoy_manager.check_and_trigger(
        target_str="fake-backup",
        service="web",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"url": str(request.url)}
    ) or ("fake-backup", "-- Decoy SQL Backup")

    return PlainTextResponse(content=str(synthetic_data), media_type="text/plain")


@web_app.get("/fake-credentials")
@web_app.get("/credentials.txt")
async def fake_credentials_decoy(request: Request):
    client_ip = get_client_ip(request)
    session_id = get_or_create_session_id(request)

    _, synthetic_data = decoy_manager.check_and_trigger(
        target_str="fake-credentials",
        service="web",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"url": str(request.url)}
    ) or ("fake-credentials", "# Credentials Decoy")

    return PlainTextResponse(content=str(synthetic_data), media_type="text/plain")


@web_app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt(request: Request):
    """Classic decoy bait in robots.txt leading attackers to fake sensitive endpoints."""
    return """User-agent: *
Disallow: /admin
Disallow: /fake-config
Disallow: /fake-users
Disallow: /fake-backup
Disallow: /api/admin
Disallow: /api/config
"""


@web_app.get("/docs")
async def web_docs(request: Request):
    """Bait docs route."""
    return RedirectResponse(url="/api/docs")
