"""
API Honeypot Endpoints.
Provides controlled deception endpoints:
  - POST /api/login
  - GET  /api/users
  - GET  /api/admin
  - GET  /api/config
  - GET  /api/v1/health
  - GET  /api/swagger.json
Produces structured JSON telemetry events for every invocation.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from honeypot.common.event_schema import generate_session_id
from honeypot.common.telemetry import emit_event
from honeypot.decoys.decoy_manager import decoy_manager
from honeypot.config.settings import settings

api_router = APIRouter(prefix="/api", tags=["API Deception"])


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_session_id(request: Request) -> str:
    # Check headers or cookies
    session_id = (
        request.headers.get("x-session-id")
        or request.cookies.get("deception_session_id")
        or generate_session_id(prefix="ATK-API", ip=get_client_ip(request))
    )
    return session_id


class LoginPayload(BaseModel):
    username: Optional[str] = "admin"
    password: Optional[str] = "password"


@api_router.get("")
@api_router.get("/")
async def api_root(request: Request):
    """API Root index disclosing fake API documentation and endpoints."""
    return {
        "service": "Internal Enterprise Core API Gateway",
        "version": "v2.4-enterprise",
        "status": "active",
        "endpoints": [
            "/api/login",
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/v1/health",
            "/api/swagger.json"
        ]
    }


@api_router.get("/docs")
async def api_docs_redirect(request: Request):
    return JSONResponse(content={
        "title": "Internal Enterprise API Documentation",
        "spec_url": "/api/swagger.json",
        "auth_header": "Authorization: Bearer <token>",
        "supported_endpoints": ["/api/login", "/api/users", "/api/admin", "/api/config", "/api/v1/health"]
    })


@api_router.post("/login")
async def api_login(request: Request, payload: Optional[LoginPayload] = None):
    """Fake API Authentication endpoint producing synthetic JWTs."""
    client_ip = get_client_ip(request)
    session_id = get_session_id(request)
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore")

    user = payload.username if payload else "unknown"
    pwd = payload.password if payload else "unknown"

    emit_event(
        service="api",
        event_type="api_call",
        event=f"POST /api/login (user='{user}')",
        source_ip=client_ip,
        session_id=session_id,
        metadata={
            "endpoint": "/api/login",
            "method": "POST",
            "username": user,
            "password": pwd,
            "raw_payload": body_str[:256]
        }
    )

    # Return fake JWT token
    fake_jwt = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{session_id}.fakeDeceptionSignature2026"
    return {
        "status": "success",
        "message": "Authentication successful",
        "token_type": "Bearer",
        "access_token": fake_jwt,
        "expires_in": 3600,
        "user_profile": {
            "username": user,
            "role": "cluster_admin",
            "permissions": ["read:all", "write:all", "admin:access"]
        }
    }


@api_router.get("/users")
async def api_users(request: Request):
    """Fake Users endpoint returning synthetic employee records."""
    client_ip = get_client_ip(request)
    session_id = get_session_id(request)

    # Trigger decoy access
    _, synthetic_users = decoy_manager.check_and_trigger(
        target_str="fake-users",
        service="api",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"endpoint": "/api/users"}
    ) or ("fake-users", [])

    emit_event(
        service="api",
        event_type="api_call",
        event="GET /api/users",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"endpoint": "/api/users", "records_returned": len(synthetic_users) if isinstance(synthetic_users, list) else 1}
    )

    return {
        "status": "success",
        "total": len(synthetic_users) if isinstance(synthetic_users, list) else 5,
        "data": synthetic_users
    }


@api_router.get("/admin")
async def api_admin(request: Request):
    """Fake Admin endpoint returning synthetic administrative controls."""
    client_ip = get_client_ip(request)
    session_id = get_session_id(request)

    # Trigger decoy access
    _, synthetic_admin = decoy_manager.check_and_trigger(
        target_str="fake-admin",
        service="api",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"endpoint": "/api/admin"}
    ) or ("fake-admin", {})

    emit_event(
        service="api",
        event_type="api_call",
        event="GET /api/admin",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"endpoint": "/api/admin", "action": "inspect_admin_controls"}
    )

    return {
        "status": "success",
        "environment": "production-eu-central",
        "admin_config": synthetic_admin
    }


@api_router.get("/config")
async def api_config(request: Request):
    """Fake Config endpoint returning synthetic infrastructure secrets."""
    client_ip = get_client_ip(request)
    session_id = get_session_id(request)

    # Trigger decoy access
    _, synthetic_config = decoy_manager.check_and_trigger(
        target_str="fake-config",
        service="api",
        source_ip=client_ip,
        session_id=session_id,
        extra_metadata={"endpoint": "/api/config"}
    ) or ("fake-config", {})

    emit_event(
        service="api",
        event_type="api_call",
        event="GET /api/config",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"endpoint": "/api/config", "leak_type": "production_secrets"}
    )

    return {
        "status": "success",
        "config": synthetic_config
    }


@api_router.get("/v1/health")
async def api_health(request: Request):
    """Simulated health check endpoint."""
    client_ip = get_client_ip(request)
    session_id = get_session_id(request)

    emit_event(
        service="api",
        event_type="api_call",
        event="GET /api/v1/health",
        source_ip=client_ip,
        session_id=session_id,
        metadata={"endpoint": "/api/v1/health"}
    )

    return {
        "status": "UP",
        "node": settings.HONEYPOT_HOSTNAME,
        "database": "CONNECTED",
        "cache": "CONNECTED"
    }


@api_router.get("/swagger.json")
async def api_swagger(request: Request):
    """Synthetic Swagger/OpenAPI spec baiting attackers."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Internal Enterprise Core API", "version": "2.4.0"},
        "paths": {
            "/api/login": {"post": {"summary": "Authenticate User"}},
            "/api/users": {"get": {"summary": "List Corporate Users"}},
            "/api/admin": {"get": {"summary": "Administrative Console"}},
            "/api/config": {"get": {"summary": "System Configuration & Secrets"}},
            "/fake-backup": {"get": {"summary": "Database Backup Archive"}},
            "/fake-credentials": {"get": {"summary": "Infrastructure Secrets Vault"}}
        }
    }


# ===================================================================
# Live Threat Intelligence & Attacker Technique Forensics
# ===================================================================

@api_router.get("/threat-intel")
async def get_live_threat_intelligence():
    """Returns aggregated threat intelligence and learned techniques from all attackers."""
    from honeypot.common.threat_learning_engine import threat_engine
    dossiers = threat_engine.get_all_attacker_dossiers()
    return {
        "status": "active",
        "total_attackers_tracked": len(dossiers),
        "backend_target": settings.BACKEND_URL,
        "attackers": dossiers,
    }


@api_router.get("/threat-intel/{session_or_ip}")
async def get_attacker_profile(session_or_ip: str):
    """Returns deep threat forensic dossier for a specific attacker IP or session."""
    from honeypot.common.threat_learning_engine import threat_engine
    profile = threat_engine.get_or_create_profile(session_or_ip)
    return {
        "status": "success",
        "dossier": profile.to_dict()
    }

