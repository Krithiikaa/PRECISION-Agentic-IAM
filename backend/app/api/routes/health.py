"""Health and readiness.

/health always answers (it is a diagnostic).
/ready returns 503 when a dependency the API needs is not usable, so an
orchestrator does not route traffic to a broken instance.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.deps import KeyStoreDep, LLMDep, SessionDep, SettingsDep
from app.core.config import DEV_MASTER_KEY

router = APIRouter(tags=["health"])


async def _database_check(session) -> dict[str, Any]:
    try:
        await session.execute(text("SELECT 1"))
        return {"available": True, "detail": "OK"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "detail": f"{type(exc).__name__}: {exc}"}


@router.get("/health")
async def health(
    session: SessionDep, keystore: KeyStoreDep, llm: LLMDep, settings: SettingsDep
) -> dict[str, Any]:
    llm_health = await llm.health()
    return {
        "service": "agentic-iam-api",
        "status": "UP",
        "environment": settings.env,
        "phase": 1,
        "database": await _database_check(session),
        "llm": {
            "available": llm_health.available,
            "provider": llm_health.provider,
            "model": llm_health.model,
            "base_url": llm_health.base_url,
            "detail": llm_health.detail,
            "models_present": llm_health.models_present,
        },
        "keystore": {
            "backend": keystore.backend_name,
            "using_development_master_key": settings.keystore_master_key == DEV_MASTER_KEY,
        },
    }


@router.get("/ready")
async def ready(session: SessionDep, llm: LLMDep) -> JSONResponse:
    database = await _database_check(session)
    llm_health = await llm.health()
    checks = {"database": database["available"], "llm": llm_health.available}
    ok = all(checks.values())
    return JSONResponse(
        status_code=200 if ok else 503,
        content={
            "ready": ok,
            "checks": checks,
            "details": {"database": database["detail"], "llm": llm_health.detail},
        },
    )
