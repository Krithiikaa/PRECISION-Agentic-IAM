"""Domain-error to HTTP mapping, shared by every service.

Defined once so the IAM API, the ANS service and the tests cannot drift apart
about what a NotFoundError looks like on the wire.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.errors import ConflictError, IdentityError, KeyStoreError, NotFoundError

ERROR_STATUS: list[tuple[type[Exception], int, str]] = [
    (NotFoundError, 404, "NOT_FOUND"),
    (ConflictError, 409, "CONFLICT"),
    (IdentityError, 400, "IDENTITY_ERROR"),
    (KeyStoreError, 500, "KEYSTORE_ERROR"),
]


def install_error_handlers(app: FastAPI) -> None:
    for exception_type, status_code, code in ERROR_STATUS:
        def make(status_code: int, code: str):
            async def handler(request: Request, exc: Exception) -> JSONResponse:
                return JSONResponse(status_code=status_code,
                                    content={"error": code, "detail": str(exc)})
            return handler

        app.add_exception_handler(exception_type, make(status_code, code))
