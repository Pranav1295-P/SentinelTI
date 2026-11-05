"""FastAPI application. In development it also serves the front-end, so both share one origin."""

import logging
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.agents.llm import configure_tracing
from app.api.routes import analyses, auth, health
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.security import signing_key

logger = logging.getLogger("sentinelti.api")
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}
FRONTEND_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store"
        return response


def create_app() -> FastAPI:
    configure_logging()
    configure_tracing()
    signing_key()  # Fail at startup, not at first login, if production has no secret.

    production = settings.environment == "production"
    app = FastAPI(
        title="SentinelTI API",
        version="0.1.0",
        docs_url=None if production else "/api/docs",
        redoc_url=None,
        openapi_url=None if production else "/api/openapi.json",
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled error", extra={"request_id": request_id, "path": request.url.path})
            response = JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)
        response.headers["X-Request-ID"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        if request.url.path.startswith("/api/docs"):
            pass  # Swagger UI loads its own CDN assets.
        elif request.url.path.startswith("/api"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        else:
            response.headers["Content-Security-Policy"] = FRONTEND_CSP
        if request.url.path.startswith("/api"):
            logger.info("request", extra={
                "request_id": request_id, "method": request.method, "path": request.url.path,
                "status": response.status_code, "ms": round((time.perf_counter() - started) * 1000),
            })
        return response

    api = APIRouter(prefix="/api")
    api.include_router(health.router)
    api.include_router(auth.router)
    api.include_router(analyses.router)
    app.include_router(api)

    if FRONTEND_DIR.is_dir():
        app.mount("/", NoCacheStaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    return app


app = create_app()
