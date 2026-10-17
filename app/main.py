from __future__ import annotations

import asyncio
import hmac
import html
import logging
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field, SecretStr, field_validator

from .config import Settings
from .deployer import DeploymentError, DeploySpec, deploy
from .security import (
    TargetRejected,
    csrf_token,
    csrf_valid,
    resolve_and_validate_target,
    validate_hostname,
    validate_port,
    validate_username,
)
from .tasks import Reporter, TaskStore

BASE = Path(__file__).resolve().parent
logger = logging.getLogger("nodelite_auto_deploy")
SESSION_COOKIE = "nlad_session"
PRE_COOKIE = "nlad_pre"


class RateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, count: int, window: int) -> bool:
        now = time.time()
        bucket = self.events[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= count:
            return False
        bucket.append(now)
        return True


class DeployRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int | str | None = Field(default=None, validate_default=True)
    ssh_user: str | None = Field(default=None, max_length=32, validate_default=True)
    ssh_password: SecretStr = Field(min_length=1, max_length=512)
    disable_ipv6: bool = True
    authorized: bool = False

    @field_validator("host")
    @classmethod
    def host_valid(cls, value: str) -> str:
        return validate_hostname(value)

    @field_validator("ssh_port", mode="before")
    @classmethod
    def port_valid(cls, value: Any) -> int:
        if value is None or (isinstance(value, str) and not value.strip()):
            return 22
        return validate_port(value, "SSH 端口")

    @field_validator("ssh_user", mode="before")
    @classmethod
    def user_valid(cls, value: Any) -> str:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "root"
        return validate_username(str(value))


class State:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.serializer = URLSafeTimedSerializer(settings.session_secret, salt="nlad-session-v1")
        self.pre_serializer = URLSafeTimedSerializer(settings.session_secret, salt="nlad-login-v1")
        self.tasks = TaskStore(settings.max_concurrent_tasks, settings.task_ttl_seconds)
        self.login_limiter = RateLimiter()
        self.task_limiter = RateLimiter()
        self.background: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    for task in list(app.state.core.background):
        task.cancel()
    if app.state.core.background:
        await asyncio.gather(*app.state.core.background, return_exceptions=True)


def render(name: str, **values: str) -> str:
    text = (BASE / "static" / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", html.escape(value, quote=True))
    return text


def create_app(settings: Settings | None = None, deploy_fn=deploy) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(
        title="NodeLite Auto Deploy",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.core = State(settings)
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

    def session_id(request: Request) -> str:
        token = request.cookies.get(SESSION_COOKIE, "")
        try:
            payload = app.state.core.serializer.loads(token, max_age=settings.session_ttl_seconds)
        except (BadSignature, SignatureExpired):
            raise HTTPException(401, "请先登录") from None
        if not isinstance(payload, dict) or not payload.get("sid"):
            raise HTTPException(401, "请先登录")
        return str(payload["sid"])

    def require_csrf(request: Request, sid: str = Depends(session_id)) -> str:
        if not csrf_valid(settings.session_secret, sid, request.headers.get("x-csrf-token")):
            raise HTTPException(403, "CSRF 校验失败，请刷新页面后重试")
        return sid

    def client_key(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def same_origin(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin or origin == "null":
            return origin is None
        return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not same_origin(request):
            return JSONResponse({"detail": "跨站请求已拒绝"}, status_code=403)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Content-Security-Policy": (
                    "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                    "script-src 'self'; connect-src 'self'; form-action 'self'; "
                    "frame-ancestors 'none'; base-uri 'none'"
                ),
            }
        )
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        # Never echo request input back (it may contain the SSH password).
        messages = []
        for error in exc.errors():
            ctx = error.get("ctx") or {}
            if isinstance(ctx.get("error"), ValueError):
                messages.append(str(ctx["error"]))
            else:
                field = ".".join(str(p) for p in error.get("loc", [])[1:]) or "请求"
                messages.append(f"{field} 字段无效")
        return JSONResponse({"detail": "；".join(messages) or "请求无效"}, status_code=422)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str = ""):
        try:
            session_id(request)
            return RedirectResponse("/", 303)
        except HTTPException:
            pass
        nonce = secrets.token_urlsafe(24)
        messages = {"1": "用户名或密码错误", "2": "登录尝试过多，请稍后再试", "3": "页面已过期，请重试"}
        response = HTMLResponse(
            render("login.html", csrf=app.state.core.pre_serializer.dumps(nonce), error=messages.get(error, ""))
        )
        response.set_cookie(
            PRE_COOKIE, nonce, max_age=900, httponly=True, secure=settings.cookie_secure,
            samesite="strict", path="/login",
        )
        return response

    @app.post("/login")
    async def login(
        request: Request,
        username: str = Form(..., max_length=128),
        password: str = Form(..., max_length=512),
        csrf: str = Form("", max_length=512),
    ):
        state: State = app.state.core
        if not state.login_limiter.allow(client_key(request), settings.login_attempts, settings.login_window_seconds):
            return RedirectResponse("/login?error=2", 303)
        try:
            nonce = state.pre_serializer.loads(csrf, max_age=900)
        except (BadSignature, SignatureExpired):
            nonce = None
        cookie = request.cookies.get(PRE_COOKIE, "")
        if not nonce or not cookie or not hmac.compare_digest(str(nonce), cookie):
            return RedirectResponse("/login?error=3", 303)
        ok = hmac.compare_digest(username.encode(), settings.admin_user.encode())
        ok = hmac.compare_digest(password.encode(), settings.admin_password.encode()) and ok
        if not ok:
            logger.warning("login failed from %s", client_key(request))
            return RedirectResponse("/login?error=1", 303)
        token = state.serializer.dumps({"sid": secrets.token_urlsafe(24)})
        response = RedirectResponse("/", 303)
        response.set_cookie(
            SESSION_COOKIE, token, max_age=settings.session_ttl_seconds, httponly=True,
            secure=settings.cookie_secure, samesite="strict", path="/",
        )
        response.delete_cookie(PRE_COOKIE, path="/login")
        return response

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("", max_length=256)):
        try:
            sid = session_id(request)
        except HTTPException:
            return RedirectResponse("/login", 303)
        if not csrf_valid(settings.session_secret, sid, csrf):
            raise HTTPException(403, "CSRF 校验失败")
        response = RedirectResponse("/login", 303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        try:
            sid = session_id(request)
        except HTTPException:
            return RedirectResponse("/login", 303)
        return HTMLResponse(
            render(
                "index.html",
                csrf=csrf_token(settings.session_secret, sid),
                ttl=str(settings.task_ttl_seconds // 60),
            )
        )

    @app.post("/api/tasks", status_code=202)
    async def create_task(payload: DeployRequest, sid: str = Depends(require_csrf)):
        state: State = app.state.core
        if not payload.authorized:
            raise HTTPException(422, "请先确认你拥有或已获授权管理这台服务器")
        if state.tasks.active_count() >= settings.max_concurrent_tasks * 2:
            raise HTTPException(429, "当前排队任务过多，请稍后再试")
        if not state.task_limiter.allow(sid, settings.task_attempts, settings.task_window_seconds):
            raise HTTPException(429, "创建任务过于频繁，请稍后再试")
        try:
            target = await resolve_and_validate_target(payload.host, settings)
        except (ValueError, TargetRejected) as exc:
            raise HTTPException(422, str(exc)) from exc
        holder = {
            "spec": DeploySpec(
                host=target.original,
                resolved_addresses=target.addresses,
                typed_ipv6=target.typed_ipv6,
                ssh_port=int(payload.ssh_port),
                ssh_user=str(payload.ssh_user),
                ssh_password=payload.ssh_password.get_secret_value(),
                disable_ipv6=payload.disable_ipv6,
            )
        }
        del payload
        task = await state.tasks.create(sid)

        async def worker(reporter: Reporter) -> dict[str, Any]:
            spec = holder.pop("spec")
            try:
                return await asyncio.to_thread(deploy_fn, spec, reporter, settings)
            except DeploymentError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise DeploymentError(f"部署异常：{type(exc).__name__}") from None
            finally:
                # CPython strings cannot be zeroed; drop every reference we hold.
                spec.ssh_password = None
                del spec

        runner = asyncio.create_task(state.tasks.run(task, worker))
        state.background.add(runner)
        runner.add_done_callback(state.background.discard)
        return {"task_id": task.id, "status": task.status}

    @app.get("/api/tasks/{task_id}")
    async def get_task(task_id: str, since: int = 0, sid: str = Depends(session_id)):
        task = await app.state.core.tasks.get(task_id, sid)
        if not task:
            raise HTTPException(404, "任务不存在、已过期或无权访问")
        return task.public(max(0, since))

    @app.delete("/api/tasks/{task_id}")
    async def delete_task(task_id: str, sid: str = Depends(require_csrf)):
        if not await app.state.core.tasks.discard(task_id, sid):
            raise HTTPException(404, "任务不存在、仍在运行或无权访问")
        return {"ok": True}

    return app


def run() -> None:  # pragma: no cover - exercised by the systemd unit
    import uvicorn

    settings = Settings.load()
    if settings.allow_public_listen:
        logger.warning("WEB_ALLOW_PUBLIC_LISTEN=1：本程序处理 root 密码，务必放在 HTTPS 之后")
    uvicorn.run(
        create_app(settings),
        host=settings.listen_host,
        port=settings.listen_port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
