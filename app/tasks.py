from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

STAGES = ("connect", "preflight", "install", "ipv6", "info")
MAX_LOG_LINES = 600


@dataclass
class Task:
    id: str
    session_id: str
    status: str = "queued"
    stage: str = "connect"
    message: str = "任务已进入队列"
    steps: dict[str, str] = field(default_factory=lambda: {s: "pending" for s in STAGES})
    logs: list[str] = field(default_factory=list)
    log_offset: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    expires_at: float | None = None

    def log(self, line: str) -> None:
        # Called from worker threads; list.append is atomic under the GIL.
        self.logs.append(line[:500])
        overflow = len(self.logs) - MAX_LOG_LINES
        if overflow > 0:
            del self.logs[:overflow]
            self.log_offset += overflow

    def public(self, since: int = 0) -> dict[str, Any]:
        start = max(0, since - self.log_offset)
        return {
            "id": self.id,
            "status": self.status,
            "stage": self.stage,
            "message": self.message,
            "steps": dict(self.steps),
            "logs": self.logs[start:],
            "log_next": self.log_offset + len(self.logs),
            "result": self.result if self.status == "success" else None,
            "error": self.error,
            "expires_at": self.expires_at,
        }


class Reporter:
    """Thread-safe-enough progress facade handed to the deployer."""

    def __init__(self, task: Task):
        self.task = task

    def stage(self, stage: str, message: str) -> None:
        task = self.task
        if stage in task.steps:
            for name in STAGES:
                if name == stage:
                    break
                if task.steps[name] == "running":
                    task.steps[name] = "done"
            task.steps[stage] = "running"
        task.stage, task.message = stage, message
        task.log(f"== {message}")

    def step(self, stage: str, status: str) -> None:
        if stage in self.task.steps:
            self.task.steps[stage] = status

    def info(self, message: str) -> None:
        self.task.message = message
        self.task.log(message)

    def log(self, line: str) -> None:
        self.task.log(line)


class TaskStore:
    def __init__(self, limit: int, ttl: int):
        self.tasks: dict[str, Task] = {}
        self.limit = limit
        self.semaphore = asyncio.Semaphore(limit)
        self.ttl = ttl
        self._lock = asyncio.Lock()

    def active_count(self) -> int:
        return sum(1 for t in self.tasks.values() if t.status in {"queued", "running"})

    async def create(self, session_id: str) -> Task:
        task = Task(uuid.uuid4().hex, session_id)
        async with self._lock:
            self.tasks[task.id] = task
        return task

    async def run(self, task: Task, factory: Callable[[Reporter], Awaitable[dict[str, Any]]]) -> None:
        async with self.semaphore:
            task.status = "running"
            reporter = Reporter(task)
            try:
                task.result = await factory(reporter)
                for name, value in task.steps.items():
                    if value == "running":
                        task.steps[name] = "done"
                task.status = "success"
                task.message = "部署完成"
            except asyncio.CancelledError:
                task.status = "failed"
                task.error = "任务已取消"
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI as a sanitized message
                task.status = "failed"
                task.error = str(exc) or "部署失败"
                if task.stage in task.steps:
                    task.steps[task.stage] = "failed"
                task.log(f"!! {task.error}")
            finally:
                task.finished_at = time.time()
                task.expires_at = task.finished_at + self.ttl

    async def get(self, task_id: str, session_id: str) -> Task | None:
        await self.cleanup()
        task = self.tasks.get(task_id)
        if not task or task.session_id != session_id:
            return None
        return task

    async def discard(self, task_id: str, session_id: str) -> bool:
        async with self._lock:
            task = self.tasks.get(task_id)
            if not task or task.session_id != session_id or task.status in {"queued", "running"}:
                return False
            self._wipe(task)
            del self.tasks[task_id]
            return True

    @staticmethod
    def _wipe(task: Task) -> None:
        task.result = None
        task.error = None
        task.logs.clear()
        task.status = "expired"

    async def cleanup(self) -> None:
        now = time.time()
        async with self._lock:
            for task_id, task in list(self.tasks.items()):
                if task.expires_at and task.expires_at <= now:
                    self._wipe(task)
                    del self.tasks[task_id]
