"""Dependency-free terminal progress reporting shared by long-running scripts."""

from __future__ import annotations

import sys
import threading
import time
from typing import TextIO


def _duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class TerminalProgressBar:
    """Small dependency-free TTY progress bar with rate, elapsed time, and ETA."""

    def __init__(
        self,
        description: str,
        total: int,
        *,
        enabled: bool = True,
        stream: TextIO = sys.stderr,
        width: int = 28,
    ) -> None:
        self.description = description
        self.total = max(0, total)
        self.stream = stream
        self.width = width
        self.current = 0
        self.detail = ""
        self.started = time.monotonic()
        self.last_length = 0
        is_tty = bool(getattr(stream, "isatty", lambda: False)())
        self.visible = enabled and is_tty and self.total > 0
        if self.visible:
            self._render()

    def _render(self) -> None:
        elapsed = max(0.0, time.monotonic() - self.started)
        fraction = min(1.0, self.current / self.total) if self.total else 1.0
        filled = int(self.width * fraction)
        bar = "#" * filled + "-" * (self.width - filled)
        rate = self.current / elapsed if elapsed > 0 else 0.0
        eta = (self.total - self.current) / rate if rate > 0 else 0.0
        line = (
            f"\r{self.description} [{bar}] {self.current}/{self.total} "
            f"({fraction * 100:5.1f}%) rate={rate:.2f}/s "
            f"elapsed={_duration(elapsed)} eta={_duration(eta)}"
        )
        if self.detail:
            line += f" | {self.detail}"
        padding = " " * max(0, self.last_length - len(line))
        self.stream.write(line + padding)
        self.stream.flush()
        self.last_length = len(line)

    def update(self, amount: int = 1, *, detail: str | None = None) -> None:
        self.current = min(self.total, self.current + max(0, amount))
        if detail is not None:
            self.detail = detail
        if self.visible:
            self._render()

    def make_room(self) -> None:
        """Finish the current display line before ordinary log output."""

        if self.visible:
            self.stream.write("\n")
            self.stream.flush()
            self.last_length = 0

    def close(self) -> None:
        if self.visible:
            self._render()
            self.stream.write("\n")
            self.stream.flush()


class PhaseHeartbeat:
    """Show liveness and elapsed time while a blocking phase is running."""

    SPINNER = ("|", "/", "-", "\\")

    def __init__(
        self,
        description: str,
        *,
        enabled: bool = True,
        stream: TextIO = sys.stderr,
        tty_interval_seconds: float = 0.5,
        log_interval_seconds: float = 30.0,
    ) -> None:
        self.description = description
        self.enabled = enabled
        self.stream = stream
        self.tty_interval_seconds = tty_interval_seconds
        self.log_interval_seconds = log_interval_seconds
        self.started = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_length = 0
        self.visible = enabled and bool(
            getattr(stream, "isatty", lambda: False)()
        )

    def __enter__(self) -> PhaseHeartbeat:
        self.started = time.monotonic()
        self.stream.write(f"{self.description}: started\n")
        self.stream.flush()
        if self.enabled:
            self._thread = threading.Thread(
                target=self._run,
                name="socrates-phase-heartbeat",
                daemon=True,
            )
            self._thread.start()
        return self

    def _run(self) -> None:
        tick = 0
        next_log = self.log_interval_seconds
        interval = (
            self.tty_interval_seconds if self.visible else min(1.0, next_log)
        )
        while not self._stop.wait(interval):
            elapsed = time.monotonic() - self.started
            if self.visible:
                marker = self.SPINNER[tick % len(self.SPINNER)]
                line = (
                    f"\r{self.description}: {marker} elapsed={_duration(elapsed)}"
                )
                padding = " " * max(0, self._last_length - len(line))
                self.stream.write(line + padding)
                self.stream.flush()
                self._last_length = len(line)
                tick += 1
            elif elapsed >= next_log:
                self.stream.write(
                    f"{self.description}: still running, "
                    f"elapsed={_duration(elapsed)}\n"
                )
                self.stream.flush()
                next_log += self.log_interval_seconds

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.tty_interval_seconds * 2))
        elapsed = time.monotonic() - self.started
        if self.visible and self._last_length:
            self.stream.write("\r" + " " * self._last_length + "\r")
        status = "completed" if exc_type is None else "failed"
        self.stream.write(
            f"{self.description}: {status}, elapsed={_duration(elapsed)}\n"
        )
        self.stream.flush()
