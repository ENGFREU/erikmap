from __future__ import annotations

import asyncio
import platform
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class PingResult:
    host: str
    alive: bool
    rtt_ms: Optional[float]  # приблизительное round-trip time
    raw: str


def _build_cmd(host: str, count: int, timeout: float) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        # -n количество, -w таймаут в миллисекундах
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if system == "darwin":
        # macOS: -c количество, -t общий таймаут в секундах
        return ["ping", "-c", str(count), "-t", str(max(1, int(timeout))), host]
    # Linux и прочие: -c количество, -W таймаут ожидания ответа в секундах
    return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]


async def ping(host: str, count: int = 1, timeout: float = 1.0) -> PingResult:
    """Пингует хост и возвращает результат.

    Работает асинхронно, чтобы не блокировать событийный цикл.
    """
    cmd = _build_cmd(host, count, timeout)
    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout * count + 2
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return PingResult(host, False, None, "timeout")
    except FileNotFoundError:
        return PingResult(host, False, None, "утилита ping не найдена")

    elapsed_ms = (time.perf_counter() - start) * 1000
    out = stdout.decode(errors="replace")
    alive = proc.returncode == 0
    rtt = _parse_rtt(out)
    return PingResult(host, alive, rtt if rtt is not None else (elapsed_ms if alive else None), out.strip())
