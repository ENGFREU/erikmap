from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional


@dataclass
class PortResult:
    port: int
    is_open: bool


@dataclass
class ScanReport:
    host: str
    ip: str
    open_ports: list[int]
    scanned: int
    duration: float
    via_proxy: bool


# --- разбор диапазона портов, (port diapasone) ----------------------------------------------

def parse_ports(spec: str, default_count: int) -> list[int]:
    """Разбирает спецификацию портов.

      "-"          -> первые default_count портов (флаг -p-)
      "1-2000"     -> диапазон
      "22,80,443"  -> список
      "1-100,443"  -> смешанно
    """
    spec = spec.strip()
    if spec in ("", "-"):
        return list(range(1, default_count + 1))

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo = int(lo_s) if lo_s else 1
            hi = int(hi_s) if hi_s else 65535
            if lo > hi:
                lo, hi = hi, lo
            for p in range(max(1, lo), min(65535, hi) + 1):
                ports.add(p)
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


# --- разрешение имени в IP (extension ip)--------------------------------------------------

async def resolve(host: str) -> str:
    """Резолвит хост в IP (или возвращает как есть, если это уже IP)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
        for family, *_rest, sockaddr in infos:
            return sockaddr[0]
    except OSError:
        pass
    return host


# --- проверка одного порта (1 port checking) --------------------------------------------------

async def _check_direct(host: str, port: int, timeout: float) -> bool:
    """Прямое TCP-соединение без прокси."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    else:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
        except (asyncio.TimeoutError, OSError):
            pass
        return True


def _build_proxy(proxy_url: str):

    try:
        from python_socks.async_.asyncio import Proxy  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Для работы через прокси нужен пакет python-socks:\n"
            "    pip install 'python-socks[asyncio]'"
        ) from exc
    return Proxy.from_url(proxy_url)


async def _check_via_proxy(proxy, host: str, port: int, timeout: float) -> bool:
    """Проверка порта через SOCKS/HTTP-прокси."""
    sock = None
    try:
        sock = await asyncio.wait_for(
            proxy.connect(dest_host=host, dest_port=port, timeout=timeout),
            timeout=timeout + 0.5,
        )
        return True
    except Exception:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --- основной проход --------------------------------------------------------

async def scan(
    host: str,
    ports: list[int],
    *,
    timeout: float,
    concurrency: int,
    proxy_url: Optional[str] = None,
    on_open: Optional[Callable[[int], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> ScanReport:
    """Сканирует список портов и возвращает отчёт.

    on_open(port)         — вызывается сразу, как только найден открытый порт.
    on_progress(done, total) — вызывается по мере прохождения.
    """
    ip = await resolve(host)
    proxy = _build_proxy(proxy_url) if proxy_url else None

    sem = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []
    done = 0
    total = len(ports)
    start = time.perf_counter()

    async def worker(port: int) -> None:
        nonlocal done
        async with sem:
            if proxy is not None:
                is_open = await _check_via_proxy(proxy, ip, port, timeout)
            else:
                is_open = await _check_direct(ip, port, timeout)
        if is_open:
            open_ports.append(port)
            if on_open:
                on_open(port)
        done += 1
        if on_progress and (done % 64 == 0 or done == total):
            on_progress(done, total)

    await asyncio.gather(*(worker(p) for p in ports))
    open_ports.sort()
    duration = time.perf_counter() - start
    return ScanReport(
        host=host,
        ip=ip,
        open_ports=open_ports,
        scanned=total,
        duration=duration,
        via_proxy=proxy is not None,
