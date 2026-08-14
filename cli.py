"""Командный интерфейс erikmap.

Примеры:
    erikmap -p- 1.2.3.4            # пинг + первые 2000 портов
    erikmap -p 1-2000 example.com  # явный диапазон
    erikmap -p 22,80,443 10.0.0.1  # список портов
    erikmap --no-ping -p- 1.2.3.4  # без пинга
    erikmap --proxy socks5://user:pass@host:1080 -p- 1.2.3.4

Настройка прокси (сохраняется между запусками):
    erikmap config --proxy socks5://user:pass@127.0.0.1:1080
    erikmap config                 # интерактивный ввод
    erikmap config --show
    erikmap config --clear
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Optional

from . import __version__
from .config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT,
    Config,
    config_path,
    validate_proxy,
)
from .pinger import ping
from .scanner import parse_ports, scan

# ---- ANSI-цвета (минималистично, отключаются в неинтерактивном выводе) ----

_TTY = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def bold(t: str) -> str:
    return _c(t, "1")


def green(t: str) -> str:
    return _c(t, "32")


def red(t: str) -> str:
    return _c(t, "31")


def dim(t: str) -> str:
    return _c(t, "2")


def cyan(t: str) -> str:
    return _c(t, "36")


# ---- частые сервисы для наглядности ---------------------------------------

_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 587: "smtp", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


def service_name(port: int) -> str:
    return _SERVICES.get(port, "")


# ---------------------------------------------------------------------------
# Команда сканирования
# ---------------------------------------------------------------------------

def _run_scan(args: argparse.Namespace) -> int:
    cfg = Config.load()

    # приоритет: флаг из командной строки > сохранённый конфиг
    proxy_url: Optional[str] = args.proxy if args.proxy is not None else cfg.proxy
    if proxy_url:
        try:
            proxy_url = validate_proxy(proxy_url)
        except ValueError as e:
            print(red(f"Ошибка прокси: {e}"), file=sys.stderr)
            return 2

    timeout = args.timeout if args.timeout is not None else cfg.timeout
    concurrency = args.concurrency if args.concurrency is not None else cfg.concurrency
    default_count = cfg.ports or DEFAULT_PORTS

    spec = args.ports if args.ports is not None else "-"
    try:
        ports = parse_ports(spec, default_count)
    except ValueError:
        print(red(f"Некорректная спецификация портов: {spec}"), file=sys.stderr)
        return 2

    if not ports:
        print(red("Нет портов для сканирования."), file=sys.stderr)
        return 2

    return asyncio.run(
        _scan_async(
            host=args.target,
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            proxy_url=proxy_url,
            do_ping=not args.no_ping,
            open_only=args.open,
        )
    )


async def _scan_async(
    *,
    host: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
    proxy_url: Optional[str],
    do_ping: bool,
    open_only: bool,
) -> int:
    print(bold(f"erikmap v{__version__}") + dim(f"  ->  {host}"))
    if proxy_url:
        # прячем пароль при выводе
        shown = proxy_url
        if "@" in shown and ":" in shown.split("@")[0]:
            head, tail = shown.split("@", 1)
            scheme_user = head.rsplit(":", 1)[0]
            shown = f"{scheme_user}:***@{tail}"
        print(dim(f"прокси: {shown}"))

    # --- фаза 1: пинг -------------------------------------------------------
    if do_ping:
        sys.stdout.write(dim("пинг... "))
        sys.stdout.flush()
        pr = await ping(host, count=1, timeout=max(1.0, timeout))
        if pr.alive:
            rtt = f"{pr.rtt_ms:.1f} мс" if pr.rtt_ms is not None else "ok"
            print(green(f"хост отвечает ({rtt})"))
        else:
            print(red("нет ответа на ICMP") + dim(" — продолжаю сканирование"))

    # --- фаза 2: сканирование ----------------------------------------------
    total = len(ports)
    print(dim(f"сканирую {total} портов, потоков={concurrency}, таймаут={timeout}s"))

    last_line_len = 0

    def on_progress(done: int, total: int) -> None:
        nonlocal last_line_len
        if not _TTY:
            return
        pct = done * 100 // total
        line = f"\r  {done}/{total} ({pct}%)"
        last_line_len = len(line)
        sys.stdout.write(line)
        sys.stdout.flush()

    report = await scan(
        host,
        ports,
        timeout=timeout,
        concurrency=concurrency,
        proxy_url=proxy_url,
        on_progress=on_progress,
    )

    if _TTY and last_line_len:
        sys.stdout.write("\r" + " " * last_line_len + "\r")
        sys.stdout.flush()

    # --- вывод результата ---------------------------------------------------
    print()
    if report.ip != report.host:
        print(bold(f"Отчёт для {report.host} ({report.ip})"))
    else:
        print(bold(f"Отчёт для {report.ip}"))

    if report.open_ports:
        print(f"  {bold('PORT'):<12}{bold('STATE'):<10}{bold('SERVICE')}")
        for p in report.open_ports:
            svc = service_name(p)
            print(f"  {cyan(str(p)):<20}{green('open'):<18}{dim(svc)}")
    else:
        print(dim("  открытых портов не найдено"))

    rate = report.scanned / report.duration if report.duration > 0 else 0
    print()
    print(
        dim(
            f"готово за {report.duration:.2f}s  "
            f"({rate:,.0f} портов/с)  "
            f"открыто: {len(report.open_ports)}/{report.scanned}"
        )
    )
    return 0


# ---------------------------------------------------------------------------
# Команда config
# ---------------------------------------------------------------------------

def _run_config(args: argparse.Namespace) -> int:
    cfg = Config.load()

    if args.show:
        _print_config(cfg)
        return 0

    if args.clear:
        cfg.proxy = None
        path = cfg.save()
        print(green(f"Прокси удалён. Конфиг: {path}"))
        return 0

    changed = False

    # неинтерактивная установка через флаги
    if args.proxy is not None:
        try:
            cfg.set_proxy(args.proxy or None)
        except ValueError as e:
            print(red(str(e)), file=sys.stderr)
            return 2
        changed = True

    if args.timeout is not None:
        cfg.timeout = args.timeout
        changed = True
    if args.concurrency is not None:
        cfg.concurrency = args.concurrency
        changed = True
    if args.ports is not None:
        cfg.ports = args.ports
        changed = True

    # интерактивный режим, если ничего не передали флагами
    if not changed:
        changed = _interactive_config(cfg)

    if changed:
        path = cfg.save()
        print(green(f"Сохранено в {path}"))
        _print_config(cfg)
    else:
        print(dim("Изменений нет."))
    return 0


def _interactive_config(cfg: Config) -> bool:
    print(bold("Настройка erikmap"))
    print(dim("Оставьте поле пустым, чтобы не менять текущее значение.\n"))

    cur_proxy = cfg.proxy or "(не задан)"
    raw = input(f"Прокси [{cur_proxy}] (или 'none' чтобы убрать): ").strip()
    changed = False
    if raw:
        if raw.lower() in ("none", "нет", "-"):
            cfg.proxy = None
            changed = True
        else:
            try:
                cfg.set_proxy(raw)
                changed = True
            except ValueError as e:
                print(red(str(e)))

    raw = input(f"Таймаут соединения, сек [{cfg.timeout}]: ").strip()
    if raw:
        try:
            cfg.timeout = float(raw)
            changed = True
        except ValueError:
            print(red("Не число, пропускаю."))

    raw = input(f"Одновременных потоков [{cfg.concurrency}]: ").strip()
    if raw:
        try:
            cfg.concurrency = int(raw)
            changed = True
        except ValueError:
            print(red("Не число, пропускаю."))

    return changed


def _print_config(cfg: Config) -> None:
    print(bold("Текущая конфигурация:"))
    proxy = cfg.proxy or dim("(не задан)")
    print(f"  прокси      : {proxy}")
    print(f"  таймаут     : {cfg.timeout}s")
    print(f"  потоков     : {cfg.concurrency}")
    print(f"  портов (-p-): {cfg.ports}")
    print(dim(f"  файл        : {config_path()}"))


# ---------------------------------------------------------------------------
# Разбор аргументов
# ---------------------------------------------------------------------------

def build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="erikmap",
        description="Минималистичный высокоскоростной сканер первых 2000 портов.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "команда настройки:\n"
            "  erikmap config [--proxy URL] [--timeout N] [--concurrency N] [--show] [--clear]\n\n"
            "примеры:\n"
            "  erikmap -p- 1.2.3.4\n"
            "  erikmap -p 1-2000 example.com\n"
            "  erikmap --proxy socks5://user:pass@127.0.0.1:1080 -p- 1.2.3.4\n"
            "  erikmap config --proxy socks5://127.0.0.1:1080\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"erikmap {__version__}")
    p.add_argument("target", nargs="?", help="IP-адрес или домен цели")
    p.add_argument("-p", "--ports", dest="ports", nargs="?", const="-", default=None,
                   help="'-' или '-p-' = первые 2000; '1-2000'; '22,80,443'")
    p.add_argument("--proxy", dest="proxy", default=None,
                   help="прокси на этот запуск (переопределяет конфиг)")
    p.add_argument("--timeout", dest="timeout", type=float, default=None,
                   help=f"таймаут соединения, сек (по умолчанию {DEFAULT_TIMEOUT})")
    p.add_argument("-c", "--concurrency", dest="concurrency", type=int, default=None,
                   help=f"одновременных потоков (по умолчанию {DEFAULT_CONCURRENCY})")
    p.add_argument("--no-ping", dest="no_ping", action="store_true",
                   help="не пинговать перед сканированием")
    p.add_argument("--open", action="store_true",
                   help="в конце показать только открытые порты (по умолчанию так и есть)")
    return p


def build_config_parser() -> argparse.ArgumentParser:
    cfg = argparse.ArgumentParser(
        prog="erikmap config",
        description="Настройка прокси и параметров по умолчанию.",
    )
    cfg.add_argument("--proxy", nargs="?", const="", default=None,
                     help="строка прокси scheme://[user:pass@]host:port")
    cfg.add_argument("--timeout", type=float, help="таймаут соединения, сек")
    cfg.add_argument("--concurrency", type=int, help="одновременных потоков")
    cfg.add_argument("--ports", type=int, help="сколько первых портов сканировать по -p-")
    cfg.add_argument("--show", action="store_true", help="показать текущий конфиг")
    cfg.add_argument("--clear", action="store_true", help="удалить сохранённый прокси")
    return cfg


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Подкоманда config обрабатывается отдельным парсером, чтобы позиционный
    # target на верхнем уровне не конфликтовал с подкомандой.
    if argv and argv[0] == "config":
        cfg_args = build_config_parser().parse_args(argv[1:])
        return _run_config(cfg_args)

    parser = build_scan_parser()
    args = parser.parse_args(argv)

    if not args.target:
        parser.print_help()
        return 1

    try:
        return _run_scan(args)
    except KeyboardInterrupt:
        print("\n" + red("Прервано пользователем."), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
