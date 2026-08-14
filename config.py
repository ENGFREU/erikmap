from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# Значения по умолчанию, подобранные под "абсолютную скорость".
DEFAULT_TIMEOUT = 1.0          # секунд на одно TCP-соединение
DEFAULT_CONCURRENCY = 1500     # одновременных сокетов
DEFAULT_PORTS = 2000           # сколько первых портов сканировать по -p-

_PROXY_RE = re.compile(
    r"^(?P<scheme>socks5|socks5h|socks4|http|https)://"
    r"(?:(?P<user>[^:@/]+)(?::(?P<password>[^@/]*))?@)?"
    r"(?P<host>[^:@/]+):(?P<port>\d{1,5})/?$",
    re.IGNORECASE,
)


def config_path() -> Path:
    """Путь к файлу конфигурации."""
    env = os.environ.get("ERIKMAP_CONFIG")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base).expanduser() / "erikmap" / "config.json"


def validate_proxy(url: str) -> str:
    """Проверяет строку прокси и возвращает её же нормализованной.

    Поддерживаются схемы: socks5, socks5h, socks4, http, https.
    Формат: scheme://[user[:pass]@]host:port
    """
    url = url.strip()
    m = _PROXY_RE.match(url)
    if not m:
        raise ValueError(
            "Некорректный прокси. Ожидается вид "
            "socks5://user:pass@host:port или http://host:port"
        )
    port = int(m.group("port"))
    if not (1 <= port <= 65535):
        raise ValueError("Порт прокси должен быть в диапазоне 1..65535")
    return url


@dataclass
class Config:
    """Настройки erikmap, сохраняемые между запусками."""

    proxy: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    ports: int = DEFAULT_PORTS
    extra: dict[str, Any] = field(default_factory=dict)

    # --- сериализация -----------------------------------------------------

    @classmethod
    def load(cls) -> "Config":
        """Загружает конфиг с диска. Если файла нет — значения по умолчанию."""
        path = config_path()
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls()
        known = {f for f in cls().__dict__ if f != "extra"}
        kwargs = {k: v for k, v in data.items() if k in known}
        extra = {k: v for k, v in data.items() if k not in known}
        cfg = cls(**kwargs)
        cfg.extra = extra
        return cfg

    def save(self) -> Path:
        """Сохраняет конфиг на диск (создаёт директории при необходимости)."""
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        extra = payload.pop("extra", {}) or {}
        payload.update(extra)
        payload = {k: v for k, v in payload.items() if v is not None}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(path, 0o600)  # в прокси может быть пароль — не светим его
        except OSError:
            pass
        return path

    def set_proxy(self, url: Optional[str]) -> None:
        self.proxy = validate_proxy(url) if url else None
