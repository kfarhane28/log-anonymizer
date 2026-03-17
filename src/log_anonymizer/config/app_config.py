from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoggingSettings:
    level: str = "INFO"
    fmt: str = "json"


@dataclass(frozen=True)
class AppConfig:
    logging: LoggingSettings = LoggingSettings()


def resolve_config_path(cli_path: Path | None) -> Path | None:
    """
    Resolve config path with the following precedence:
    1) CLI `--config`
    2) `LOG_ANONYMIZER_CONFIG` environment variable
    3) `./log-anonymizer.ini` in the current working directory
    """
    if cli_path is not None:
        return cli_path.expanduser().resolve()

    env = os.getenv("LOG_ANONYMIZER_CONFIG")
    if env:
        return Path(env).expanduser().resolve()

    default = Path.cwd() / "log-anonymizer.ini"
    if default.exists():
        return default.resolve()
    return None


def load_config(path: Path | None) -> AppConfig:
    """
    Load configuration from an INI file. Missing file returns defaults.

    Supported sections/keys:
    - [logging]
      - level: INFO/DEBUG/...
      - format: json|text
    """
    if path is None:
        return AppConfig()
    if not path.exists():
        return AppConfig()

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    level = parser.get("logging", "level", fallback="INFO").strip() or "INFO"
    fmt = parser.get("logging", "format", fallback="json").strip() or "json"

    return AppConfig(logging=LoggingSettings(level=level, fmt=fmt))

