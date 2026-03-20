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
class AnonymizationSettings:
    # Optional global salt used by actions like `secure_hash` and `date_shift` when
    # their per-rule salt is not provided.
    salt: str = ""


@dataclass(frozen=True)
class AppConfig:
    logging: LoggingSettings = LoggingSettings()
    anonymization: AnonymizationSettings = AnonymizationSettings()


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
    - [anonymization]
      - salt: optional stable secret used by some actions
    """
    if path is None:
        return AppConfig()
    if not path.exists():
        return AppConfig()

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    level = parser.get("logging", "level", fallback="INFO").strip() or "INFO"
    fmt = parser.get("logging", "format", fallback="json").strip() or "json"

    salt = parser.get("anonymization", "salt", fallback="").strip()
    return AppConfig(
        logging=LoggingSettings(level=level, fmt=fmt),
        anonymization=AnonymizationSettings(salt=salt),
    )
