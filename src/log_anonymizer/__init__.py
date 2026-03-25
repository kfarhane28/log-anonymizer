__all__ = ["__version__"]

try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:  # pragma: no cover
    __version__ = "0.0.0"
else:
    try:
        __version__ = version("log-anonymizer")
    except PackageNotFoundError:  # pragma: no cover
        __version__ = "0.0.0"
