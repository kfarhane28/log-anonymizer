from __future__ import annotations

import importlib.util
import sys


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--version" in argv:
        from log_anonymizer import __version__

        print(__version__)
        return

    if "--check" in argv:
        argv = [a for a in argv if a != "--check"]
        try:
            import streamlit  # noqa: F401
            import pandas  # noqa: F401
        except ModuleNotFoundError:  # pragma: no cover
            raise SystemExit(
                "UI dependencies are not installed.\n"
                'Install with: pip install "log-anonymizer[ui]"'
            ) from None

        try:
            import log_anonymizer.ui_app  # noqa: F401
        except Exception as exc:  # pragma: no cover
            raise SystemExit(f"UI import check failed: {exc}") from exc

        try:
            from importlib import resources

            logo = resources.files("log_anonymizer").joinpath("assets/logo.svg")
            if not logo.is_file():
                raise SystemExit("UI asset missing: log_anonymizer/assets/logo.svg")
        except Exception as exc:  # pragma: no cover
            raise SystemExit(f"UI asset check failed: {exc}") from exc

        print("OK")
        return

    try:
        import streamlit.web.cli as stcli
    except ModuleNotFoundError:  # pragma: no cover
        raise SystemExit(
            "UI dependencies are not installed.\n"
            'Install with: pip install "log-anonymizer[ui]"'
        ) from None

    spec = importlib.util.find_spec("log_anonymizer.ui_app")
    if spec is None or spec.origin is None:  # pragma: no cover
        raise SystemExit("Could not locate `log_anonymizer.ui_app` to launch the UI.")

    sys.argv = ["streamlit", "run", spec.origin, *argv]
    # Streamlit's CLI owns the process lifecycle and argument parsing.
    stcli.main()
