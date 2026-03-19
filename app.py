from __future__ import annotations

import json
import hashlib
import logging
import os
import base64
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Literal

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns
from log_anonymizer.input_handler import handle_input
from log_anonymizer.exclude_filter import load_patterns as _load_exclude_patterns
from log_anonymizer.application.preview_anonymization import (
    PreviewAnonymizationRequest,
    preview_anonymization,
)
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.profiling.runner import run_sensitive_data_profiling
from log_anonymizer.processor import ProcessorConfig, process_with_result
from log_anonymizer.rules_loader import load_rules


InputMode = Literal["Upload file", "Upload archive", "Use path"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreparedRun:
    input_path: Path | None
    rules_path: Path
    exclude_path: Path | None
    output_dir: Path
    verbose: bool
    dry_run: bool
    profile_sensitive_data: bool
    profiling_detectors: tuple[str, ...]


class _QueueHandler(logging.Handler):
    def __init__(self, q: Queue[str], level: int) -> None:
        super().__init__(level=level)
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._q.put_nowait(msg)
        except Exception:
            # Never fail the app because of logging.
            pass


def _render_header() -> None:
    logo_path = Path(__file__).resolve().parent / "assets" / "logo.svg"
    svg = logo_path.read_text(encoding="utf-8")
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    html = f"""
    <div style="display:flex; align-items:center; gap:12px; margin: 4px 0 8px 0;">
      <img src="data:image/svg+xml;base64,{b64}" width="36" height="36" />
      <div style="font-size: 34px; font-weight: 700; line-height: 1.0;">Log Anonymizer</div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)
    st.markdown(
        """
        <style>
          /* Avoid button label wrapping (e.g., "Clear log" splitting on 2 lines). */
          div.stButton > button { white-space: nowrap; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="Log Anonymizer", layout="wide")
    _init_state()
    # Pump queues early so status updates render in the left column.
    _pump_logs_once()

    _render_header()

    run = _render_sidebar()
    center, right = st.columns([5.5, 1.0], gap="large")

    with center:
        top = st.columns([1.1, 1.6, 8])
        run_clicked = top[0].button("Run", type="primary")
        clear_clicked = top[1].button(
            "Clear log", disabled=st.session_state.get("run_in_progress", False)
        )
        if run_clicked:
            _start_run(run)
        if clear_clicked:
            st.session_state["log_lines"] = []
            st.session_state["run_error"] = ""
            st.session_state["run_status"] = ""
            st.session_state["result_zip_bytes"] = None
            st.session_state["result_zip_name"] = None
            st.rerun()

        if st.session_state.get("run_status"):
            st.info(st.session_state["run_status"])
        if st.session_state.get("run_error"):
            st.error(st.session_state["run_error"])

        logs_tab, rules_tab, exclude_tab, preview_tab = st.tabs(
            ["Logs", "Rules", "Exclude", "Anonymization Preview"]
        )

        with logs_tab:
            log_container = st.container(border=True, height=760)
            with log_container:
                st.code("\n".join(st.session_state["log_lines"][-1200:]), language="text")

            # Show profiling outputs prominently below logs (useful for dry-run profiling).
            if (
                st.session_state.get("profiling_report_bytes") is not None
                or st.session_state.get("suggested_rules_bytes") is not None
            ):
                st.markdown("---")
                st.subheader("Profiling outputs")

                if st.session_state.get("profiling_report_bytes") is not None:
                    c1, c2 = st.columns([10, 1])
                    with c1:
                        st.markdown("**Profiling report**")
                    with c2:
                        st.download_button(
                            "⬇",
                            data=st.session_state["profiling_report_bytes"],
                            file_name=st.session_state.get(
                                "profiling_report_name", "profiling_report.json"
                            ),
                            mime="application/json",
                            help="Download profiling report",
                            use_container_width=True,
                        )
                    try:
                        report_text = st.session_state["profiling_report_bytes"].decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        report_text = ""
                    with st.expander("View report", expanded=True):
                        st.code(report_text or "(unreadable report)", language="json")

                if st.session_state.get("suggested_rules_bytes") is not None:
                    c1, c2 = st.columns([10, 1])
                    with c1:
                        st.markdown("**Suggested rules**")
                    with c2:
                        st.download_button(
                            "⬇",
                            data=st.session_state["suggested_rules_bytes"],
                            file_name=st.session_state.get(
                                "suggested_rules_name", "suggested_rules.json"
                            ),
                            mime="application/json",
                            help="Download suggested rules",
                            use_container_width=True,
                        )
                    try:
                        suggested_text = st.session_state["suggested_rules_bytes"].decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        suggested_text = ""
                    with st.expander("View suggested rules", expanded=True):
                        st.code(
                            suggested_text or "(unreadable suggested rules)", language="json"
                        )

            if st.session_state.get("run_in_progress"):
                st.caption("Updating logs…")
                time.sleep(0.25)
                st.rerun()

        with rules_tab:
            _render_rules_editor()

        with exclude_tab:
            _render_exclude_editor()

        with preview_tab:
            _render_preview_tab(run)

    with right:
        st.subheader("Output")
        st.write(f"Output directory: `{run.output_dir}`")
        if run.input_path is not None:
            st.write(f"Output archive: `{_default_output_archive_path(run.output_dir, run.input_path)}`")
        else:
            st.write("Output archive: (missing input)")

        has_any_output = any(
            st.session_state.get(k) is not None
            for k in ("result_zip_bytes", "profiling_report_bytes", "suggested_rules_bytes")
        )
        if has_any_output:
            st.success("Done.")

        if st.session_state.get("result_zip_bytes") is not None:
            st.download_button(
                "Download archive",
                data=st.session_state["result_zip_bytes"],
                file_name=st.session_state.get("result_zip_name", "anonymized.tar.gz"),
                mime="application/gzip",
                width="stretch",
            )

        st.subheader("Run")
        st.write(f"Verbose: `{run.verbose}`")
        st.write(f"Dry run: `{run.dry_run}`")
        st.write(f"Sensitive-data profiling: `{bool(run.profile_sensitive_data)}`")
        st.write(f"Exclude provided: `{bool(run.exclude_path)}`")
        st.write(
            f"Rules file: `{run.rules_path.name if run.rules_path else 'default (built-in only)'}`"
        )


def _init_state() -> None:
    st.session_state.setdefault("log_queue", Queue())
    st.session_state.setdefault("outcome_queue", Queue())
    st.session_state.setdefault("log_lines", [])
    st.session_state.setdefault("run_in_progress", False)
    st.session_state.setdefault("run_status", "")
    st.session_state.setdefault("run_error", "")
    st.session_state.setdefault("result_zip_bytes", None)
    st.session_state.setdefault("result_zip_name", None)
    st.session_state.setdefault("profiling_report_bytes", None)
    st.session_state.setdefault("profiling_report_name", None)
    st.session_state.setdefault("suggested_rules_bytes", None)
    st.session_state.setdefault("suggested_rules_name", None)
    st.session_state.setdefault("tmp_dir", None)
    st.session_state.setdefault("log_handler", None)
    st.session_state.setdefault("log_prev_handlers", None)
    st.session_state.setdefault("ui_warnings", [])
    st.session_state.setdefault("ui_errors", [])
    st.session_state.setdefault("rules_editor_df", None)
    st.session_state.setdefault("exclude_editor_df", None)
    st.session_state.setdefault("rules_upload_sig", None)
    st.session_state.setdefault("exclude_upload_sig", None)
    st.session_state.setdefault("preview_input", "")
    st.session_state.setdefault("preview_output_value", "")
    st.session_state.setdefault("preview_status", "")
    st.session_state.setdefault("preview_error", "")
    st.session_state.setdefault("preview_profile_report", "")
    st.session_state.setdefault("preview_suggested_rules", "")
    # Backward-compat: older versions used a widget key named "preview_output".
    # Ensure it doesn't linger and cause confusing state errors across hot-reloads.
    st.session_state.pop("preview_output", None)


def _render_sidebar() -> PreparedRun:
    st.sidebar.header("Configuration")
    st.session_state["ui_warnings"] = []
    st.session_state["ui_errors"] = []

    input_mode: InputMode = st.sidebar.radio(
        "Input source",
        options=["Upload file", "Upload archive", "Use path"],
        index=0,
    )

    uploaded_input = None
    input_path_text = ""
    if input_mode == "Upload file":
        uploaded_input = st.sidebar.file_uploader("Upload a log file", type=None)
    elif input_mode == "Upload archive":
        uploaded_input = st.sidebar.file_uploader(
            "Upload an archive (.zip / .tar.gz)",
            type=["zip", "tgz", "gz"],
        )
    else:
        input_path_text = st.sidebar.text_input("Input path", value="tmp_test/in")

    uploaded_rules = st.sidebar.file_uploader("Rules JSON", type=["json"], key="rules_upload")
    uploaded_exclude = st.sidebar.file_uploader(
        "Exclude file (.exclude)", type=None, key="exclude_upload"
    )

    output_dir_text = st.sidebar.text_input("Output directory", value="tmp_test/ui_out")
    verbose = st.sidebar.checkbox("Verbose mode (DEBUG)", value=False)
    dry_run = st.sidebar.checkbox("Dry run", value=False)
    profile_sensitive_data = st.sidebar.checkbox(
        "Enable sensitive-data profiling (optional)",
        value=False,
        help="Heuristic scan for potential sensitive data + suggested rules. Does not change anonymization unless you apply the suggested rules.",
    )
    detectors = ("email", "ipv4", "token", "card")
    profiling_detectors = detectors
    if profile_sensitive_data:
        profiling_detectors = tuple(
            st.sidebar.multiselect(
                "Profiling detectors",
                options=list(detectors),
                default=list(detectors),
            )
        ) or detectors

    prepared = _prepare_files(
        input_mode=input_mode,
        uploaded_input=uploaded_input,
        input_path_text=input_path_text,
        uploaded_rules=uploaded_rules,
        uploaded_exclude=uploaded_exclude,
        output_dir_text=output_dir_text,
        verbose=verbose,
        dry_run=dry_run,
        profile_sensitive_data=profile_sensitive_data,
        profiling_detectors=profiling_detectors,
    )
    if st.session_state.get("ui_errors"):
        st.sidebar.markdown("---")
        for e in st.session_state["ui_errors"]:
            st.sidebar.error(e)
    for w in st.session_state.get("ui_warnings", []):
        st.sidebar.warning(w)
    return prepared


def _prepare_files(
    *,
    input_mode: InputMode,
    uploaded_input,
    input_path_text: str,
    uploaded_rules,
    uploaded_exclude,
    output_dir_text: str,
    verbose: bool,
    dry_run: bool,
    profile_sensitive_data: bool,
    profiling_detectors: tuple[str, ...],
) -> PreparedRun:
    tmp_dir = _ensure_tmp_dir()

    if input_mode in ("Upload file", "Upload archive"):
        if uploaded_input is None:
            input_path = None
        else:
            if input_mode == "Upload archive":
                name_hint = str(getattr(uploaded_input, "name", "") or "input.tar.gz")
            else:
                name_hint = str(getattr(uploaded_input, "name", "") or "input")
            input_path = _save_upload(tmp_dir, uploaded_input, name_hint=name_hint)
    else:
        raw = (input_path_text or "").strip()
        input_path = Path(raw).expanduser() if raw else None

    if uploaded_rules is None:
        _ensure_rules_editor_initialized()
        rules_path = _write_rules_from_editor(tmp_dir)
    else:
        raw = bytes(uploaded_rules.getbuffer())
        err = _validate_rules_json_bytes(raw)
        if err:
            st.session_state["ui_errors"].append(f"Rules JSON invalid: {err}")
            _ensure_rules_editor_initialized()
            rules_path = _write_rules_from_editor(tmp_dir)
        else:
            _maybe_load_rules_upload_into_editor(raw, name=str(uploaded_rules.name))
            rules_path = _write_rules_from_editor(tmp_dir)

    exclude_path = None
    if uploaded_exclude is not None:
        raw = bytes(uploaded_exclude.getbuffer())
        err = _validate_exclude_bytes(raw, filename=str(uploaded_exclude.name))
        if err:
            st.session_state["ui_errors"].append(f"Exclude file invalid: {err}")
            exclude_path = None
        else:
            _maybe_load_exclude_upload_into_editor(raw, name=str(uploaded_exclude.name))
            exclude_path = _write_exclude_from_editor(tmp_dir)
    else:
        if _exclude_editor_has_patterns():
            exclude_path = _write_exclude_from_editor(tmp_dir)

    output_dir = Path(output_dir_text).expanduser()
    return PreparedRun(
        input_path=input_path,
        rules_path=rules_path,
        exclude_path=exclude_path,
        output_dir=output_dir,
        verbose=verbose,
        dry_run=dry_run,
        profile_sensitive_data=profile_sensitive_data,
        profiling_detectors=profiling_detectors,
    )


def _ensure_tmp_dir() -> Path:
    existing = st.session_state.get("tmp_dir")
    if existing and Path(existing).exists():
        return Path(existing)
    tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-ui-")).resolve()
    st.session_state["tmp_dir"] = str(tmp_dir)
    return tmp_dir


def _save_upload(tmp_dir: Path, uploaded, *, name_hint: str) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    target = (tmp_dir / name_hint).resolve()
    with target.open("wb") as f:
        f.write(uploaded.getbuffer())
    return target


def _default_output_archive_path(output_dir: Path, input_path: Path) -> Path:
    out_dir = output_dir.expanduser().resolve()
    name = input_path.name
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        base = name[: -len(".tar.gz")]
    elif lower.endswith(".tgz"):
        base = name[: -len(".tgz")]
    elif lower.endswith(".zip"):
        base = input_path.stem
    else:
        base = input_path.stem or name
    return out_dir / f"{base}.tar.gz"


def _start_run(run: PreparedRun) -> None:
    st.session_state["run_error"] = ""
    st.session_state["result_zip_bytes"] = None
    st.session_state["result_zip_name"] = None
    st.session_state["profiling_report_bytes"] = None
    st.session_state["profiling_report_name"] = None
    st.session_state["suggested_rules_bytes"] = None
    st.session_state["suggested_rules_name"] = None
    st.session_state["log_lines"] = []

    err = _validate_run(run)
    if err:
        st.session_state["run_error"] = err
        return

    st.session_state["run_in_progress"] = True
    st.session_state["run_status"] = "Running…"

    log_q: Queue[str] = Queue()
    outcome_q: Queue[dict[str, Any]] = Queue()
    st.session_state["log_queue"] = log_q
    st.session_state["outcome_queue"] = outcome_q

    while True:
        try:
            log_q.get_nowait()
        except Empty:
            break
    while True:
        try:
            outcome_q.get_nowait()
        except Empty:
            break

    handler, prev = _attach_streamlit_logger(log_q, verbose=run.verbose)
    st.session_state["log_handler"] = handler
    st.session_state["log_prev_handlers"] = prev

    thread = threading.Thread(
        target=_run_pipeline_thread, args=(run, log_q, outcome_q), daemon=True
    )
    thread.start()


def _validate_run(run: PreparedRun) -> str | None:
    ui_errors = st.session_state.get("ui_errors") or []
    if ui_errors:
        return str(ui_errors[0])
    if run.input_path is None:
        return "Please provide an input (upload or path)."
    if str(run.input_path).strip() in ("", "."):
        return "Please provide an input (upload or path)."
    if not run.input_path.exists():
        return f"Input path does not exist: {run.input_path}"
    if not run.output_dir or str(run.output_dir) == "":
        return "Please provide an output directory."
    if not run.input_path.exists():
        return f"Input path does not exist: {run.input_path}"
    if run.output_dir.exists() and not run.output_dir.is_dir():
        return f"Output directory is not a directory: {run.output_dir}"
    if not run.rules_path.exists():
        return f"Rules file could not be created: {run.rules_path}"
    if run.exclude_path is not None and not run.exclude_path.exists():
        return f"Exclude file does not exist: {run.exclude_path}"
    return None


def _run_pipeline_thread(
    run: PreparedRun, log_q: Queue[str], outcome_q: Queue[dict[str, Any]]
) -> None:
    try:
        if run.input_path is None:
            outcome_q.put({"type": "error", "status": "Failed.", "error": "Missing input."})
            return
        if run.dry_run:
            if run.profile_sensitive_data and run.input_path is not None:
                res = run_sensitive_data_profiling(
                    input_path=run.input_path,
                    output_dir=run.output_dir,
                    exclude_path=run.exclude_path,
                    detectors=run.profiling_detectors,
                )
                summary = (
                    "DRY RUN (profiling only)\n"
                    f"- Profiling report: {res.profiling_report_path}\n"
                    f"- Suggested rules: {res.suggested_rules_path}\n"
                    f"- Files: total={res.total_files}, excluded={res.excluded_files}, profiled={res.profiled_files}\n"
                )
                log_q.put(summary)
                outcome_q.put(
                    {
                        "type": "done",
                        "status": "Dry run (profiling only) completed.",
                        "archive_path": None,
                        "profiling_report_path": str(res.profiling_report_path),
                        "suggested_rules_path": str(res.suggested_rules_path),
                    }
                )
                return

            summary = _dry_run(run)
            log_q.put(summary)
            outcome_q.put({"type": "done", "status": "Dry run completed.", "archive_path": None})
            return

        cfg = ProcessorConfig(
            max_workers=int(os.getenv("LOG_ANONYMIZER_WORKERS", "8")),
            exclude_case_insensitive=False,
            include_builtin_rules=True,
            profile_sensitive_data=bool(run.profile_sensitive_data),
            profiling_detectors=run.profiling_detectors,
        )
        out_zip = process_with_result(
            input_path=run.input_path,
            rules_path=run.rules_path,
            output_dir=run.output_dir,
            exclude_path=run.exclude_path,
            config=cfg,
        )
        summary_lines = [
            "Completed.",
            f"- Output archive: {out_zip.output_zip}",
        ]
        if out_zip.profiling_report_path:
            summary_lines.append(f"- Profiling report: {out_zip.profiling_report_path}")
        if out_zip.suggested_rules_path:
            summary_lines.append(f"- Suggested rules: {out_zip.suggested_rules_path}")
        summary_lines.extend(
            [
                f"- Total files: {out_zip.total_files}",
                f"- Excluded: {out_zip.excluded_files}",
                f"- Processed: {out_zip.processed_files}",
                f"- Failed: {out_zip.failed_files}",
            ]
        )
        summary = "\n".join(summary_lines)
        outcome_q.put(
            {
                "type": "done",
                "status": summary,
                "archive_path": str(out_zip.output_zip),
                "profiling_report_path": str(out_zip.profiling_report_path)
                if out_zip.profiling_report_path is not None
                else None,
                "suggested_rules_path": str(out_zip.suggested_rules_path)
                if out_zip.suggested_rules_path is not None
                else None,
                "summary": {
                    "total": out_zip.total_files,
                    "excluded": out_zip.excluded_files,
                    "processed": out_zip.processed_files,
                    "failed": out_zip.failed_files,
                },
            }
        )
    except Exception as exc:  # noqa: BLE001 (UI boundary)
        log_q.put(f"ERROR: {type(exc).__name__}: {exc}")
        outcome_q.put(
            {"type": "error", "status": "Failed.", "error": f"{type(exc).__name__}: {exc}"}
        )


def _dry_run(run: PreparedRun) -> str:
    if run.input_path is None:
        return "DRY RUN\n- Input: (missing)\n"
    user_rules = load_rules(run.rules_path)

    with handle_input(run.input_path) as prepared:
        base_dir = prepared.working_dir
        files = prepared.files
        patterns = list(default_patterns())
        if run.exclude_path is not None:
            patterns.extend(_load_exclude_patterns(run.exclude_path))
        exclude_filter = (
            ExcludeFilter.from_patterns(patterns, base_dir=base_dir, case_insensitive=False)
            if patterns
            else None
        )
        filtered = [f for f in files if not (exclude_filter and exclude_filter.should_exclude(f))]

    name = run.input_path.name
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        base = name[: -len(".tar.gz")]
    elif lower.endswith(".tgz"):
        base = name[: -len(".tgz")]
    elif lower.endswith(".zip"):
        base = run.input_path.stem
    else:
        base = run.input_path.stem or name
    zip_path = run.output_dir.expanduser().resolve() / f"{base}.tar.gz"
    exclude_info = f"builtin={len(default_patterns())}"
    if run.exclude_path is not None:
        try:
            exclude_info = (
                f"{run.exclude_path} (builtin={len(default_patterns())}, "
                f"user={len(_load_exclude_patterns(run.exclude_path))})"
            )
        except Exception:
            exclude_info = str(run.exclude_path)
    lines = [
        "DRY RUN",
        f"- Input: {run.input_path}",
        f"- Output dir: {run.output_dir}",
        f"- Output archive: {zip_path}",
        f"- User rules loaded: {len(user_rules)} (built-in rules are enabled by default)",
        f"- Exclude: {exclude_info}",
        f"- Files: total={len(files)}, excluded={len(files) - len(filtered)}, to_process={len(filtered)}",
    ]
    preview = [f"  - {p}" for p in filtered[:20]]
    if len(filtered) > 20:
        preview.append(f"  ... ({len(filtered) - 20} more)")
    return "\n".join(lines + preview)


def _attach_streamlit_logger(q: Queue[str], *, verbose: bool) -> tuple[logging.Handler, list[logging.Handler]]:
    root = logging.getLogger()
    prev = list(root.handlers)

    for h in prev:
        root.removeHandler(h)

    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = _QueueHandler(q, level=logging.DEBUG if verbose else logging.INFO)
    from log_anonymizer.config.logging_config import TextWithExtrasFormatter

    handler.setFormatter(TextWithExtrasFormatter())
    root.addHandler(handler)

    return handler, prev


def _detach_streamlit_logger(handler: logging.Handler, prev: list[logging.Handler]) -> None:
    root = logging.getLogger()
    try:
        root.removeHandler(handler)
    except Exception:
        pass
    for h in prev:
        root.addHandler(h)


def _pump_logs_once() -> None:
    q: Queue[str] = st.session_state["log_queue"]
    lines: list[str] = st.session_state["log_lines"]
    while True:
        try:
            item = q.get_nowait()
        except Empty:
            break
        lines.append(item)
    st.session_state["log_lines"] = lines

    _pump_outcome_once()


def _pump_outcome_once() -> None:
    outcome_q: Queue[dict[str, Any]] = st.session_state["outcome_queue"]
    while True:
        try:
            outcome = outcome_q.get_nowait()
        except Empty:
            break

        if outcome.get("type") == "done":
            st.session_state["run_status"] = str(outcome.get("status") or "Completed.")
            archive_path = outcome.get("archive_path")
            if isinstance(archive_path, str) and archive_path:
                p = Path(archive_path)
                st.session_state["result_zip_bytes"] = p.read_bytes()
                st.session_state["result_zip_name"] = p.name
            profiling_report_path = outcome.get("profiling_report_path")
            if isinstance(profiling_report_path, str) and profiling_report_path:
                p = Path(profiling_report_path)
                if p.exists():
                    st.session_state["profiling_report_bytes"] = p.read_bytes()
                    st.session_state["profiling_report_name"] = p.name
            suggested_rules_path = outcome.get("suggested_rules_path")
            if isinstance(suggested_rules_path, str) and suggested_rules_path:
                p = Path(suggested_rules_path)
                if p.exists():
                    st.session_state["suggested_rules_bytes"] = p.read_bytes()
                    st.session_state["suggested_rules_name"] = p.name
            st.session_state["run_in_progress"] = False
            _restore_logger_if_needed()
        elif outcome.get("type") == "error":
            st.session_state["run_status"] = str(outcome.get("status") or "Failed.")
            st.session_state["run_error"] = str(outcome.get("error") or "Unknown error")
            st.session_state["run_in_progress"] = False
            _restore_logger_if_needed()


def _restore_logger_if_needed() -> None:
    handler = st.session_state.get("log_handler")
    prev = st.session_state.get("log_prev_handlers")
    if handler is not None and prev is not None:
        _detach_streamlit_logger(handler, prev)
    st.session_state["log_handler"] = None
    st.session_state["log_prev_handlers"] = None


def _render_preview_tab(run: PreparedRun) -> None:
    st.caption("Paste a few log lines to preview anonymization (in-memory; no files written).")

    status_slot = st.container()

    text_in = st.session_state.get("preview_input") or ""
    text_out = st.session_state.get("preview_output_value") or ""
    lines_in = len(text_in.splitlines()) if text_in else 0
    lines_out = len(text_out.splitlines()) if text_out else 0

    b1, b2, b3, _ = st.columns([1.2, 1.0, 1.0, 5.0])
    anonymize_clicked = b1.button(
        "Anonymize",
        width="stretch",
        disabled=bool(st.session_state.get("run_in_progress")),
        key="preview_anonymize_btn",
    )
    clear_clicked = b2.button(
        "Clear",
        width="stretch",
        disabled=bool(st.session_state.get("run_in_progress")),
        key="preview_clear_btn",
    )
    profile_clicked = b3.button(
        "Profile",
        width="stretch",
        disabled=bool(st.session_state.get("run_in_progress")),
        key="preview_profile_btn",
    )

    if anonymize_clicked:
        st.session_state["preview_error"] = ""
        st.session_state["preview_status"] = ""
        try:
            logger.info("ui_preview_clicked", extra={"lines_in": lines_in})
            res = preview_anonymization(
                PreviewAnonymizationRequest(
                    text=text_in,
                    rules_path=run.rules_path,
                    include_builtin_rules=True,
                )
            )
            st.session_state["preview_output_value"] = res.anonymized_text
            st.session_state["preview_status"] = (
                f"Success. {res.lines_in} lines → {res.lines_out} lines "
                f"({res.stats.total_replacements} replacements)."
            )
            text_out = st.session_state["preview_output_value"]
            lines_out = len(text_out.splitlines()) if text_out else 0
        except Exception as exc:  # noqa: BLE001 (UI boundary)
            logger.exception("ui_preview_failed", extra={"error": str(exc)})
            st.session_state["preview_error"] = f"{type(exc).__name__}: {exc}"

    if profile_clicked:
        st.session_state["preview_error"] = ""
        try:
            profiler = SensitiveDataProfiler(config=ProfilingConfig(detectors=("email", "ipv4", "token", "card")))
            report = profiler.profile_text(text_in, source_name="<preview>")
            st.session_state["preview_profile_report"] = report.to_json()
            st.session_state["preview_suggested_rules"] = (
                json.dumps(report.suggested_rules, ensure_ascii=False, indent=2) + "\n"
            )
        except Exception as exc:  # noqa: BLE001 (UI boundary)
            logger.exception("ui_preview_profile_failed", extra={"error": str(exc)})
            st.session_state["preview_error"] = f"{type(exc).__name__}: {exc}"

    if clear_clicked:
        st.session_state["preview_input"] = ""
        st.session_state["preview_output_value"] = ""
        st.session_state["preview_status"] = ""
        st.session_state["preview_error"] = ""
        st.session_state["preview_profile_report"] = ""
        st.session_state["preview_suggested_rules"] = ""
        st.rerun()

    with status_slot:
        if st.session_state.get("preview_status"):
            st.success(st.session_state["preview_status"])
        if st.session_state.get("preview_error"):
            st.error(st.session_state["preview_error"])

    st.text_area(
        "Input (raw logs)",
        key="preview_input",
        height=260,
        placeholder="Paste a few lines here…",
    )
    st.text_area(
        "Output (anonymized)",
        value=text_out,
        height=260,
        disabled=True,
    )
    m1, m2, m3 = st.columns(3)
    m1.metric("Input lines", lines_in)
    m2.metric("Output lines", lines_out)
    m3.metric("User rules", _preview_rules_count(run))

    if st.session_state.get("preview_profile_report"):
        with st.expander("Sensitive-data profiling report (preview)", expanded=False):
            st.code(st.session_state["preview_profile_report"], language="json")
    if st.session_state.get("preview_suggested_rules"):
        with st.expander("Suggested rules (preview)", expanded=False):
            st.code(st.session_state["preview_suggested_rules"], language="json")

    # Optional "Copy" button (best-effort; may depend on browser permissions).
    if text_out:
        copy_payload = json.dumps(text_out)
        components.html(
            f"""
            <div style="display:flex; gap:8px; align-items:center; margin-top: 8px;">
              <button
                style="padding:6px 10px; border-radius:6px; border:1px solid #bbb; cursor:pointer;"
                onclick="navigator.clipboard.writeText({copy_payload});"
              >
                Copy result
              </button>
              <span style="opacity:0.7; font-size: 12px;">Copies to clipboard (if allowed by your browser).</span>
            </div>
            """,
            height=44,
        )


def _preview_rules_count(run: PreparedRun) -> int:
    # Best-effort: file always exists in the UI, but keep it resilient.
    try:
        user_rules = load_rules(run.rules_path) if run.rules_path and run.rules_path.exists() else []
    except Exception:
        user_rules = []
    return len(user_rules)


def _write_default_rules_file(tmp_dir: Path) -> Path:
    """
    Create a minimal rules.json file so users can run with built-in rules only.
    """
    target = (tmp_dir / "rules.json").resolve()
    if target.exists():
        return target
    target.write_text('{"version": 1, "rules": []}\n', encoding="utf-8")
    return target


def _ensure_rules_editor_initialized() -> None:
    if st.session_state.get("rules_editor_df") is not None:
        return
    st.session_state["rules_editor_df"] = pd.DataFrame(
        columns=["description", "trigger", "search", "replace", "caseSensitive"]
    )


def _ensure_exclude_editor_initialized() -> None:
    if st.session_state.get("exclude_editor_df") is not None:
        return
    st.session_state["exclude_editor_df"] = pd.DataFrame(columns=["pattern"])


def _sig(name: str, raw: bytes) -> str:
    h = hashlib.sha256()
    h.update(name.encode("utf-8", errors="ignore"))
    h.update(b"\x00")
    h.update(raw[:65536])
    return h.hexdigest()


def _rules_df_to_json_bytes(df: "pd.DataFrame") -> bytes:
    rules: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        description = str(row.get("description") or "").strip()
        trigger = str(row.get("trigger") or "").strip()
        search = str(row.get("search") or "").strip()
        replace = str(row.get("replace") or "")
        case_sensitive = row.get("caseSensitive")

        if not trigger and not search and replace == "" and not description:
            continue

        rule: dict[str, Any] = {
            "description": description,
            "trigger": trigger,
            "search": search,
            "replace": replace,
        }
        if case_sensitive is not None and str(case_sensitive).strip() != "":
            rule["caseSensitive"] = case_sensitive
        rules.append(rule)

    payload = {"version": 1, "rules": rules}
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_rules_from_editor(tmp_dir: Path) -> Path:
    _ensure_rules_editor_initialized()
    df = st.session_state["rules_editor_df"]
    raw = _rules_df_to_json_bytes(df)
    err = _validate_rules_json_bytes(raw)
    if err:
        st.session_state["ui_errors"].append(f"Rules editor invalid: {err}")
        raw = b'{"version": 1, "rules": []}\n'
    target = (tmp_dir / "rules.json").resolve()
    target.write_bytes(raw)
    return target


def _exclude_df_to_text(df: "pd.DataFrame") -> str:
    patterns: list[str] = []
    for _, row in df.iterrows():
        p = str(row.get("pattern") or "").strip()
        if not p or p.startswith("#"):
            continue
        patterns.append(p)
    return "\n".join(patterns) + ("\n" if patterns else "")


def _exclude_editor_has_patterns() -> bool:
    _ensure_exclude_editor_initialized()
    df = st.session_state["exclude_editor_df"]
    if df is None or df.empty:
        return False
    for _, row in df.iterrows():
        p = str(row.get("pattern") or "").strip()
        if p and not p.startswith("#"):
            return True
    return False


def _write_exclude_from_editor(tmp_dir: Path) -> Path | None:
    _ensure_exclude_editor_initialized()
    df = st.session_state["exclude_editor_df"]
    text = _exclude_df_to_text(df)
    raw = text.encode("utf-8")
    err = _validate_exclude_bytes(raw, filename=".exclude")
    if err:
        st.session_state["ui_errors"].append(f"Exclude editor invalid: {err}")
        return None
    target = (tmp_dir / ".exclude").resolve()
    target.write_bytes(raw)
    return target


def _maybe_load_rules_upload_into_editor(raw: bytes, *, name: str) -> None:
    sig = _sig(name, raw)
    if st.session_state.get("rules_upload_sig") == sig:
        return
    st.session_state["rules_upload_sig"] = sig

    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return
    rules = obj.get("rules") if isinstance(obj, dict) else None
    if not isinstance(rules, list):
        return

    rows: list[dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        rows.append(
            {
                "description": r.get("description", ""),
                "trigger": r.get("trigger", ""),
                "search": r.get("search", ""),
                "replace": r.get("replace", ""),
                "caseSensitive": r.get("caseSensitive", ""),
            }
        )
    st.session_state["rules_editor_df"] = pd.DataFrame(
        rows, columns=["description", "trigger", "search", "replace", "caseSensitive"]
    )


def _maybe_load_exclude_upload_into_editor(raw: bytes, *, name: str) -> None:
    sig = _sig(name, raw)
    if st.session_state.get("exclude_upload_sig") == sig:
        return
    st.session_state["exclude_upload_sig"] = sig

    try:
        text = raw.decode("utf-8")
    except Exception:
        return
    patterns: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        patterns.append({"pattern": s})
    st.session_state["exclude_editor_df"] = pd.DataFrame(patterns, columns=["pattern"])


def _render_rules_editor() -> None:
    _ensure_rules_editor_initialized()
    st.caption("Edit rules that will be applied in addition to built-in rules.")

    b1, b2, _ = st.columns([1.2, 1.2, 6])
    if b1.button("Add rule", key="add_rule"):
        df = st.session_state["rules_editor_df"]
        df = pd.concat(
            [
                df,
                pd.DataFrame(
                    [
                        {
                            "description": "",
                            "trigger": "",
                            "search": "",
                            "replace": "",
                            "caseSensitive": "",
                        }
                    ]
                ),
            ],
            ignore_index=True,
        )
        st.session_state["rules_editor_df"] = df
        st.rerun()
    if b2.button("Reset rules", key="reset_rules"):
        st.session_state["rules_editor_df"] = pd.DataFrame(
            columns=["description", "trigger", "search", "replace", "caseSensitive"]
        )
        st.rerun()

    edited = st.data_editor(
        st.session_state["rules_editor_df"],
        key="rules_editor",
        num_rows="dynamic",
        width="stretch",
        column_config={
            "description": st.column_config.TextColumn("description"),
            "trigger": st.column_config.TextColumn("trigger"),
            "search": st.column_config.TextColumn("search (regex)"),
            "replace": st.column_config.TextColumn("replace"),
            "caseSensitive": st.column_config.TextColumn("caseSensitive"),
        },
    )
    st.session_state["rules_editor_df"] = edited

    raw = _rules_df_to_json_bytes(edited)
    err = _validate_rules_json_bytes(raw)
    if err:
        st.error(f"Rules validation error: {err}")
    else:
        st.success("Rules look valid.")

    st.subheader("Preview")
    st.code(raw.decode("utf-8"), language="json")


def _render_exclude_editor() -> None:
    _ensure_exclude_editor_initialized()
    st.caption("Edit exclude patterns (glob style).")

    b1, b2, _ = st.columns([1.3, 1.3, 6])
    if b1.button("Add pattern", key="add_pattern"):
        df = st.session_state["exclude_editor_df"]
        df = pd.concat([df, pd.DataFrame([{"pattern": ""}])], ignore_index=True)
        st.session_state["exclude_editor_df"] = df
        st.rerun()
    if b2.button("Reset exclude", key="reset_exclude"):
        st.session_state["exclude_editor_df"] = pd.DataFrame(columns=["pattern"])
        st.rerun()

    edited = st.data_editor(
        st.session_state["exclude_editor_df"],
        key="exclude_editor",
        num_rows="dynamic",
        width="stretch",
        column_config={"pattern": st.column_config.TextColumn("pattern")},
    )
    st.session_state["exclude_editor_df"] = edited

    text = _exclude_df_to_text(edited)
    raw = text.encode("utf-8")
    err = _validate_exclude_bytes(raw, filename=".exclude")
    if err:
        st.error(f"Exclude validation error: {err}")
    else:
        st.success("Exclude file looks valid.")

    st.subheader("Preview")
    st.code(text or "# (no exclude patterns)\n", language="text")


def _looks_like_json(raw: bytes) -> bool:
    head = raw.lstrip()[:2]
    if not head or head[:1] not in (b"{", b"["):
        return False
    try:
        json.loads(raw.decode("utf-8"))
        return True
    except Exception:
        return False


def _validate_rules_json_bytes(raw: bytes) -> str | None:
    """
    Validate that uploaded rules.json is parseable and follows the expected schema.
    """
    try:
        obj = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return "not valid UTF-8"
    except json.JSONDecodeError as exc:
        return f"invalid JSON: {exc}"

    if not isinstance(obj, dict):
        return "root must be a JSON object"
    if obj.get("version") != 1:
        return "version must be 1"
    rules = obj.get("rules")
    if not isinstance(rules, list):
        return "rules must be a list"

    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            return f"rules[{i}] must be an object"
        for key in ("search", "replace"):
            if key not in r:
                return f"rules[{i}] missing '{key}'"
            if not isinstance(r[key], str):
                return f"rules[{i}].{key} must be a string"
        if not r["search"].strip():
            return f"rules[{i}].search must be a non-empty string"
        if "trigger" in r and r["trigger"] is not None and not isinstance(r["trigger"], str):
            return f"rules[{i}].trigger must be a string"
        if "description" in r and r["description"] is not None and not isinstance(r["description"], str):
            return f"rules[{i}].description must be a string"
        if "caseSensitive" in r and r["caseSensitive"] is not None and not isinstance(
            r["caseSensitive"], (str, bool, int, float)
        ):
            return f"rules[{i}].caseSensitive must be boolean or string"
    return None


def _validate_exclude_bytes(raw: bytes, *, filename: str) -> str | None:
    """
    Validate that uploaded exclude file is plausible text.

    Heuristics:
    - Must not look like JSON
    - Must be UTF-8 decodable
    - Must not contain NUL bytes
    - Each non-comment line is treated as a glob pattern
    """
    if b"\x00" in raw:
        return "file looks binary (contains NUL bytes)"
    if _looks_like_json(raw) or filename.lower().endswith(".json"):
        return "file looks like JSON; did you upload rules.json by mistake?"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "file is not valid UTF-8 text"

    lines = text.splitlines()
    patterns = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        patterns.append(s)
        if len(s) > 512:
            return "a pattern line is too long (>512 chars)"
    if not patterns:
        st.session_state["ui_warnings"].append("Exclude file contains no patterns (only comments/blank lines).")
    return None


if __name__ == "__main__":
    main()
