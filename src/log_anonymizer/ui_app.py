from __future__ import annotations

import html
import tomllib
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
    PreviewLineDetail,
    preview_anonymization,
)
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.profiling.runner import run_sensitive_data_profiling
from log_anonymizer.batch import process_batch_with_result
from log_anonymizer.processor import CancellationToken, ProcessorConfig, process_with_result
from log_anonymizer.progress import ProgressEvent, ProgressKind, ProgressStage, QueueProgressReporter
from log_anonymizer.rules_loader import load_rules
from log_anonymizer.rules_validation import validate_rules_json_bytes


InputMode = Literal["Upload", "Use path(s)"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreparedRun:
    input_paths: list[Path]
    rules_path: Path
    exclude_path: Path | None
    output_dir: Path
    verbose: bool
    dry_run: bool
    profile_sensitive_data: bool
    profiling_detectors: tuple[str, ...]
    parallel_enabled: bool
    max_workers: int
    anonymize_filenames: bool
    batch_parallel_enabled: bool
    batch_max_workers: int


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
        top = st.columns([1.1, 1.3, 1.6, 8])
        run_clicked = top[0].button("Run", type="primary")
        cancel_clicked = top[1].button(
            "Cancel",
            disabled=not st.session_state.get("run_in_progress", False),
        )
        clear_clicked = top[2].button(
            "Clear log", disabled=st.session_state.get("run_in_progress", False)
        )
        if run_clicked:
            _start_run(run)
        if cancel_clicked:
            _request_cancel()
        if clear_clicked:
            st.session_state["log_lines"] = []
            st.session_state["run_error"] = ""
            st.session_state["run_status"] = ""
            st.session_state["result_zip_bytes"] = None
            st.session_state["result_zip_name"] = None
            st.session_state["batch_items"] = None
            st.session_state["profiling_report_bytes"] = None
            st.session_state["profiling_report_name"] = None
            st.session_state["suggested_rules_bytes"] = None
            st.session_state["suggested_rules_name"] = None
            st.rerun()

        if st.session_state.get("run_status"):
            st.info(st.session_state["run_status"])
        if st.session_state.get("run_error"):
            st.error(st.session_state["run_error"])
        if st.session_state.get("run_in_progress"):
            _render_progress_panel()

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
        if len(run.input_paths) == 1:
            st.write(
                f"Output archive: `{_default_output_archive_path(run.output_dir, run.input_paths[0], anonymize_filenames=run.anonymize_filenames)}`"
            )
        elif len(run.input_paths) > 1:
            st.write("Batch output: one subfolder per input (plus `batch_summary.json`).")
        else:
            st.write("Output archive: (missing input)")

        has_any_output = (
            st.session_state.get("result_zip_bytes") is not None
            or st.session_state.get("batch_items") is not None
            or st.session_state.get("profiling_report_bytes") is not None
            or st.session_state.get("suggested_rules_bytes") is not None
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

        batch_items = st.session_state.get("batch_items")
        if isinstance(batch_items, list) and batch_items:
            st.markdown("### Batch outputs")
            for it in batch_items:
                name = str(it.get("input_name") or it.get("input_path") or "input")
                status = str(it.get("status") or "")
                out_path = it.get("output_archive")
                if status.lower() == "success" and isinstance(out_path, str) and out_path:
                    p = Path(out_path)
                    if p.exists():
                        st.download_button(
                            f"Download: {name}",
                            data=_read_bytes_cached(str(p)),
                            file_name=p.name,
                            mime="application/gzip",
                            width="stretch",
                        )
                else:
                    st.caption(f"{name}: {status}")

        st.subheader("Run")
        st.write(f"Verbose: `{run.verbose}`")
        st.write(f"Dry run: `{run.dry_run}`")
        st.write(f"Sensitive-data profiling: `{bool(run.profile_sensitive_data)}`")
        st.write(f"Exclude provided: `{bool(run.exclude_path)}`")
        st.write(
            f"Rules file: `{run.rules_path.name if run.rules_path else 'default (built-in only)'}`"
        )

    _render_footer()


def _init_state() -> None:
    st.session_state.setdefault("log_queue", Queue())
    st.session_state.setdefault("outcome_queue", Queue())
    st.session_state.setdefault("progress_queue", Queue())
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
    st.session_state.setdefault("batch_items", None)
    st.session_state.setdefault("batch_mode", False)
    st.session_state.setdefault("batch_current_input", "")
    st.session_state.setdefault("batch_done", 0)
    st.session_state.setdefault("batch_total", None)
    st.session_state.setdefault("tmp_dir", None)
    st.session_state.setdefault("log_handler", None)
    st.session_state.setdefault("log_prev_handlers", None)
    st.session_state.setdefault("ui_warnings", [])
    st.session_state.setdefault("ui_errors", [])
    st.session_state.setdefault("rules_editor_df_v1", None)
    st.session_state.setdefault("rules_editor_df_v2", None)
    st.session_state.setdefault("rules_editor_mode", "table_v1")  # table_v1, table_v2, json
    # Radio widget state for editor mode (Table v1 / Table v2 / JSON).
    st.session_state.setdefault("rules_editor_mode_radio", None)
    st.session_state.setdefault("rules_editor_text", None)  # derived JSON content (from tables or last JSON edit)
    st.session_state.setdefault("rules_editor_json_widget", None)  # Streamlit widget state for JSON editor
    st.session_state.setdefault("exclude_editor_df", None)
    st.session_state.setdefault("rules_upload_sig", None)
    st.session_state.setdefault("exclude_upload_sig", None)
    st.session_state.setdefault("preview_input", "")
    st.session_state.setdefault("preview_output_value", "")
    st.session_state.setdefault("preview_status", "")
    st.session_state.setdefault("preview_error", "")
    st.session_state.setdefault("preview_profile_report", "")
    st.session_state.setdefault("preview_suggested_rules", "")
    st.session_state.setdefault("preview_line_details", ())
    st.session_state.setdefault("preview_replacements_by_rule", {})
    st.session_state.setdefault("progress_stage", None)
    st.session_state.setdefault("progress_stage_current", None)
    st.session_state.setdefault("progress_stage_total", None)
    st.session_state.setdefault("progress_stage_message", "")
    st.session_state.setdefault("progress_files_done", 0)
    st.session_state.setdefault("progress_files_total", None)
    st.session_state.setdefault("progress_file_path", None)
    st.session_state.setdefault("progress_file_done", None)
    st.session_state.setdefault("progress_file_total", None)
    st.session_state.setdefault("cancel_token", None)
    # Backward-compat: older versions used a widget key named "preview_output".
    # Ensure it doesn't linger and cause confusing state errors across hot-reloads.
    st.session_state.pop("preview_output", None)


def _get_app_version() -> str:
    try:
        from importlib import metadata

        return "v" + metadata.version("log-anonymizer")
    except Exception:
        pass

    try:
        repo_root = Path(__file__).resolve().parents[2]
        pyproject = repo_root / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        v = (
            data.get("project", {})
            .get("version", "")
        )
        if isinstance(v, str) and v.strip():
            return "v" + v.strip()
    except Exception:
        pass

    return "v?"


def _render_footer() -> None:
    version = _get_app_version()
    st.markdown(
        f"""
        <style>
          div.da-footer {{
            position: fixed;
            left: 12px;
            bottom: 10px;
            z-index: 1000;
            opacity: 0.65;
            font-size: 12px;
            pointer-events: none;
          }}
          @media (prefers-color-scheme: dark) {{
            div.da-footer {{
              opacity: 0.55;
            }}
          }}
        </style>
        <div class="da-footer">Log Anonymizer {html.escape(version)}</div>
        """,
        unsafe_allow_html=True,
    )


def _render_sidebar() -> PreparedRun:
    st.sidebar.header("Configuration")
    st.session_state["ui_warnings"] = []
    st.session_state["ui_errors"] = []

    input_mode: InputMode = st.sidebar.radio(
        "Input source",
        options=["Upload", "Use path(s)"],
        index=0,
    )

    uploaded_inputs = None
    input_paths_text = ""
    if input_mode == "Upload":
        uploaded_inputs = st.sidebar.file_uploader(
            "Upload one or more inputs (files and/or archives)",
            type=None,
            accept_multiple_files=True,
        )
    else:
        input_paths_text = st.sidebar.text_area(
            "Input path(s) (one per line)",
            value="tmp_test/in",
            height=110,
        )

    uploaded_rules = st.sidebar.file_uploader("Rules JSON", type=["json"], key="rules_upload")
    uploaded_exclude = st.sidebar.file_uploader(
        "Exclude file (.exclude)", type=None, key="exclude_upload"
    )

    output_dir_text = st.sidebar.text_input("Output directory", value="tmp_test/ui_out")
    verbose = st.sidebar.checkbox("Verbose mode (DEBUG)", value=False)
    dry_run = st.sidebar.checkbox("Dry run", value=False)
    anonymize_filenames = st.sidebar.checkbox(
        "Anonymize file and folder names",
        value=False,
        help="Applies anonymization rules to output file/folder names (when possible) and also sanitizes the output archive name.",
    )
    st.sidebar.markdown("### Performance")
    batch_parallel_enabled = st.sidebar.checkbox(
        "Enable parallel input processing (batch)",
        value=False,
        help="Runs multiple top-level inputs concurrently. Separate from per-file parallelism inside each input.",
    )
    batch_max_workers = int(
        st.sidebar.number_input(
            "Max parallel inputs",
            min_value=1,
            max_value=16,
            value=2,
            step=1,
            disabled=not batch_parallel_enabled,
            help="Only used when batch parallelism is enabled (default: 2).",
        )
    )
    parallel_enabled = st.sidebar.checkbox(
        "Enable parallel file processing",
        value=False,
        help="Processes files concurrently to speed up large bundles. Output is functionally identical.",
    )
    default_workers = int(os.getenv("LOG_ANONYMIZER_WORKERS", "5"))
    max_workers = int(
        st.sidebar.number_input(
            "Max parallel workers",
            min_value=1,
            max_value=64,
            value=max(1, min(64, default_workers)),
            step=1,
            disabled=not parallel_enabled,
            help="Only used when parallel processing is enabled (default: 5).",
        )
    )
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
        uploaded_inputs=uploaded_inputs,
        input_paths_text=input_paths_text,
        uploaded_rules=uploaded_rules,
        uploaded_exclude=uploaded_exclude,
        output_dir_text=output_dir_text,
        verbose=verbose,
        dry_run=dry_run,
        profile_sensitive_data=profile_sensitive_data,
        profiling_detectors=profiling_detectors,
        batch_parallel_enabled=batch_parallel_enabled,
        batch_max_workers=batch_max_workers,
        parallel_enabled=parallel_enabled,
        max_workers=max_workers,
        anonymize_filenames=anonymize_filenames,
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
    uploaded_inputs,
    input_paths_text: str,
    uploaded_rules,
    uploaded_exclude,
    output_dir_text: str,
    verbose: bool,
    dry_run: bool,
    profile_sensitive_data: bool,
    profiling_detectors: tuple[str, ...],
    batch_parallel_enabled: bool,
    batch_max_workers: int,
    parallel_enabled: bool,
    max_workers: int,
    anonymize_filenames: bool,
) -> PreparedRun:
    tmp_dir = _ensure_tmp_dir()

    input_paths: list[Path] = []
    if input_mode == "Upload":
        if uploaded_inputs:
            input_paths = _save_uploads_cached(tmp_dir, uploaded_inputs)
    else:
        raw = (input_paths_text or "").strip()
        if raw:
            for line in raw.splitlines():
                s = (line or "").strip()
                if not s:
                    continue
                input_paths.append(Path(s).expanduser())

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
        input_paths=input_paths,
        rules_path=rules_path,
        exclude_path=exclude_path,
        output_dir=output_dir,
        verbose=verbose,
        dry_run=dry_run,
        profile_sensitive_data=profile_sensitive_data,
        profiling_detectors=profiling_detectors,
        parallel_enabled=parallel_enabled,
        max_workers=int(max_workers),
        anonymize_filenames=bool(anonymize_filenames),
        batch_parallel_enabled=bool(batch_parallel_enabled),
        batch_max_workers=int(batch_max_workers),
    )


def _ensure_tmp_dir() -> Path:
    existing = st.session_state.get("tmp_dir")
    if existing and Path(existing).exists():
        return Path(existing)
    tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-ui-")).resolve()
    st.session_state["tmp_dir"] = str(tmp_dir)
    return tmp_dir


def _save_upload_cached(tmp_dir: Path, uploaded, *, name_hint: str) -> Path:
    """
    Persist an uploaded file to disk in a stable, content-addressed path.

    Streamlit re-runs the script frequently; without caching, we might overwrite the same
    on-disk tar.gz while a background worker is reading it (leading to intermittent EOF/ReadError).
    """
    tmp_dir.mkdir(parents=True, exist_ok=True)
    raw = bytes(uploaded.getbuffer())
    safe_name = Path(name_hint).name
    sig = _sig(safe_name, raw)

    target = (tmp_dir / f"input-{sig[:12]}-{safe_name}").resolve()
    if not target.exists():
        _atomic_write_bytes(target, raw)
    return target


def _save_uploads_cached(tmp_dir: Path, uploaded_list) -> list[Path]:
    out: list[Path] = []
    for up in list(uploaded_list or []):
        name_hint = str(getattr(up, "name", "") or "input")
        out.append(_save_upload_cached(tmp_dir, up, name_hint=name_hint))
    return out


def _atomic_write_bytes(target: Path, raw: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, target)


def _default_output_archive_path(output_dir: Path, input_path: Path, *, anonymize_filenames: bool) -> Path:
    out_dir = output_dir.expanduser().resolve()
    if anonymize_filenames:
        return out_dir / "anonymized_output.tar.gz"
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
    st.session_state["progress_stage"] = None
    st.session_state["progress_stage_current"] = None
    st.session_state["progress_stage_total"] = None
    st.session_state["progress_stage_message"] = ""
    st.session_state["progress_files_done"] = 0
    st.session_state["progress_files_total"] = None
    st.session_state["progress_file_path"] = None
    st.session_state["progress_file_done"] = None
    st.session_state["progress_file_total"] = None
    st.session_state["cancel_token"] = None
    st.session_state["batch_mode"] = len(run.input_paths) > 1
    st.session_state["batch_items"] = None
    st.session_state["batch_current_input"] = ""
    st.session_state["batch_done"] = 0
    st.session_state["batch_total"] = len(run.input_paths) if run.input_paths else None

    err = _validate_run(run)
    if err:
        st.session_state["run_error"] = err
        return

    st.session_state["run_in_progress"] = True
    st.session_state["run_status"] = "Running…"
    cancel_token = CancellationToken()
    st.session_state["cancel_token"] = cancel_token

    log_q: Queue[str] = Queue()
    outcome_q: Queue[dict[str, Any]] = Queue()
    progress_q: Queue[ProgressEvent] = Queue()
    st.session_state["log_queue"] = log_q
    st.session_state["outcome_queue"] = outcome_q
    st.session_state["progress_queue"] = progress_q

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
    while True:
        try:
            progress_q.get_nowait()
        except Empty:
            break

    handler, prev = _attach_streamlit_logger(log_q, verbose=run.verbose)
    st.session_state["log_handler"] = handler
    st.session_state["log_prev_handlers"] = prev

    thread = threading.Thread(
        target=_run_pipeline_thread,
        args=(run, cancel_token, log_q, outcome_q, progress_q),
        daemon=True,
    )
    thread.start()


def _request_cancel() -> None:
    token = st.session_state.get("cancel_token")
    if token is None:
        return
    try:
        token.cancel()
    except Exception:
        return
    st.session_state["run_status"] = "Cancellation requested…"


def _validate_run(run: PreparedRun) -> str | None:
    ui_errors = st.session_state.get("ui_errors") or []
    if ui_errors:
        return str(ui_errors[0])
    if not run.input_paths:
        return "Please provide at least one input (upload or paths)."
    for p in run.input_paths:
        if str(p).strip() in ("", "."):
            return "Please provide valid input path(s)."
        if not p.exists():
            return f"Input path does not exist: {p}"
    if not run.output_dir or str(run.output_dir) == "":
        return "Please provide an output directory."
    if run.output_dir.exists() and not run.output_dir.is_dir():
        return f"Output directory is not a directory: {run.output_dir}"
    if not run.rules_path.exists():
        return f"Rules file could not be created: {run.rules_path}"
    if run.exclude_path is not None and not run.exclude_path.exists():
        return f"Exclude file does not exist: {run.exclude_path}"
    return None


def _run_pipeline_thread(
    run: PreparedRun,
    cancel_token: CancellationToken,
    log_q: Queue[str],
    outcome_q: Queue[dict[str, Any]],
    progress_q: Queue[ProgressEvent],
) -> None:
    try:
        t0 = time.perf_counter()
        if not run.input_paths:
            outcome_q.put({"type": "error", "status": "Failed.", "error": "Missing input(s)."})
            return
        if cancel_token.is_cancelled():
            outcome_q.put(
                {
                    "type": "done",
                    "status": "Cancelled with partial output kept.\n- No output produced.",
                    "archive_path": None,
                    "cancelled": True,
                    "rolled_back": False,
                }
            )
            return
        if run.dry_run:
            elapsed_s = int(round(time.perf_counter() - t0))
            if run.profile_sensitive_data:
                lines = ["DRY RUN (profiling only)"]
                for p in run.input_paths:
                    res = run_sensitive_data_profiling(
                        input_path=p,
                        output_dir=run.output_dir,
                        exclude_path=run.exclude_path,
                        detectors=run.profiling_detectors,
                    )
                    lines.append(f"- Input: {p}")
                    lines.append(f"  - Profiling report: {res.profiling_report_path}")
                    lines.append(f"  - Suggested rules: {res.suggested_rules_path}")
                    lines.append(
                        f"  - Files: total={res.total_files}, excluded={res.excluded_files}, profiled={res.profiled_files}"
                    )
                lines.append(f"- Duration: {elapsed_s}s")
                log_q.put("\n".join(lines) + "\n")
                outcome_q.put(
                    {
                        "type": "done",
                        "status": "Dry run (profiling only) completed.",
                        "archive_path": None,
                    }
                )
                return

            if len(run.input_paths) == 1:
                summary = _dry_run_single(run, run.input_paths[0])
            else:
                parts = ["DRY RUN (batch)", f"- Inputs: {len(run.input_paths)}"]
                for p in run.input_paths:
                    block = _dry_run_single(run, p).rstrip("\n")
                    lines = block.splitlines()
                    parts.append("\n".join(lines[1:] if len(lines) > 1 else lines))
                summary = "\n".join(parts) + "\n"
            summary = summary.rstrip("\n") + f"\n- Duration: {elapsed_s}s\n"
            log_q.put(summary)
            outcome_q.put({"type": "done", "status": "Dry run completed.", "archive_path": None})
            return

        cfg = ProcessorConfig(
            parallel_enabled=bool(run.parallel_enabled),
            max_workers=int(run.max_workers),
            exclude_case_insensitive=False,
            include_builtin_rules=True,
            profile_sensitive_data=bool(run.profile_sensitive_data),
            anonymize_filenames=bool(run.anonymize_filenames),
            profiling_detectors=run.profiling_detectors,
            cancellation_token=cancel_token,
            rollback_on_cancel=False,
        )
        reporter = QueueProgressReporter(progress_q)
        if len(run.input_paths) == 1:
            result = process_with_result(
                input_path=run.input_paths[0],
                rules_path=run.rules_path,
                output_dir=run.output_dir,
                exclude_path=run.exclude_path,
                config=cfg,
                progress=reporter,
            )
            elapsed_s = int(round(time.perf_counter() - t0))
            if result.cancelled and result.rolled_back:
                title = "Cancelled and rolled back."
            elif result.cancelled:
                title = "Cancelled with partial output kept."
            else:
                title = "Completed."
            summary_lines = [title]
            if result.output_zip.exists():
                summary_lines.append(f"- Output archive: {result.output_zip}")
            summary_lines.append(f"- Duration: {elapsed_s}s")
            if result.profiling_report_path:
                summary_lines.append(f"- Profiling report: {result.profiling_report_path}")
            if result.suggested_rules_path:
                summary_lines.append(f"- Suggested rules: {result.suggested_rules_path}")
            summary_lines.extend(
                [
                    f"- Total files: {result.total_files}",
                    f"- Excluded: {result.excluded_files}",
                    f"- Processed: {result.processed_files}",
                    f"- Failed: {result.failed_files}",
                ]
            )
            summary = "\n".join(summary_lines)
            outcome_q.put(
                {
                    "type": "done",
                    "status": summary,
                    "archive_path": str(result.output_zip) if result.output_zip.exists() else None,
                    "profiling_report_path": str(result.profiling_report_path)
                    if result.profiling_report_path is not None
                    else None,
                    "suggested_rules_path": str(result.suggested_rules_path)
                    if result.suggested_rules_path is not None
                    else None,
                    "cancelled": bool(result.cancelled),
                    "rolled_back": bool(result.rolled_back),
                    "summary": {
                        "total": result.total_files,
                        "excluded": result.excluded_files,
                        "processed": result.processed_files,
                        "failed": result.failed_files,
                    },
                }
            )
            return

        batch = process_batch_with_result(
            inputs=run.input_paths,
            rules_path=run.rules_path,
            output_dir=run.output_dir,
            exclude_path=run.exclude_path,
            config=cfg,
            batch_parallel_enabled=bool(run.batch_parallel_enabled),
            batch_max_workers=int(run.batch_max_workers or 2),
            progress=reporter,
        )
        elapsed_s = int(round(time.perf_counter() - t0))
        summary_lines = [
            "Batch completed.",
            f"- Batch directory: {batch.batch_dir}",
            f"- Duration: {elapsed_s}s",
            f"- Inputs: total={batch.total} ok={batch.succeeded} failed={batch.failed} cancelled={batch.cancelled} skipped={batch.skipped}",
            f"- Summary JSON: {batch.summary_path}",
        ]
        outcome_q.put(
            {
                "type": "done",
                "status": "\n".join(summary_lines),
                "archive_path": None,
                "batch_dir": str(batch.batch_dir),
                "batch_summary_path": str(batch.summary_path),
                "batch_items": [
                    {
                        "input_path": str(it.input_path),
                        "input_name": it.input_path.name,
                        "status": it.status,
                        "output_archive": str(it.output_archive) if it.output_archive else None,
                        "error": it.error,
                        "profiling_report_path": str(it.result.profiling_report_path)
                        if it.result is not None and it.result.profiling_report_path is not None
                        else None,
                        "suggested_rules_path": str(it.result.suggested_rules_path)
                        if it.result is not None and it.result.suggested_rules_path is not None
                        else None,
                    }
                    for it in batch.items
                ],
            }
        )
    except Exception as exc:  # noqa: BLE001 (UI boundary)
        log_q.put(f"ERROR: {type(exc).__name__}: {exc}")
        outcome_q.put(
            {"type": "error", "status": "Failed.", "error": f"{type(exc).__name__}: {exc}"}
        )


def _dry_run_single(run: PreparedRun, input_path: Path) -> str:
    user_rules = load_rules(run.rules_path)

    with handle_input(input_path) as prepared:
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

    zip_path = _default_output_archive_path(run.output_dir, input_path, anonymize_filenames=bool(run.anonymize_filenames))
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
        f"- Input: {input_path}",
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


@st.cache_data(show_spinner=False)
def _read_bytes_cached(path: str) -> bytes:
    return Path(path).read_bytes()


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

    _pump_progress_once()
    _pump_outcome_once()


def _pump_progress_once() -> None:
    q: Queue[ProgressEvent] = st.session_state["progress_queue"]
    batch_mode = bool(st.session_state.get("batch_mode"))
    while True:
        try:
            ev = q.get_nowait()
        except Empty:
            break

        st.session_state["progress_stage"] = ev.stage.value
        st.session_state["progress_stage_current"] = ev.current
        st.session_state["progress_stage_total"] = ev.total
        if ev.message:
            st.session_state["progress_stage_message"] = ev.message

        if batch_mode and ev.stage == ProgressStage.PROCESSING and ev.kind in (
            ProgressKind.STAGE_START,
            ProgressKind.STAGE_PROGRESS,
            ProgressKind.STAGE_END,
        ):
            if ev.current is not None:
                st.session_state["batch_done"] = int(ev.current)
            if ev.total is not None:
                st.session_state["batch_total"] = int(ev.total)
            msg = str(ev.message or "")
            if msg.startswith("input="):
                st.session_state["batch_current_input"] = msg[len("input="):]
            st.session_state["progress_files_total"] = None
            st.session_state["progress_file_path"] = None
            st.session_state["progress_file_done"] = None
            st.session_state["progress_file_total"] = None
        else:
            if ev.kind == ProgressKind.STAGE_START and ev.stage == ProgressStage.PROCESSING:
                st.session_state["progress_files_done"] = 0
                st.session_state["progress_files_total"] = ev.total
            if ev.kind == ProgressKind.STAGE_PROGRESS and ev.stage == ProgressStage.PROCESSING:
                if ev.current is not None:
                    st.session_state["progress_files_done"] = ev.current
                if ev.total is not None:
                    st.session_state["progress_files_total"] = ev.total

            if ev.kind in (ProgressKind.FILE_START, ProgressKind.FILE_PROGRESS, ProgressKind.FILE_END):
                if ev.path:
                    st.session_state["progress_file_path"] = ev.path
                st.session_state["progress_file_done"] = ev.bytes_done
                st.session_state["progress_file_total"] = ev.bytes_total


def _render_progress_panel() -> None:
    stage = st.session_state.get("progress_stage") or ""
    stage_msg = st.session_state.get("progress_stage_message") or ""
    cur = st.session_state.get("progress_stage_current")
    total = st.session_state.get("progress_stage_total")

    files_done = int(st.session_state.get("progress_files_done") or 0)
    files_total = st.session_state.get("progress_files_total")

    file_path = st.session_state.get("progress_file_path")
    file_done = st.session_state.get("progress_file_done")
    file_total = st.session_state.get("progress_file_total")

    st.subheader("Progress")

    if bool(st.session_state.get("batch_mode")):
        done = int(st.session_state.get("batch_done") or 0)
        tot = st.session_state.get("batch_total")
        current_input = str(st.session_state.get("batch_current_input") or "")
        if tot is not None and int(tot) > 0:
            frac = min(1.0, float(done) / float(tot))
            label = f"Inputs: {done}/{tot}"
            if current_input:
                label += f" (current: {current_input})"
            st.progress(frac, text=label)
        else:
            st.progress(0.0, text="Inputs: (waiting)")
        if stage_msg:
            st.caption(f"Stage: {stage} ({stage_msg})" if stage else stage_msg)
        return

    if files_total is not None and int(files_total) > 0:
        frac = min(1.0, float(files_done) / float(files_total))
        st.progress(frac, text=f"Files: {files_done}/{files_total}")
    else:
        st.progress(0.0, text="Files: (waiting)")

    if total is not None and cur is not None and int(total) > 0:
        frac = min(1.0, float(cur) / float(total))
        label = f"Stage: {stage} {cur}/{total}"
        if stage_msg:
            label += f" ({stage_msg})"
        st.progress(frac, text=label)
    else:
        label = f"Stage: {stage}".strip()
        if stage_msg:
            label = (label + f" ({stage_msg})").strip()
        st.caption(label or "Stage: (waiting)")

    if file_path and file_done is not None and file_total is not None and int(file_total) > 0:
        frac = min(1.0, float(file_done) / float(file_total))
        st.progress(frac, text=f"File: {file_path}")
    elif file_path:
        st.caption(f"File: {file_path}")


def _pump_outcome_once() -> None:
    outcome_q: Queue[dict[str, Any]] = st.session_state["outcome_queue"]
    while True:
        try:
            outcome = outcome_q.get_nowait()
        except Empty:
            break

        if outcome.get("type") == "done":
            st.session_state["run_status"] = str(outcome.get("status") or "Completed.")
            batch_items = outcome.get("batch_items")
            if isinstance(batch_items, list) and batch_items:
                st.session_state["batch_items"] = batch_items
                st.session_state["result_zip_bytes"] = None
                st.session_state["result_zip_name"] = None
            archive_path = outcome.get("archive_path")
            if isinstance(archive_path, str) and archive_path:
                p = Path(archive_path)
                if p.exists():
                    st.session_state["result_zip_bytes"] = p.read_bytes()
                    st.session_state["result_zip_name"] = p.name
                else:
                    st.session_state["result_zip_bytes"] = None
                    st.session_state["result_zip_name"] = None
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
            st.session_state["cancel_token"] = None
            _restore_logger_if_needed()
        elif outcome.get("type") == "error":
            st.session_state["run_status"] = str(outcome.get("status") or "Failed.")
            st.session_state["run_error"] = str(outcome.get("error") or "Unknown error")
            st.session_state["run_in_progress"] = False
            st.session_state["cancel_token"] = None
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
            st.session_state["preview_line_details"] = res.line_details
            st.session_state["preview_replacements_by_rule"] = dict(res.stats.replacements_by_rule)
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
        st.session_state["preview_line_details"] = ()
        st.session_state["preview_replacements_by_rule"] = {}
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

    st.markdown(
        """
        <style>
          div.da-preview-wrap {
            border-radius: 10px;
            border: 1px solid rgba(120, 120, 140, 0.25);
            background: rgba(248, 249, 251, 1.0);
            padding: 10px 12px;
            max-height: 360px;
            overflow: auto;
          }
          div.da-preview {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 13px;
            line-height: 1.38;
            margin: 0;
          }
          div.da-line {
            display: flex;
            gap: 8px;
            align-items: flex-start;
          }
          span.da-mark {
            display: inline-block;
            width: 16px;
            opacity: 0.45;
            flex: 0 0 16px;
          }
          span.da-mark-on {
            opacity: 1.0;
            font-weight: 700;
          }
          span.da-text {
            /* Keep explicit line breaks (one log line per line), but allow wrapping for long lines. */
            white-space: pre-wrap;
            word-break: break-word;
            flex: 1 1 auto;
          }
          span.da-hl {
            background: rgba(255, 208, 77, 0.55);
            border-bottom: 2px solid rgba(176, 106, 0, 0.95);
            border-radius: 4px;
            padding: 0 2px;
          }
          @media (prefers-color-scheme: dark) {
            div.da-preview-wrap {
              background: rgba(255, 255, 255, 0.04);
              border-color: rgba(255, 255, 255, 0.10);
            }
            span.da-hl {
              background: rgba(0, 169, 255, 0.35);
              border-bottom: 2px solid rgba(0, 169, 255, 0.95);
            }
            span.da-mark-on {
              color: rgba(0, 169, 255, 0.95);
            }
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    out_tabs = st.tabs(["Output (highlighted)", "Output (plain text)"])
    with out_tabs[0]:
        st.caption("Legend: highlighted text = anonymized content")
        details: tuple[PreviewLineDetail, ...] = st.session_state.get("preview_line_details") or ()
        if details:
            st.markdown(_render_highlighted_preview(details), unsafe_allow_html=True)
        else:
            st.info("Run a preview to see highlighted output.")
    with out_tabs[1]:
        st.code(text_out or "", language="text")
    m1, m2, m3 = st.columns(3)
    m1.metric("Input lines", lines_in)
    m2.metric("Output lines", lines_out)
    m3.metric("User rules", _preview_rules_count(run))

    repls_by_rule = st.session_state.get("preview_replacements_by_rule") or {}
    if repls_by_rule:
        with st.expander("Triggered rules (preview)", expanded=False):
            rows = [
                {"rule": k, "replacements": v}
                for k, v in sorted(
                    repls_by_rule.items(), key=lambda kv: (-int(kv[1]), str(kv[0]))
                )
            ]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

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


def _render_highlighted_preview(details: tuple[PreviewLineDetail, ...]) -> str:
    """
    Render the anonymized output with changed segments highlighted.

    Uses HTML, but escapes all user content to avoid unsafe rendering.
    """

    def _hl_line(text: str, spans) -> str:
        if not spans:
            return html.escape(text)
        out: list[str] = []
        i = 0
        for s in spans:
            start = max(0, min(int(s.start), len(text)))
            end = max(start, min(int(s.end), len(text)))
            out.append(html.escape(text[i:start]))
            out.append(
                f'<span class="da-hl" title="Anonymized">{html.escape(text[start:end])}</span>'
            )
            i = end
        out.append(html.escape(text[i:]))
        return "".join(out)

    lines: list[str] = []
    for d in details:
        mark_cls = "da-mark da-mark-on" if d.changed_spans else "da-mark"
        mark = f'<span class="{mark_cls}" title="Line changed">▍</span>'
        text = f'<span class="da-text">{_hl_line(d.anonymized, d.changed_spans)}</span>'
        lines.append(f'<div class="da-line">{mark}{text}</div>')
    body = "\n".join(lines)
    return f'<div class="da-preview-wrap"><div class="da-preview">{body}</div></div>'


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
    if st.session_state.get("rules_editor_df_v1") is None:
        st.session_state["rules_editor_df_v1"] = pd.DataFrame(
            columns=["description", "trigger", "search", "replace", "caseSensitive"]
        )
    if st.session_state.get("rules_editor_df_v2") is None:
        st.session_state["rules_editor_df_v2"] = pd.DataFrame(
            columns=["description", "trigger", "search", "action", "caseSensitive"]
        )
    if st.session_state.get("rules_editor_mode") not in ("table_v1", "table_v2", "json"):
        st.session_state["rules_editor_mode"] = "table_v1"
    # Initialize the radio label only when missing/invalid; do not force it on every rerun.
    if st.session_state.get("rules_editor_mode_radio") not in ("Table (v1)", "Table (v2)", "JSON (v1/v2)"):
        st.session_state["rules_editor_mode_radio"] = _label_for_rules_editor_mode(st.session_state["rules_editor_mode"])
    if st.session_state.get("rules_editor_text") is None:
        raw = _rules_dfs_to_json_bytes(
            st.session_state["rules_editor_df_v1"],
            st.session_state["rules_editor_df_v2"],
        )
        st.session_state["rules_editor_text"] = raw.decode("utf-8")
    if st.session_state.get("rules_editor_json_widget") is None:
        # Only set an initial value for the JSON widget; avoid modifying it after instantiation.
        st.session_state["rules_editor_json_widget"] = st.session_state["rules_editor_text"]


def _label_for_rules_editor_mode(mode: str) -> str:
    if mode == "table_v2":
        return "Table (v2)"
    if mode == "json":
        return "JSON (v1/v2)"
    return "Table (v1)"


def _mode_for_rules_editor_label(label: str) -> str:
    if label == "Table (v2)":
        return "table_v2"
    if label == "JSON (v1/v2)":
        return "json"
    return "table_v1"


def _sync_rules_editor_json_from_tables() -> None:
    raw = _rules_dfs_to_json_bytes(
        st.session_state["rules_editor_df_v1"],
        st.session_state["rules_editor_df_v2"],
    )
    text = raw.decode("utf-8")
    st.session_state["rules_editor_text"] = text
    # Do not update the JSON widget value here; Streamlit forbids updating a widget's
    # session_state key after instantiation. Use the mode-change callback instead.


def _on_add_rule_clicked() -> None:
    _ensure_rules_editor_initialized()
    label = st.session_state.get("rules_editor_mode_radio") or _label_for_rules_editor_mode(
        st.session_state.get("rules_editor_mode", "table_v1")
    )
    mode = _mode_for_rules_editor_label(str(label))
    if mode == "json":
        return

    if mode == "table_v2":
        df = st.session_state["rules_editor_df_v2"]
        df = pd.concat(
            [
                df,
                pd.DataFrame(
                    [
                        {
                            "description": "",
                            "trigger": "",
                            "search": "",
                            "action": '{"type":"redaction"}',
                            "caseSensitive": "",
                        }
                    ]
                ),
            ],
            ignore_index=True,
        )
        st.session_state["rules_editor_df_v2"] = df
    else:
        df = st.session_state["rules_editor_df_v1"]
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
        st.session_state["rules_editor_df_v1"] = df

    _sync_rules_editor_json_from_tables()


def _on_reset_rules_clicked() -> None:
    _ensure_rules_editor_initialized()
    st.session_state["rules_editor_df_v1"] = pd.DataFrame(
        columns=["description", "trigger", "search", "replace", "caseSensitive"]
    )
    st.session_state["rules_editor_df_v2"] = pd.DataFrame(
        columns=["description", "trigger", "search", "action", "caseSensitive"]
    )
    st.session_state["rules_editor_mode"] = "table_v1"
    st.session_state["rules_editor_mode_radio"] = "Table (v1)"
    _sync_rules_editor_json_from_tables()
    # Allow re-uploading the same file after a reset.
    st.session_state["rules_upload_sig"] = None


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


def _rules_dfs_to_json_bytes(df_v1: "pd.DataFrame", df_v2: "pd.DataFrame") -> bytes:
    rules: list[dict[str, Any]] = []

    # v1 (legacy) table: search + replace.
    for _, row in df_v1.iterrows():
        description = str(row.get("description") or "").strip()
        trigger = str(row.get("trigger") or "").strip()
        search = str(row.get("search") or "").strip()
        replace = str(row.get("replace") or "")
        case_sensitive = row.get("caseSensitive")

        if not trigger and not search and replace == "" and not description:
            continue
        rule: dict[str, Any] = {"description": description, "trigger": trigger, "search": search, "replace": replace}
        if case_sensitive is not None and str(case_sensitive).strip() != "":
            rule["caseSensitive"] = case_sensitive
        rules.append(rule)

    # v2 (action) table: search + action object.
    for _, row in df_v2.iterrows():
        description = str(row.get("description") or "").strip()
        trigger = str(row.get("trigger") or "").strip()
        search = str(row.get("search") or "").strip()
        action_text = str(row.get("action") or "").strip()
        case_sensitive = row.get("caseSensitive")

        if not trigger and not search and not action_text and not description:
            continue

        action_obj: Any
        if not action_text:
            # Let the validator surface a clear error for missing action.
            action_obj = None
        else:
            try:
                action_obj = json.loads(action_text)
            except Exception:
                # Keep raw string so validator can fail clearly (invalid JSON).
                action_obj = action_text

        rule = {"description": description, "trigger": trigger, "search": search, "action": action_obj}
        if case_sensitive is not None and str(case_sensitive).strip() != "":
            rule["caseSensitive"] = case_sensitive
        rules.append(rule)

    version = 2 if any(isinstance(r, dict) and r.get("action") is not None for r in rules) else 1
    payload = {"version": version, "rules": rules}
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_rules_from_editor(tmp_dir: Path) -> Path:
    _ensure_rules_editor_initialized()
    mode = st.session_state.get("rules_editor_mode", "table")
    if mode == "json":
        # Prefer the JSON editor widget content when present.
        text = str(
            st.session_state.get("rules_editor_json_widget")
            or st.session_state.get("rules_editor_text")
            or ""
        )
        raw = text.encode("utf-8")
    else:
        raw = _rules_dfs_to_json_bytes(
            st.session_state["rules_editor_df_v1"],
            st.session_state["rules_editor_df_v2"],
        )
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
        # If the same file is uploaded again but the editor state was reset/migrated,
        # re-apply it so the UI updates correctly.
        df_v1 = st.session_state.get("rules_editor_df_v1")
        df_v2 = st.session_state.get("rules_editor_df_v2")
        text = st.session_state.get("rules_editor_text")
        if (
            isinstance(df_v1, pd.DataFrame)
            and isinstance(df_v2, pd.DataFrame)
            and (not df_v1.empty or not df_v2.empty)
            and isinstance(text, str)
            and text.strip()
        ):
            return
    st.session_state["rules_upload_sig"] = sig

    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return
    rules = obj.get("rules") if isinstance(obj, dict) else None
    if not isinstance(rules, list):
        return

    version_raw = obj.get("version", 1) if isinstance(obj, dict) else 1
    try:
        version = int(version_raw)
    except Exception:
        version = 1

    rows_v1: list[dict[str, Any]] = []
    rows_v2: list[dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        if r.get("action") is not None:
            rows_v2.append(
                {
                    "description": r.get("description", ""),
                    "trigger": r.get("trigger", ""),
                    "search": r.get("search", ""),
                    "action": json.dumps(r.get("action"), ensure_ascii=False),
                    "caseSensitive": r.get("caseSensitive", ""),
                }
            )
        else:
            rows_v1.append(
                {
                    "description": r.get("description", ""),
                    "trigger": r.get("trigger", ""),
                    "search": r.get("search", ""),
                    "replace": r.get("replace", ""),
                    "caseSensitive": r.get("caseSensitive", ""),
                }
            )

    st.session_state["rules_editor_df_v1"] = pd.DataFrame(
        rows_v1, columns=["description", "trigger", "search", "replace", "caseSensitive"]
    )
    st.session_state["rules_editor_df_v2"] = pd.DataFrame(
        rows_v2, columns=["description", "trigger", "search", "action", "caseSensitive"]
    )
    try:
        st.session_state["rules_editor_text"] = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    except Exception:
        st.session_state["rules_editor_text"] = raw.decode("utf-8", errors="replace")
    # Seed the JSON widget with the uploaded content (safe here: before widget instantiation in rerun).
    st.session_state["rules_editor_json_widget"] = st.session_state["rules_editor_text"]

    # Default editor selection: prefer table views; use v2 table when the file is v2 or contains actions.
    if version == 2 or rows_v2:
        st.session_state["rules_editor_mode"] = "table_v2" if rows_v2 else "table_v1"
    else:
        st.session_state["rules_editor_mode"] = "table_v1"
    st.session_state["rules_editor_mode_radio"] = _label_for_rules_editor_mode(
        st.session_state["rules_editor_mode"]
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

    # Keep the widget's state in a dedicated key to avoid "double click" behavior on reruns.
    # IMPORTANT: do not overwrite the widget key on every rerun, otherwise the radio becomes "stuck".
    options = ["Table (v1)", "Table (v2)", "JSON (v1/v2)"]
    current_label = _label_for_rules_editor_mode(st.session_state.get("rules_editor_mode", "table_v1"))
    if st.session_state.get("rules_editor_mode_radio") not in options:
        st.session_state["rules_editor_mode_radio"] = current_label

    def _on_rules_editor_mode_changed() -> None:
        label = st.session_state.get("rules_editor_mode_radio") or "Table (v1)"
        st.session_state["rules_editor_mode"] = _mode_for_rules_editor_label(str(label))
        if st.session_state["rules_editor_mode"] == "json":
            # When switching into JSON mode, refresh the JSON editor with the derived JSON
            # from current tables/upload state.
            st.session_state["rules_editor_json_widget"] = str(st.session_state.get("rules_editor_text") or "")

    mode_label = st.radio(
        "Editor mode",
        options=options,
        key="rules_editor_mode_radio",
        horizontal=True,
        on_change=_on_rules_editor_mode_changed,
    )
    # Ensure mode follows the widget value (the callback handles mode changes, but keep this safe).
    st.session_state["rules_editor_mode"] = _mode_for_rules_editor_label(mode_label)

    b1, b2, _ = st.columns([1.2, 1.2, 6])
    b1.button(
        "Add rule",
        key="add_rule",
        disabled=st.session_state["rules_editor_mode"] == "json",
        on_click=_on_add_rule_clicked,
    )
    b2.button(
        "Reset rules",
        key="reset_rules",
        on_click=_on_reset_rules_clicked,
    )

    if st.session_state["rules_editor_mode"] == "table_v1":
        edited = st.data_editor(
            st.session_state["rules_editor_df_v1"],
            key="rules_editor_v1",
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
        st.session_state["rules_editor_df_v1"] = edited
        raw = _rules_dfs_to_json_bytes(edited, st.session_state["rules_editor_df_v2"])
        st.session_state["rules_editor_text"] = raw.decode("utf-8")
    elif st.session_state["rules_editor_mode"] == "table_v2":
        edited = st.data_editor(
            st.session_state["rules_editor_df_v2"],
            key="rules_editor_v2",
            num_rows="dynamic",
            width="stretch",
            column_config={
                "description": st.column_config.TextColumn("description"),
                "trigger": st.column_config.TextColumn("trigger"),
                "search": st.column_config.TextColumn("search (regex)"),
                "action": st.column_config.TextColumn("action (JSON)"),
                "caseSensitive": st.column_config.TextColumn("caseSensitive"),
            },
        )
        st.session_state["rules_editor_df_v2"] = edited
        raw = _rules_dfs_to_json_bytes(st.session_state["rules_editor_df_v1"], edited)
        st.session_state["rules_editor_text"] = raw.decode("utf-8")
    else:
        def _on_rules_json_changed() -> None:
            st.session_state["rules_editor_text"] = str(st.session_state.get("rules_editor_json_widget") or "")

        # Ensure the JSON widget has some initial content before it is instantiated.
        if st.session_state.get("rules_editor_json_widget") is None:
            st.session_state["rules_editor_json_widget"] = str(st.session_state.get("rules_editor_text") or "")
        st.text_area(
            "rules.json",
            key="rules_editor_json_widget",
            height=320,
            on_change=_on_rules_json_changed,
        )
        text = str(st.session_state.get("rules_editor_json_widget") or "")
        st.session_state["rules_editor_text"] = text
        raw = text.encode("utf-8")

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
    return validate_rules_json_bytes(raw)


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
