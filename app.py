from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Iterable, Literal

import streamlit as st

from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.exclude_filter import ExcludeFilter
from log_anonymizer.input_handler import handle_input
from log_anonymizer.processor import ProcessorConfig, process
from log_anonymizer.rules_loader import load_rules


InputMode = Literal["Upload file", "Upload zip", "Use path"]


@dataclass(frozen=True)
class PreparedRun:
    input_path: Path
    rules_path: Path
    exclude_path: Path | None
    output_dir: Path
    verbose: bool
    dry_run: bool


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


def main() -> None:
    st.set_page_config(page_title="Log Anonymizer", layout="wide")
    _init_state()

    st.title("Log Anonymizer")

    run = _render_sidebar()
    left, right = st.columns([1, 1])

    with left:
        st.subheader("Execution")
        run_clicked = st.button("Run Anonymization", type="primary", use_container_width=True)
        if run_clicked:
            _start_run(run)

        if st.session_state.get("run_status"):
            st.write(st.session_state["run_status"])

        if st.session_state.get("result_zip_bytes") is not None:
            st.success("Anonymization finished successfully.")
            st.download_button(
                "Download anonymized zip",
                data=st.session_state["result_zip_bytes"],
                file_name=st.session_state.get("result_zip_name", "anonymized.zip"),
                mime="application/zip",
                use_container_width=True,
            )

        if st.session_state.get("run_error"):
            st.error(st.session_state["run_error"])

    with right:
        st.subheader("Logs")
        log_box = st.empty()

        # Display buffered logs and keep updating while a run is active.
        _pump_logs_once()
        log_box.code("\n".join(st.session_state["log_lines"][-400:]), language="text")

        if st.session_state.get("run_in_progress"):
            st.caption("Updating logs…")
            time.sleep(0.25)
            st.rerun()


def _init_state() -> None:
    st.session_state.setdefault("log_queue", Queue())
    st.session_state.setdefault("log_lines", [])
    st.session_state.setdefault("run_in_progress", False)
    st.session_state.setdefault("run_status", "")
    st.session_state.setdefault("run_error", "")
    st.session_state.setdefault("result_zip_bytes", None)
    st.session_state.setdefault("result_zip_name", None)
    st.session_state.setdefault("tmp_dir", None)


def _render_sidebar() -> PreparedRun:
    st.sidebar.header("Configuration")

    input_mode: InputMode = st.sidebar.radio(
        "Input source",
        options=["Upload file", "Upload zip", "Use path"],
        index=0,
    )

    uploaded_input = None
    input_path_text = ""
    if input_mode == "Upload file":
        uploaded_input = st.sidebar.file_uploader("Upload a log file", type=None)
    elif input_mode == "Upload zip":
        uploaded_input = st.sidebar.file_uploader("Upload a zip archive", type=["zip"])
    else:
        input_path_text = st.sidebar.text_input("Input path", value="tmp_test/in")

    uploaded_rules = st.sidebar.file_uploader("Rules JSON", type=["json"])
    uploaded_exclude = st.sidebar.file_uploader("Exclude file (.exclude)", type=None)

    output_dir_text = st.sidebar.text_input("Output directory", value="tmp_test/ui_out")
    verbose = st.sidebar.checkbox("Verbose mode (DEBUG)", value=False)
    dry_run = st.sidebar.checkbox("Dry run", value=False)

    prepared = _prepare_files(
        input_mode=input_mode,
        uploaded_input=uploaded_input,
        input_path_text=input_path_text,
        uploaded_rules=uploaded_rules,
        uploaded_exclude=uploaded_exclude,
        output_dir_text=output_dir_text,
        verbose=verbose,
        dry_run=dry_run,
    )
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
) -> PreparedRun:
    tmp_dir = _ensure_tmp_dir()

    if input_mode in ("Upload file", "Upload zip"):
        if uploaded_input is None:
            input_path = Path("")
        else:
            suffix = ".zip" if input_mode == "Upload zip" else ""
            input_path = _save_upload(tmp_dir, uploaded_input, name_hint=f"input{suffix}")
    else:
        input_path = Path(input_path_text).expanduser()

    if uploaded_rules is None:
        rules_path = Path("")
    else:
        rules_path = _save_upload(tmp_dir, uploaded_rules, name_hint="rules.json")

    exclude_path = None
    if uploaded_exclude is not None:
        exclude_path = _save_upload(tmp_dir, uploaded_exclude, name_hint=".exclude")

    output_dir = Path(output_dir_text).expanduser()
    return PreparedRun(
        input_path=input_path,
        rules_path=rules_path,
        exclude_path=exclude_path,
        output_dir=output_dir,
        verbose=verbose,
        dry_run=dry_run,
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


def _start_run(run: PreparedRun) -> None:
    st.session_state["run_error"] = ""
    st.session_state["result_zip_bytes"] = None
    st.session_state["result_zip_name"] = None
    st.session_state["log_lines"] = []

    err = _validate_run(run)
    if err:
        st.session_state["run_error"] = err
        return

    st.session_state["run_in_progress"] = True
    st.session_state["run_status"] = "Running…"

    q: Queue[str] = st.session_state["log_queue"]
    while True:
        try:
            q.get_nowait()
        except Empty:
            break

    thread = threading.Thread(target=_run_pipeline_thread, args=(run,), daemon=True)
    thread.start()


def _validate_run(run: PreparedRun) -> str | None:
    if not run.input_path or str(run.input_path) == "":
        return "Please provide an input (upload or path)."
    if not run.rules_path or str(run.rules_path) == "":
        return "Please upload a rules.json file."
    if not run.output_dir or str(run.output_dir) == "":
        return "Please provide an output directory."
    if run.input_path.exists() is False and run.input_path.is_absolute():
        return f"Input path does not exist: {run.input_path}"
    # For uploaded files, input_path is absolute and should exist.
    if run.input_path.is_absolute() and not run.input_path.exists():
        return f"Uploaded input could not be saved: {run.input_path}"
    if not run.rules_path.exists():
        return f"Rules file does not exist: {run.rules_path}"
    if run.exclude_path is not None and not run.exclude_path.exists():
        return f"Exclude file does not exist: {run.exclude_path}"
    return None


def _run_pipeline_thread(run: PreparedRun) -> None:
    q: Queue[str] = st.session_state["log_queue"]
    handler, prev = _attach_streamlit_logger(q, verbose=run.verbose)
    try:
        if run.dry_run:
            summary = _dry_run(run)
            q.put(summary)
            st.session_state["run_status"] = "Dry run completed."
            st.session_state["run_in_progress"] = False
            return

        cfg = ProcessorConfig(
            max_workers=int(os.getenv("LOG_ANONYMIZER_WORKERS", "8")),
            exclude_case_insensitive=False,
            include_builtin_rules=True,
        )
        out_zip = process(
            input_path=run.input_path,
            rules_path=run.rules_path,
            output_dir=run.output_dir,
            exclude_path=run.exclude_path,
            config=cfg,
        )

        data = out_zip.read_bytes()
        st.session_state["result_zip_bytes"] = data
        st.session_state["result_zip_name"] = out_zip.name
        st.session_state["run_status"] = f"Completed: {out_zip}"
    except Exception as exc:  # noqa: BLE001 (UI boundary)
        st.session_state["run_error"] = f"{type(exc).__name__}: {exc}"
        st.session_state["run_status"] = "Failed."
        q.put(f"ERROR: {type(exc).__name__}: {exc}")
    finally:
        _detach_streamlit_logger(handler, prev)
        st.session_state["run_in_progress"] = False


def _dry_run(run: PreparedRun) -> str:
    user_rules = load_rules(run.rules_path)
    rules = merge_rules(builtin=default_rules(), user=user_rules)
    if not rules:
        raise ValueError("No valid rules loaded; nothing to do.")

    with handle_input(run.input_path) as prepared:
        base_dir = prepared.working_dir
        files = prepared.files
        exclude_filter = (
            ExcludeFilter.from_file(run.exclude_path, base_dir=base_dir, case_insensitive=False)
            if run.exclude_path is not None
            else None
        )
        filtered = [f for f in files if not (exclude_filter and exclude_filter.should_exclude(f))]

    zip_path = run.output_dir.expanduser().resolve().with_suffix(".zip")
    lines = [
        "DRY RUN",
        f"- Input: {run.input_path}",
        f"- Output dir: {run.output_dir}",
        f"- Output zip: {zip_path}",
        f"- Rules: {len(rules)} (user={len(user_rules)}, builtin=on)",
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
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
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


if __name__ == "__main__":
    main()
