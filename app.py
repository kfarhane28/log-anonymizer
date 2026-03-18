from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Literal

import streamlit as st

from log_anonymizer.exclude_filter import ExcludeFilter
from log_anonymizer.input_handler import handle_input
from log_anonymizer.exclude_filter import load_patterns as _load_exclude_patterns
from log_anonymizer.processor import ProcessorConfig, process_with_result
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
    # Pump queues early so status updates render in the left column.
    _pump_logs_once()

    st.title("Log Anonymizer")

    run = _render_sidebar()
    center, right = st.columns([3.8, 1.2], gap="large")

    with center:
        top = st.columns([1.4, 1.1, 6])
        run_clicked = top[0].button("Run", type="primary")
        clear_clicked = top[1].button(
            "Clear logs", disabled=st.session_state.get("run_in_progress", False)
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

        st.subheader("Logs")
        log_container = st.container(border=True, height=760)
        with log_container:
            st.code("\n".join(st.session_state["log_lines"][-1200:]), language="text")

        if st.session_state.get("run_in_progress"):
            st.caption("Updating logs…")
            time.sleep(0.25)
            st.rerun()

    with right:
        st.subheader("Output")
        st.write(f"Output directory: `{run.output_dir}`")
        st.write(f"Output zip: `{run.output_dir.with_suffix('.zip')}`")

        if st.session_state.get("result_zip_bytes") is not None:
            st.success("Done.")
            st.download_button(
                "Download zip",
                data=st.session_state["result_zip_bytes"],
                file_name=st.session_state.get("result_zip_name", "anonymized.zip"),
                mime="application/zip",
                use_container_width=True,
            )

        st.subheader("Run")
        st.write(f"Verbose: `{run.verbose}`")
        st.write(f"Dry run: `{run.dry_run}`")
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
    st.session_state.setdefault("tmp_dir", None)
    st.session_state.setdefault("log_handler", None)
    st.session_state.setdefault("log_prev_handlers", None)
    st.session_state.setdefault("ui_warnings", [])
    st.session_state.setdefault("ui_errors", [])


def _render_sidebar() -> PreparedRun:
    st.sidebar.header("Configuration")
    st.session_state["ui_warnings"] = []
    st.session_state["ui_errors"] = []

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
        rules_path = _write_default_rules_file(tmp_dir)
    else:
        raw = bytes(uploaded_rules.getbuffer())
        err = _validate_rules_json_bytes(raw)
        if err:
            st.session_state["ui_errors"].append(f"Rules JSON invalid: {err}")
            rules_path = _write_default_rules_file(tmp_dir)
        else:
            rules_path = _save_upload(tmp_dir, uploaded_rules, name_hint="rules.json")

    exclude_path = None
    if uploaded_exclude is not None:
        raw = bytes(uploaded_exclude.getbuffer())
        err = _validate_exclude_bytes(raw, filename=str(uploaded_exclude.name))
        if err:
            st.session_state["ui_errors"].append(f"Exclude file invalid: {err}")
            exclude_path = None
        else:
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
    if not run.input_path or str(run.input_path) == "":
        return "Please provide an input (upload or path)."
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
        if run.dry_run:
            summary = _dry_run(run)
            log_q.put(summary)
            outcome_q.put({"type": "done", "status": "Dry run completed.", "zip_path": None})
            return

        cfg = ProcessorConfig(
            max_workers=int(os.getenv("LOG_ANONYMIZER_WORKERS", "8")),
            exclude_case_insensitive=False,
            include_builtin_rules=True,
        )
        out_zip = process_with_result(
            input_path=run.input_path,
            rules_path=run.rules_path,
            output_dir=run.output_dir,
            exclude_path=run.exclude_path,
            config=cfg,
        )
        summary = (
            f"Completed.\n"
            f"- Output zip: {out_zip.output_zip}\n"
            f"- Total files: {out_zip.total_files}\n"
            f"- Excluded: {out_zip.excluded_files}\n"
            f"- Processed: {out_zip.processed_files}\n"
            f"- Failed: {out_zip.failed_files}"
        )
        outcome_q.put(
            {
                "type": "done",
                "status": summary,
                "zip_path": str(out_zip.output_zip),
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
    user_rules = load_rules(run.rules_path)

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
    exclude_info = "none"
    if run.exclude_path is not None:
        try:
            exclude_info = f"{run.exclude_path} ({len(_load_exclude_patterns(run.exclude_path))} patterns)"
        except Exception:
            exclude_info = str(run.exclude_path)
    lines = [
        "DRY RUN",
        f"- Input: {run.input_path}",
        f"- Output dir: {run.output_dir}",
        f"- Output zip: {zip_path}",
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
            zip_path = outcome.get("zip_path")
            if isinstance(zip_path, str) and zip_path:
                p = Path(zip_path)
                st.session_state["result_zip_bytes"] = p.read_bytes()
                st.session_state["result_zip_name"] = p.name
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


def _write_default_rules_file(tmp_dir: Path) -> Path:
    """
    Create a minimal rules.json file so users can run with built-in rules only.
    """
    target = (tmp_dir / "rules.json").resolve()
    if target.exists():
        return target
    target.write_text('{"version": 1, "rules": []}\n', encoding="utf-8")
    return target


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
        for key in ("trigger", "search", "replace"):
            if key not in r:
                return f"rules[{i}] missing '{key}'"
            if not isinstance(r[key], str):
                return f"rules[{i}].{key} must be a string"
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
