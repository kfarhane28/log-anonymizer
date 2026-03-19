from __future__ import annotations

import json
from pathlib import Path

from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.profiling.runner import run_sensitive_data_profiling
from log_anonymizer.processor import ProcessorConfig, process_with_result


def test_profiling_detects_and_masks_examples() -> None:
    text = (
        "user=john email=john.doe@company.com ip=10.213.0.10\n"
        "Authorization: Bearer sk_test_0123456789abcdef0123456789\n"
        "token=abcdEFGH0123456789abcdEFGH\n"
        "card=4111 1111 1111 1111\n"
    )
    profiler = SensitiveDataProfiler(config=ProfilingConfig(detectors=("email", "ipv4", "token", "card")))
    report = profiler.profile_text(text, source_name="<test>")

    obj = report.to_json_obj()
    assert obj["version"] == 1
    assert obj["files_scanned"] == 1

    examples = obj["masked_examples_by_kind"]
    assert any(e.endswith("@company.com") for e in examples.get("email", []))
    assert not any("john.doe@company.com" in e for e in examples.get("email", []))
    assert any(e.startswith("10.") and e.endswith(".10") for e in examples.get("ipv4", []))

    token_examples = examples.get("bearer_token", []) + examples.get("kv_secret", []) + examples.get(
        "probable_token", []
    )
    assert token_examples
    assert not any("sk_test_0123456789abcdef0123456789" in e for e in token_examples)
    assert any(e.endswith("1111") for e in examples.get("card_number", []))

    suggested = obj["suggested_rules"]
    assert suggested["version"] == 1
    assert isinstance(suggested["rules"], list)
    assert all("search" in r and "replace" in r for r in suggested["rules"])


def test_profiling_in_pipeline_writes_report_and_suggestions(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "a.log").write_text("email=john.doe@company.com ip=10.0.0.1\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    cfg = ProcessorConfig(profile_sensitive_data=True)
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir, config=cfg)

    assert res.profiling_report_path is not None
    assert res.profiling_report_path.exists()
    assert res.suggested_rules_path is not None
    assert res.suggested_rules_path.exists()

    report_text = res.profiling_report_path.read_text(encoding="utf-8")
    assert "john.doe@company.com" not in report_text
    assert "profiling_report" in res.profiling_report_path.name or res.profiling_report_path.name.endswith(".json")

    suggested = json.loads(res.suggested_rules_path.read_text(encoding="utf-8"))
    assert suggested["version"] == 1


def test_profiling_disabled_has_no_side_effects(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "a.log").write_text("email=john.doe@company.com\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir)
    assert res.profiling_report_path is None
    assert res.suggested_rules_path is None


def test_profiling_only_runner_writes_outputs(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "a.log").write_text("email=john.doe@company.com ip=10.0.0.1\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    res = run_sensitive_data_profiling(input_path=inp_dir, output_dir=out_dir)
    assert res.profiling_report_path.exists()
    assert res.suggested_rules_path.exists()
    assert "john.doe@company.com" not in res.profiling_report_path.read_text(encoding="utf-8")
