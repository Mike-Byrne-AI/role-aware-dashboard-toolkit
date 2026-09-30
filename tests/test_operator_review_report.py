"""The portable example report treats imported packets as data, never code."""
from copy import deepcopy
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import sys

import pytest

import role_aware_dashboard_toolkit as radt
from examples.operator_review.report import render_run_report
from role_aware_dashboard_toolkit.team_ops import build_handoff_summary, build_signoff_record


def packet():
    run = radt.build_run({"model": "small"}, run_id="review-demo", source_profile_id="baseline")
    for label, latency in [("Baseline", 100), ("Candidate", 150)]:
        run = radt.append_checkpoint(
            run, {"model": "small"}, label=label, reason="Synthetic comparison",
            telemetry={"ts": "2026-09-20T10:00:00+00:00", "metrics": {"latency": latency}, "units": {"latency": "ms"}},
        )
    run = radt.end_run(run, outcome="changes_requested")
    signoff = build_signoff_record(run["run_id"], "changes_requested", checkpoint_id=run["last_checkpoint_id"],
                                   actor="Demo reviewer", role="Reviewer", reason="Latency increased.")
    result = radt.build_run_packet(run)
    result["meta"]["operator_review"] = {
        "signoffs": [signoff],
        "handoff": build_handoff_summary(run, signoffs=[signoff], handoff_to="Demo operator", notes="Try another setting."),
        "simulation": "Simulated values; no model calls.",
    }
    return result


def test_report_explains_outcomes_and_review_without_changing_evidence():
    source = packet()
    before = deepcopy(source)
    html = render_run_report(source)
    assert source == before
    for text in ("review-demo", "baseline", "changes_requested", "Demo reviewer", "Latency increased.",
                 "Try another setting.", "Simulated values", "50", "ms", "2026-09-20T10:00:00+00:00"):
        assert text in html
    assert "Run completion and checkpoint approval are separate" in html
    assert "does not establish causation or freshness" in html


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_report_escapes_all_imported_text_and_has_no_active_content():
    source = packet()
    attack = '<script>alert(1)</script><img src="https://example.invalid/track" onerror="alert(2)">'
    source["payload"]["notes"] = attack
    source["payload"]["initial_controls"][attack] = attack
    source["payload"]["checkpoints"][0]["label"] = attack
    source["meta"]["operator_review"]["signoffs"][0]["reason"] = attack
    source["meta"]["operator_review"]["handoff"]["notes"] = attack
    source["meta"]["operator_review"]["simulation"] = attack
    html = render_run_report(source)
    assert attack not in html
    assert "&lt;script&gt;" in html
    parsed = Tags()
    parsed.feed(html)
    assert not {tag for tag, _ in parsed.tags}.intersection({"script", "img", "iframe", "form", "a", "link", "object"})
    assert not any(key.startswith("on") or key in {"src", "href"} for _, attrs in parsed.tags for key in attrs)
    assert "default-src 'none'" in html


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(meta=[]),
    lambda p: p["payload"].update(initial_controls=[]),
    lambda p: p["payload"].update(checkpoints=None),
    lambda p: p["payload"]["checkpoints"].append("invalid"),
    lambda p: p["payload"]["checkpoints"].append(deepcopy(p["payload"]["checkpoints"][0])),
    lambda p: p["payload"]["checkpoints"][0].update(telemetry_slice={"metrics": []}),
    lambda p: p["meta"].update(operator_review={"signoffs": "invalid"}),
    lambda p: p["meta"]["operator_review"]["signoffs"][0].update(run_id="other"),
    lambda p: p["meta"]["operator_review"]["signoffs"][0].update(checkpoint_id="missing"),
    lambda p: p["meta"]["operator_review"].update(handoff=[]),
    lambda p: p["payload"]["latest_controls"].update(value=float("nan")),
])
def test_report_rejects_malformed_or_mislinked_evidence(mutation):
    source = packet()
    mutation(source)
    with pytest.raises(ValueError):
        render_run_report(source)


def test_report_handles_empty_run_and_rejects_non_run_packet():
    html = render_run_report(radt.build_run_packet(radt.build_run({})))
    assert "None recorded." in html
    with pytest.raises(ValueError, match="run packets only"):
        render_run_report(radt.build_packet("x_other", {"schema_version": 1}))


def test_report_does_not_render_unselected_audit_or_extension_content():
    source = packet()
    source["payload"]["checkpoints"][0]["audit_slice"] = [{"detail": "AUDIT-ONLY-TEXT"}]
    source["meta"]["unrelated_extension"] = {"data": "EXTENSION-ONLY-TEXT"}
    html = render_run_report(source)
    assert "AUDIT-ONLY-TEXT" not in html
    assert "EXTENSION-ONLY-TEXT" not in html


def test_single_checkpoint_report_includes_legacy_telemetry():
    run = radt.append_checkpoint(radt.build_run({}), {}, telemetry={"queue": {"depth": [2, 7]}})
    html = render_run_report(radt.build_run_packet(run))
    assert "queue.depth" in html
    assert "<td>7.0</td>" in html


def test_report_cli_creates_portable_file_and_refuses_overwrite(tmp_path):
    source = tmp_path / "run.json"
    target = tmp_path / "review.html"
    source.write_text(radt.export_packet_json(packet()), encoding="utf-8")
    command = [sys.executable, "-m", "examples.operator_review.report", str(source), str(target)]
    root = Path(__file__).resolve().parents[1]
    first = subprocess.run(command, cwd=root, text=True, capture_output=True)
    assert first.returncode == 0, first.stderr
    saved = target.read_bytes()
    second = subprocess.run(command, cwd=root, text=True, capture_output=True)
    assert second.returncode == 2
    assert target.read_bytes() == saved


def test_report_rejects_oversized_packet():
    source = packet()
    source["payload"]["notes"] = "x" * (2 * 1024 * 1024)
    with pytest.raises(ValueError, match="2 MiB"):
        render_run_report(source)
