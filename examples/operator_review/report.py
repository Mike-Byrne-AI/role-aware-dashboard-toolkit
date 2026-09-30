"""Render an exported run as a standalone, read-only HTML report.

This is an example consumer, not a new toolkit packet type. Review records use
the example's ``meta.operator_review`` convention. No packet is executed.
"""
from __future__ import annotations

import argparse
from html import escape
import json
from pathlib import Path
from typing import Any

from role_aware_dashboard_toolkit import compare_checkpoints, export_packet_json, load_packet_json
from role_aware_dashboard_toolkit.validators import (
    validate_checkpoint_record,
    validate_handoff_record,
    validate_run_record,
    validate_signoff_record,
)

MAX_PACKET_BYTES = 2 * 1024 * 1024


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not recorded"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return str(value)


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return '<p class="muted">None recorded.</p>'
    head = "".join(f"<th scope=\"col\">{escape(label)}</th>" for label in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(_text(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _validate(result: dict[str, Any], label: str) -> None:
    if not result["ok"]:
        raise ValueError(f"Invalid {label}: " + "; ".join(result["errors"]))


def _validated_packet(packet: dict[str, Any]) -> dict[str, Any]:
    # Round-trip through the public strict JSON boundary; detach caller data.
    raw = export_packet_json(packet)
    if len(raw.encode("utf-8")) > MAX_PACKET_BYTES:
        raise ValueError("Run packet exceeds the 2 MiB report limit.")
    result = load_packet_json(raw)
    if result["packet_type"] != "run":
        raise ValueError("The report accepts run packets only.")
    run = result["payload"]
    _validate(validate_run_record(run), "run")
    for field in ("initial_controls", "latest_controls"):
        if not isinstance(run[field], dict):
            raise ValueError(f"Run {field} must be an object.")
    if not isinstance(run["checkpoints"], list):
        raise ValueError("Run checkpoints must be a list.")
    checkpoint_ids: set[str] = set()
    for checkpoint in run["checkpoints"]:
        _validate(validate_checkpoint_record(checkpoint), "checkpoint")
        if not isinstance(checkpoint["controls"], dict):
            raise ValueError("Checkpoint controls must be an object.")
        checkpoint_id = checkpoint["checkpoint_id"]
        if not isinstance(checkpoint_id, str) or not checkpoint_id or checkpoint_id in checkpoint_ids:
            raise ValueError("Checkpoint identifiers must be nonempty and unique.")
        checkpoint_ids.add(checkpoint_id)
        telemetry = checkpoint.get("telemetry_slice", {})
        if not isinstance(telemetry, dict):
            raise ValueError("Checkpoint telemetry must be an object.")
        for field in ("metrics", "units"):
            if field in telemetry and not isinstance(telemetry[field], dict):
                raise ValueError(f"Telemetry {field} must be an object.")
    if not isinstance(result.get("meta", {}), dict):
        raise ValueError("Packet metadata must be an object.")
    review = result.get("meta", {}).get("operator_review", {})
    if not isinstance(review, dict) or not isinstance(review.get("signoffs", []), list):
        raise ValueError("Operator review must contain a signoffs list.")
    for signoff in review.get("signoffs", []):
        _validate(validate_signoff_record(signoff), "signoff")
        _validate_reference(signoff, run, checkpoint_ids)
    handoff = review.get("handoff", {})
    if not isinstance(handoff, dict):
        raise ValueError("Operator review handoff must be an object.")
    if handoff:
        _validate(validate_handoff_record(handoff), "handoff")
        _validate_reference(handoff, run, checkpoint_ids)
    return result


def _validate_reference(record: dict[str, Any], run: dict[str, Any], checkpoint_ids: set[str]) -> None:
    if record["run_id"] != run["run_id"]:
        raise ValueError("Review record belongs to a different run.")
    checkpoint_id = record.get("checkpoint_id", "")
    if checkpoint_id and (not isinstance(checkpoint_id, str) or checkpoint_id not in checkpoint_ids):
        raise ValueError("Review record references an unknown checkpoint.")


def render_run_report(packet: dict[str, Any]) -> str:
    """Validate and render evidence, without callbacks, writes, or remote assets.

    The exporting application owns authorization and sensitive-value omission.
    A packet alone cannot establish identity, authenticity, or permission to share.
    """
    packet = _validated_packet(packet)
    run = packet["payload"]
    checkpoints = run["checkpoints"]
    review = packet.get("meta", {}).get("operator_review", {})
    sections = [
        '<p class="eyebrow">OPERATOR REVIEW</p><h1>Portable run report</h1>',
        '<p class="muted">Read-only exported evidence. Recorded identities and decisions are not independently verified. '
        'This report does not run or restore anything.</p>',
    ]
    if review.get("simulation"):
        sections.append(f'<p class="notice">{escape(_text(review["simulation"]))}</p>')
    sections += [
        "<h2>Run summary</h2>",
        _table(["Field", "Recorded value"], [
            ["Run", run["run_id"]], ["Status", run["status"]],
            ["Outcome", run.get("outcome")], ["Notes", run.get("notes")],
            ["Started", run["started_at"]], ["Ended", run.get("ended_at")],
            ["Starting profile", run.get("source_profile_id")],
            ["Exporter", packet.get("source_app")], ["Exported", packet["exported_at"]],
        ]),
        '<p class="muted">Run completion and checkpoint approval are separate records.</p>',
        "<h2>Settings</h2>",
        _table(["Control", "Initial", "Latest"], [
            [key, run["initial_controls"].get(key), run["latest_controls"].get(key)]
            for key in sorted(set(run["initial_controls"]) | set(run["latest_controls"]))
        ]),
    ]
    if len(checkpoints) >= 2:
        comparison = compare_checkpoints(checkpoints[0], checkpoints[-1], include_telemetry=True)
        telemetry = comparison["telemetry_comparison"]
        sections += [
            "<h2>First and latest checkpoint</h2>",
            _table(["Evidence", "First", "Latest"], [
                ["Checkpoint", checkpoints[0]["checkpoint_id"], checkpoints[-1]["checkpoint_id"]],
                ["Sample time", telemetry["left_sample_ts"], telemetry["right_sample_ts"]],
            ]),
            _table(["Metric", "First", "First unit", "Latest", "Latest unit", "Delta", "Comparison"], [
                [key, row["from"], row["from_unit"], row["to"], row["to_unit"], row["delta"], row["status"]]
                for key, row in telemetry["metrics"].items()
            ]),
            '<p class="muted">Delta is latest minus first. Missing values or incompatible units have no delta. '
            'Recorded samples are observations; their timing does not establish causation or freshness.</p>',
        ]
    sections.append("<h2>Checkpoints</h2>")
    if not checkpoints:
        sections.append('<p class="muted">None recorded.</p>')
    for number, checkpoint in enumerate(checkpoints, 1):
        sample = checkpoint.get("telemetry_slice", {})
        metrics = compare_checkpoints(
            checkpoint, checkpoint, include_telemetry=True,
        )["telemetry_comparison"]["metrics"]
        sections += [
            f'<h3>{number}. {escape(_text(checkpoint.get("label") or checkpoint["checkpoint_id"]))}</h3>',
            _table(["Field", "Recorded value"], [
                ["Checkpoint", checkpoint["checkpoint_id"]], ["Captured", checkpoint["ts"]],
                ["Reason", checkpoint.get("reason")], ["Approval", checkpoint["approval_state"]],
                ["Actor", checkpoint.get("actor")], ["Role", checkpoint.get("role")],
                ["Metric sample time", sample.get("ts")],
            ]),
            _table(["Control", "Value"], [[key, value] for key, value in sorted(checkpoint["controls"].items())]),
            _table(["Metric", "Value", "Unit"], [
                [key, value["from"], value["from_unit"]] for key, value in metrics.items()
            ]),
        ]
    sections += [
        "<h2>Human review</h2>",
        _table(["Checkpoint", "Decision", "Actor", "Role", "Time", "Reason"], [
            [s.get("checkpoint_id"), s["decision"], s.get("actor"), s.get("role"), s["ts"], s.get("reason")]
            for s in review.get("signoffs", [])
        ]),
        "<h2>Handoff</h2>",
    ]
    handoff = review.get("handoff", {})
    sections.append(_table(["Field", "Recorded value"], [
        ["Recipient", handoff.get("handoff_to")], ["Role", handoff.get("handoff_role")],
        ["Status", handoff.get("status")], ["Checkpoint", handoff.get("checkpoint_id")],
        ["Notes", handoff.get("notes")],
    ] if handoff else []))
    body = "\n".join(sections)
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Operator review report</title>
<style>
body{font:16px/1.55 system-ui,sans-serif;color:#172b3a;background:#f4f7fa;margin:0}
main{max-width:1050px;margin:32px auto;padding:36px;background:white;border-radius:12px}
h1{font-size:2.2rem;margin:.2em 0}h2{margin-top:2rem;border-bottom:2px solid #dce8ef;padding-bottom:.35rem}
h3{margin-top:1.6rem}.eyebrow{color:#116b69;font-weight:700;letter-spacing:.13em;font-size:.8rem}
.muted{color:#526776}.notice{background:#e8f5f2;border-left:4px solid #116b69;padding:14px}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{padding:10px 12px;border-bottom:1px solid #dee7ed;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#edf3f7;font-size:.9rem}td{white-space:pre-wrap}tr:nth-child(even){background:#fafcfd}
@media(max-width:650px){main{margin:0;padding:18px;border-radius:0}th,td{padding:8px}}
@media print{body{background:white}main{margin:0;padding:0}h2,h3{break-after:avoid}tr{break-inside:avoid}}
</style></head><body><main>''' + body + "</main></body></html>\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a run packet into a standalone read-only HTML report.")
    parser.add_argument("packet", type=Path)
    parser.add_argument("output", type=Path, help="New HTML file; existing files are never overwritten.")
    args = parser.parse_args()
    try:
        with args.packet.open("rb") as stream:
            raw = stream.read(MAX_PACKET_BYTES + 1)
        if len(raw) > MAX_PACKET_BYTES:
            raise ValueError("Run packet exceeds the 2 MiB report limit.")
        report = render_run_report(load_packet_json(raw.decode("utf-8")))
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(report)
    except (ValueError, OSError, RecursionError) as exc:
        parser.exit(2, f"Could not create report: {exc}\n")


if __name__ == "__main__":
    main()
