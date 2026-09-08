import json
from pathlib import Path

import pytest

import role_aware_dashboard_toolkit as radt
import role_aware_dashboard_toolkit.team_ops as team_ops
import role_aware_dashboard_toolkit.team_store as team_store
import role_aware_dashboard_toolkit.store_diagnostics as store_diagnostics
from role_aware_dashboard_toolkit.validators import validate_assignment_record, validate_comment_record, validate_handoff_record, validate_signoff_record
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError, hashed_store_filename


def test_team_records_validate_and_summarize():
    run = radt.build_run({"temperature": 0.7, "mode": "safe"}, run_id="run_team", role="Operator")
    run = radt.append_checkpoint(run, {"temperature": 0.9, "mode": "safe"}, label="cp1", approval_state="approved")

    comment = team_ops.build_team_comment(
        "Need approver review before rollout.",
        run_id=run["run_id"],
        checkpoint_id=run["last_checkpoint_id"],
        actor="mike",
        role="Operator",
        tags=["rollout", "review", "review"],
    )
    assignment = team_ops.build_review_assignment(
        run["run_id"],
        checkpoint_id=run["last_checkpoint_id"],
        title="Approve rollout",
        assignee="jane",
        assignee_role="Approver",
        assigned_by="mike",
        assigned_role="Operator",
    )
    signoff = team_ops.build_signoff_record(
        run["run_id"],
        "approved",
        checkpoint_id=run["last_checkpoint_id"],
        assignment_id=assignment["assignment_id"],
        actor="jane",
        role="Approver",
        reason="Looks stable.",
    )
    handoff = team_ops.build_handoff_summary(
        run,
        handoff_to="night-shift",
        handoff_role="Auditor",
        actor="mike",
        role="Operator",
        comments=[comment],
        assignments=[assignment],
        signoffs=[signoff],
        notes="Watch the first deployment window.",
    )

    assert validate_comment_record(comment)["ok"] is True
    assert validate_assignment_record(assignment)["ok"] is True
    assert validate_signoff_record(signoff)["ok"] is True
    assert validate_handoff_record(handoff)["ok"] is True

    summary = team_ops.summarize_team_ops([assignment], [comment], [signoff])
    assert summary["open_assignments"] == 1
    assert summary["latest_signoff_decision"] == "approved"
    assert handoff["summary"]["latest_controls"]["temperature"] == 0.9


def test_inmemory_team_store_round_trip_filters_by_run_and_checkpoint():
    store = team_store.InMemoryTeamStore()
    comment_a = team_ops.build_team_comment("A", run_id="run_a", checkpoint_id="cp_a")
    comment_b = team_ops.build_team_comment("B", run_id="run_b", checkpoint_id="cp_b")
    store.save_comment(comment_a)
    store.save_comment(comment_b)

    assignment = team_ops.build_review_assignment("run_a", checkpoint_id="cp_a", assignee="alex")
    signoff = team_ops.build_signoff_record("run_a", "acknowledged", checkpoint_id="cp_a", actor="alex", role="Approver")
    handoff = team_ops.build_handoff_summary({"run_id": "run_a", "latest_controls": {"mode": "safe"}, "checkpoints": [], "status": "active"}, comments=[comment_a], assignments=[assignment], signoffs=[signoff])
    store.save_assignment(assignment)
    store.save_signoff(signoff)
    store.save_handoff(handoff)

    assert len(store.list_comments("run_a")) == 1
    assert store.list_comments("run_a", "cp_a")[0]["body"] == "A"
    assert store.list_assignments("run_a")[0]["assignee"] == "alex"
    assert store.list_signoffs("run_a")[0]["decision"] == "acknowledged"
    assert store.list_handoffs("run_a")[0]["summary"]["comment_count"] == 1


def test_role_partitions_cover_team_ops_without_control_mutation():
    approver = radt.get_role("Approver")
    auditor = radt.get_role("Auditor")
    viewer = radt.get_role("Viewer")

    assert approver is not None and approver.perms["can_signoff_runs"] is True
    assert approver.perms["can_edit_controls"] is False
    assert auditor is not None and auditor.perms["can_view_team_ops"] is True
    assert auditor.perms["can_signoff_runs"] is False
    assert viewer is not None and viewer.perms["can_comment_runs"] is False


def test_file_team_store_uses_hashed_writes_lists_manual_records_and_rejects_symlinks(tmp_path):
    store_dir = tmp_path / "team_ops"
    store = team_store.FileTeamStore(str(store_dir))
    left = team_ops.build_team_comment("left", run_id="run_a", comment_id="comment/a")
    right = team_ops.build_team_comment("right", run_id="run_a", comment_id="comment:a")

    left_path = Path(store.save_comment(left))
    right_path = Path(store.save_comment(right))

    assert left_path != right_path
    assert left_path.name.startswith("commenta-")
    assert right_path.name.startswith("commenta-")
    comment_ids = {item["comment_id"] for item in store.list_comments("run_a")}
    assert {"comment/a", "comment:a"}.issubset(comment_ids)

    legacy_id = "legacy/comment"
    legacy_path = store_dir / "comments" / "legacycomment.json"
    legacy_path.write_text(json.dumps({"comment_id": legacy_id, "run_id": "run_a", "body": "legacy"}), encoding="utf-8")
    comment_ids = {item["comment_id"] for item in store.list_comments("run_a")}
    assert legacy_id in comment_ids

    outside = tmp_path / "outside_comment.json"
    outside.write_text(json.dumps({"comment_id": "escape/comment", "run_id": "run_a", "body": "escape"}), encoding="utf-8")
    link = store_dir / "comments" / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")
    store.clear_read_errors()

    comment_ids = {item["comment_id"] for item in store.list_comments("run_a")}
    assert "escape/comment" not in comment_ids
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_file_team_store_preserves_rows_before_directory_enumeration_error(tmp_path, monkeypatch):
    store_dir = tmp_path / "team_ops"
    store = team_store.FileTeamStore(str(store_dir))
    hidden = team_ops.build_team_comment("hidden", run_id="run_a", comment_id="hidden")
    visible = team_ops.build_team_comment("visible", run_id="run_a", comment_id="visible")
    store.save_comment(hidden)
    visible_path = Path(store.save_comment(visible))
    comments_dir = visible_path.parent
    original_scandir = store_diagnostics.os.scandir

    class PartialScandir:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def __iter__(self):
            yield comments_dir / "ignored.txt"
            yield visible_path
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\record.json",
                str(comments_dir),
            )

    def partial_scandir(path):
        if Path(path) == comments_dir:
            return PartialScandir()
        return original_scandir(path)

    with monkeypatch.context() as scoped:
        scoped.setattr(store_diagnostics.os, "scandir", partial_scandir)
        rows = store.list_comments("run_a")

    assert [row["comment_id"] for row in rows] == ["visible"]
    assert store.read_errors == [
        {
            "path": "comments",
            "error_type": "PermissionError",
            "exception_type": "PermissionError",
            "message": "PermissionError: JSON store directory enumeration failed (errno 13)",
        }
    ]
    assert str(comments_dir) not in store.read_errors[0]["message"]
    assert "private-server" not in store.read_errors[0]["message"]


def test_file_team_store_records_collection_preflight_error(tmp_path):
    store = team_store.FileTeamStore(chr(0))
    assert store.list_comments("run_a") == []
    assert store.read_errors == [
        {
            "path": "comments",
            "error_type": "ValueError",
            "exception_type": "ValueError",
            "message": "ValueError: JSON store directory enumeration failed",
        }
    ]


def test_file_team_store_handles_collection_root_symlinks(tmp_path):
    file_target = tmp_path / "not-a-directory"
    file_target.write_text("not a store", encoding="utf-8")
    file_link = tmp_path / "file-link"
    try:
        file_link.symlink_to(file_target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    file_store = team_store.FileTeamStore(str(file_link))
    assert file_store.list_comments("run_a") == []
    assert file_store.read_errors == []

    loop_store = tmp_path / "loop-store"
    try:
        loop_store.symlink_to(loop_store, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is not available in this environment")

    store = team_store.FileTeamStore(str(loop_store))
    assert store.list_comments("run_a") == []
    assert len(store.read_errors) == 1

    error = store.read_errors[0]
    assert error["path"] == "comments"
    assert error["error_type"] == error["exception_type"]
    assert error["message"].startswith(
        f'{error["error_type"]}: JSON store directory enumeration failed'
    )
    assert str(tmp_path) not in "\n".join(error.values())


def test_file_team_store_save_rejects_symlink_target(tmp_path):
    store_dir = tmp_path / "team_ops"
    store = team_store.FileTeamStore(str(store_dir))
    record = team_ops.build_team_comment("body", run_id="run_a", comment_id="blocked")

    target_path = store_dir / "comments" / f"{hashed_store_filename('blocked')}.json"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside_comment.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        target_path.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    with pytest.raises(StorePathSecurityError):
        store.save_comment(record)


def test_file_team_store_rejects_symlinked_collection_dir(tmp_path):
    store_dir = tmp_path / "team_ops"
    store = team_store.FileTeamStore(str(store_dir))
    outside = tmp_path / "outside_comments"
    outside.mkdir()
    comments_dir = store_dir / "comments"
    comments_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        comments_dir.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    record = team_ops.build_team_comment("body", run_id="run_a", comment_id="blocked")
    with pytest.raises(StorePathSecurityError):
        store.save_comment(record)

    assert store.list_comments("run_a") == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_inmemory_team_store_returns_json_roundtrip_copies():
    store = team_store.InMemoryTeamStore()
    source = team_ops.build_team_comment("original", run_id="run_a", checkpoint_id="cp_a")
    store.save_comment(source)
    source["body"] = "mutated-after-save"

    loaded_once = store.list_comments("run_a")
    assert loaded_once[0]["body"] == "original"
    loaded_once[0]["body"] = "mutated-after-load"

    loaded_twice = store.list_comments("run_a")
    assert loaded_twice[0]["body"] == "original"
