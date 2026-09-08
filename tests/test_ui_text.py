import json
import os

from role_aware_dashboard_toolkit.ui_json import redact_ui_json_payload, with_redacted_json
from role_aware_dashboard_toolkit.ui_text import sanitize_caption_text


def test_sanitize_caption_text_redacts_path_like_values_before_escaping():
    text = r'<Repo "C:\private\Dash Forge\session.json">'

    assert sanitize_caption_text(text) == "&lt;Repo &quot;&lt;redacted-local-path&gt;&quot;&gt;"


def test_sanitize_caption_text_preserves_markup_closing_slashes_while_escaping():
    text = '<script>alert("x")</script>'

    assert sanitize_caption_text(text) == "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"


def test_sanitize_caption_text_preserves_repo_relative_path_context():
    repo_root = r"C:\private\Dash Forge"
    text = rf'<Session "{repo_root}\.role_aware_dashboard_toolkit\session.json">'

    assert sanitize_caption_text(text, repo_root=repo_root) == "&lt;Session &quot;.role_aware_dashboard_toolkit/session.json&quot;&gt;"


def test_redact_ui_json_payload_redacts_tuple_nested_in_mapping():
    payload = {"paths": (r"C:\private\session.json",)}

    redacted = redact_ui_json_payload(payload)

    assert redacted == {"paths": ["<redacted-local-path>"]}


def test_redact_ui_json_payload_sanitizes_non_finite_numbers():
    redacted = redact_ui_json_payload(
        {
            "finite": 1.25,
            "nan": float("nan"),
            "nested": [float("inf"), float("-inf")],
        }
    )

    assert redacted == {
        "finite": 1.25,
        "nan": None,
        "nested": [None, None],
    }
    json.dumps(redacted, allow_nan=False)


def test_redact_ui_json_payload_normalizes_top_level_and_nested_paths(tmp_path):
    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    outside = tmp_path / "outside" / "secret.json"

    assert redact_ui_json_payload(inside, repo_root=repo_root) == "reports/inside.json"

    payload = {
        inside: "path-key",
        "values": ({outside}, (inside,)),
    }
    redacted = redact_ui_json_payload(payload, repo_root=repo_root)

    assert redacted == {
        "reports/inside.json": "path-key",
        "values": [
            ["<redacted-local-path>"],
            ["reports/inside.json"],
        ],
    }


def test_redact_ui_json_payload_redacts_local_paths_inside_urls():
    payload = {
        "safe": "https://example.test/assets/app.js?mode=preview#section",
        "query": "https://example.test/view?path=C%3A%5CPrivate%5Csecret.json",
        "fragment": "https://example.test/view#%2Fhome%2Falice%2Fsecret.json",
        "file": "file:///C:/Private/secret.json",
    }

    assert redact_ui_json_payload(payload) == {
        "safe": payload["safe"],
        "query": "https://example.test/view?path=<redacted-local-path>",
        "fragment": "https://example.test/view#<redacted-local-path>",
        "file": "<redacted-local-path>",
    }


def test_redact_ui_json_payload_normalizes_top_level_set_before_ordering(tmp_path):
    class HostileReprPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return str(self.value)

        def __repr__(self):
            raise RuntimeError(f"repr leaked {self.value}")

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"

    redacted = redact_ui_json_payload(
        {HostileReprPath(inside)},
        repo_root=repo_root,
    )

    assert redacted == ["reports/inside.json"]


def test_redact_ui_json_payload_normalizes_hybrid_string_pathlike(tmp_path):
    class HybridPath(str, os.PathLike):
        def __fspath__(self):
            return str.__str__(self)

        def __str__(self):
            raise AssertionError("hybrid PathLike must use __fspath__")

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"

    assert redact_ui_json_payload(
        HybridPath(inside),
        repo_root=repo_root,
    ) == "reports/inside.json"


def test_redact_ui_json_payload_reads_list_repo_root_once(tmp_path):
    class OneShotPath(os.PathLike):
        def __init__(self, value):
            self.value = value
            self.calls = 0

        def __fspath__(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError(f"path read twice: {self.value}")
            return str(self.value)

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    one_shot_root = OneShotPath(repo_root)
    one_shot_inside = OneShotPath(inside)

    redacted = redact_ui_json_payload(
        [one_shot_inside, one_shot_inside],
        repo_root=one_shot_root,
    )

    assert one_shot_root.calls == 1
    assert one_shot_inside.calls == 1
    assert redacted == [
        "reports/inside.json",
        "reports/inside.json",
    ]


def test_redacted_json_wrapper_accepts_falsey_pathlike_repo_root(tmp_path):
    class FalseyPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return str(self.value)

        def __bool__(self):
            raise AssertionError("PathLike repo roots must not use truthiness")

        def __str__(self):
            raise AssertionError("PathLike repo roots must use __fspath__")

    class FakeStreamlit:
        def __init__(self):
            self.payload = None

        def json(self, payload):
            self.payload = payload

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    streamlit = FakeStreamlit()

    wrapped = with_redacted_json(
        streamlit,
        repo_root=FalseyPath(repo_root),
    )
    wrapped.json({"path": inside})

    assert streamlit.payload == {"path": "reports/inside.json"}
