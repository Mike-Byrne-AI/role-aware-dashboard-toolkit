"""Exercise the public onboarding example through real Streamlit reruns."""
from pathlib import Path
import re

import pytest
from tests.demo_role_helpers import start_as_admin


ROOT = Path(__file__).resolve().parents[1]


def test_readme_dashboard_retains_audit_history_per_browser_session():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Minimal dashboard", 1)[1]
    match = re.search(r"```python\n(.*?)\n```", section, re.DOTALL)
    assert match is not None
    # Capture the object created by the actual documented snippet, without
    # substituting a test-only resource lifetime or renderer.
    source = match.group(1) + '\nst.session_state["_example_config"] = config\n'
    app = start_as_admin(AppTest.from_string(source)).run()
    assert not app.exception
    audit = app.session_state["_example_config"].audit

    for value in (40, 50):
        app.slider(key="request_timeout_seconds").set_value(value).run()
        assert not app.exception
        assert app.session_state["_example_config"].audit is audit

    changes = [event for event in audit.all_events()
               if event["type"] == "control_change"]
    assert [(event["old"], event["new"]) for event in changes] == [(30, 40), (40, 50)]
    history = audit.all_events()
    app.run()
    assert not app.exception
    assert app.session_state["_example_config"].audit is audit
    assert audit.all_events() == history

    other_session = start_as_admin(AppTest.from_string(source)).run()
    assert not other_session.exception
    other_audit = other_session.session_state["_example_config"].audit
    assert other_audit is not audit
    assert not other_audit.all_events()
