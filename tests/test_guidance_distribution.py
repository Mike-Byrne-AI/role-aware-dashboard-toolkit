"""Prove offline guidance travels inside actual release artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile


TOPICS = ("start", "controls", "appearance", "sections", "plugins", "permissions",
          "profiles", "runs", "telemetry", "api", "troubleshooting")
RESOURCE_FILES = {"role_aware_dashboard_toolkit/resources/guides/" + topic + ".md"
                  for topic in TOPICS} | {
    "role_aware_dashboard_toolkit/resources/starter/" + name
    for name in ("app.py", "config.toml", "AGENTS.md", "README.md")
}


def test_both_artifacts_include_exact_guidance_resource_bytes(built_release_artifacts):
    root = Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(built_release_artifacts["wheel"]) as wheel:
        for name in RESOURCE_FILES:
            assert wheel.read(name) == (root / name).read_bytes()
    with tarfile.open(built_release_artifacts["sdist"]) as sdist:
        files = {member.name.split("/", 1)[1]: member
                 for member in sdist.getmembers() if member.isfile() and "/" in member.name}
        for name in RESOURCE_FILES:
            with sdist.extractfile(files[name]) as stream:
                assert stream.read() == (root / name).read_bytes()


def test_core_only_zip_wheel_reads_guide_without_checkout(built_release_artifacts, tmp_path):
    wheel = str(built_release_artifacts["wheel"].resolve())
    code = """
import contextlib, io, json, sys
sys.path.insert(0, sys.argv[1])
captured = io.StringIO()
with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit import guidance
assert captured.getvalue() == ''
assert sys.argv[1] in radt.__file__
assert 'streamlit' not in sys.modules
assert 'fastapi' not in sys.modules
for topic in ('start','controls','appearance','sections','plugins','permissions',
              'profiles','runs','telemetry','api','troubleshooting'):
    assert guidance.read_guide(topic)
assert guidance.read_starter()
report = guidance.inspect_capabilities()
assert report
assert 'streamlit' not in sys.modules
print(json.dumps({'version': radt.__version__, 'ok': True}))
"""
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code, wheel],
                            cwd=tmp_path, env=env, capture_output=True, text=True,
                            encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"version": "0.1.0", "ok": True}
