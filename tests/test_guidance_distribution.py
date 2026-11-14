"""Prove offline guidance travels inside actual release artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

from role_aware_dashboard_toolkit import __version__


TOPICS = ("start", "controls", "web", "appearance", "sections", "plugins", "permissions",
          "authentication", "deployment", "workflows", "profiles", "runs", "telemetry", "api", "troubleshooting")
RESOURCE_FILES = {"role_aware_dashboard_toolkit/resources/guides/" + topic + ".md"
                  for topic in TOPICS} | {
    "role_aware_dashboard_toolkit/resources/starter/" + name
    for name in ("app.py", "config.toml", "AGENTS.md", "README.md")
}
RESOURCE_FILES |= {"role_aware_dashboard_toolkit/resources/web/" + name for name in ("components.js", "components.css", "tour.js", "presentation.js")}
RESOURCE_FILES |= {"role_aware_dashboard_toolkit/resources/web_starter/" + name for name in ("index.html", "gallery.js", "gallery.css", "README.md")}
RESOURCE_FILES |= {"role_aware_dashboard_toolkit/resources/web_host_starter/" + name for name in (
    "app.py", "manage.py", "README.md", "AGENTS.md", "gitignore", "host/__init__.py",
    "host/actions.py", "host/service.py", "host/auth.py", "host/storage.py",
    "static/index.html", "static/app.js", "static/app.css",
)}


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
for topic in ('start','controls','web','appearance','sections','plugins','permissions',
              'authentication','deployment','workflows','profiles','runs','telemetry','api','troubleshooting'):
    assert guidance.read_guide(topic)
assert guidance.read_starter()
from role_aware_dashboard_toolkit.web import WebTheme, WebPresentation, read_web_starter, read_web_host_starter
assert WebTheme().css()
assert set(read_web_starter()) == {"index.html", "gallery.js", "gallery.css", "README.md", "components.js", "components.css", "theme.css", "tour.js", "presentation.js", "web-config.js", "web-presentation.json"}
brand = WebPresentation(preset="studio", brand="Harbor & Co.")
assert WebPresentation.from_json(brand.to_json()) == brand
assert "Harbor & Co." in read_web_starter(brand)["web-config.js"]
host = read_web_host_starter(brand)
assert "Harbor & Co." in host["static/web-config.js"]
assert "from host.service import" in host["app.py"]
assert "examples." not in "\\n".join(text for name, text in host.items() if name.endswith(".py"))
assert 'fastapi' not in sys.modules
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
    assert json.loads(result.stdout) == {"version": __version__, "ok": True}
