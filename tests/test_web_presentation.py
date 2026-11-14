"""Installed resources, theme boundaries and standalone web generation."""
import json

import pytest

from role_aware_dashboard_toolkit.cli import main
from role_aware_dashboard_toolkit.web import WebPresentation, WebTheme, read_web_asset, read_web_starter


@pytest.mark.parametrize("color", ["red", "#fff", "#123456;}", "</style>", None, 1])
def test_theme_rejects_css_injection_and_non_colors(color):
    with pytest.raises(ValueError):
        WebTheme(accent=color)


def test_theme_can_be_shared_without_optional_hosts():
    theme = WebTheme(accent="#315C83")
    assert "--radt-accent: #315C83;" in theme.css()
    assert '#315C83' in theme.streamlit_toml()
    assert "window.RADTWeb" in read_web_asset("components.js")
    for value in ("../web.py", "theme.css", "index.html"):
        with pytest.raises(ValueError):
            read_web_asset(value)


def test_web_init_is_complete_and_never_overwrites(tmp_path, capsys):
    destination = tmp_path / "studio"
    assert main(["init", str(destination), "--web", "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["auth_mode"] == "presentation-only"
    assert "http.server" in result["run_command"]
    for name, text in read_web_starter().items():
        assert (destination / name).read_text(encoding="utf-8") == text
    (destination / "index.html").write_text("Consumer edits", encoding="utf-8")
    assert main(["init", str(destination), "--web"]) != 0
    assert (destination / "index.html").read_text() == "Consumer edits"


def test_web_auth_are_mutually_exclusive(tmp_path, capsys):
    destination = tmp_path / "studio"
    assert main(["init", str(destination), "--web", "--auth"]) != 0
    assert not destination.exists()


def test_config_roundtrip_generates_repeatable_plain_text_brand():
    config = WebPresentation(preset="studio", brand="Harbor & Co. <script>example</script>",
                             headline="A clearer day for your team.")
    assert WebPresentation.from_json(config.to_json()) == config
    first = read_web_starter(config)
    assert first == read_web_starter(WebPresentation.from_json(first["web-presentation.json"]))
    assert "</script>" not in first["web-config.js"]
    assert "\\u003c" in first["web-config.js"]
    assert "tour.js" in first and "presentation.js" in first
    assert first["theme.css"] == config.theme.css()


@pytest.mark.parametrize("text", [
    "{}", "[]", '{"schema_version":true}', '{"schema_version":2}',
    '{"schema_version":1,"preset":"unknown"}', '{"schema_version":1,"preset":[]}',
    '{"schema_version":1,"brand":""}', '{"schema_version":1,"brand":"\\n"}',
    '{"schema_version":1,"brand":55}', '{"schema_version":1,"extra":"ignored?"}',
    '{"schema_version":1,"schema_version":1}',
    '{"schema_version":1,"theme":{"accent":"red"}}',
    '{"schema_version":1,"theme":null}', pytest.param("{" * 65537, id="oversized"),
    pytest.param("[" * 1500 + "]" * 1500, id="deeply-nested"),
])
def test_config_rejects_ambiguous_or_unsupported_input(text):
    with pytest.raises(ValueError):
        WebPresentation.from_json(text)


def test_config_checks_declared_color_pairs_without_changing_web_theme_contract():
    theme = WebTheme(ink="#FFFFFF")
    assert theme.css()
    with pytest.raises(ValueError, match="contrast"):
        WebPresentation(theme=theme)
    for preset in ("field", "studio"):
        assert WebPresentation(preset=preset).theme


def test_web_config_cli_validates_before_creating_and_preserves_existing_output(tmp_path, capsys):
    source = tmp_path / "presentation.json"
    config = WebPresentation(preset="studio", brand="Harbor & Co.")
    source.write_text(config.to_json(), encoding="utf-8")
    destination = tmp_path / "client"
    command = ["init", str(destination), "--web", "--web-config", str(source), "--format", "json"]
    assert main([*command, "--dry-run"]) == 0
    assert not destination.exists()
    capsys.readouterr()
    assert main(command) == 0
    assert (destination / "web-presentation.json").read_text() == config.to_json()
    capsys.readouterr()
    assert main(command) != 0
    assert (destination / "web-presentation.json").read_text() == config.to_json()
    source.write_text('{"schema_version":1,"brand":""}', encoding="utf-8")
    rejected = tmp_path / "rejected"
    assert main(["init", str(rejected), "--web", "--web-config", str(source)]) != 0
    assert not rejected.exists()
    assert main(["init", str(rejected), "--web-config", str(source)]) != 0
    assert not rejected.exists()
