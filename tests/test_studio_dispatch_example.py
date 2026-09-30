"""Exercise real Streamlit widgets and server-side profile authorization guards."""
import json
from pathlib import Path

import pytest

pa = pytest.importorskip("pyarrow")
AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = Path(__file__).resolve().parents[1] / "examples" / "studio_dispatch" / "app.py"
CONTROL_WIDGETS = {
    'weekly_hours': 'number_input',
    'completion_percent': 'slider',
    'priority': 'selectbox',
    'project_name': 'text_input',
    'accept_new_work': 'toggle',
    'chart_color': 'color_picker',
}


@pytest.fixture
def app():
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    healthy(at)
    return at


def healthy(at):
    assert not at.exception, [e.message for e in at.exception]
    assert not at.error, [e.value for e in at.error]


def metrics(at):
    return {item.label: item.value for item in at.metric}


def field(at, key):
    # Toolkit deliberately changes rendered keys for disabled read-only mirrors.
    candidates = at.get(CONTROL_WIDGETS[key])
    return next(w for w in candidates if w.key in (key, '_radt_read_only_control__' + key))


def chart_elements(at):
    # Streamlit renamed the chart element; both carry the same Arrow datasets.
    return [*at.get('arrow_vega_lite_chart'), *at.get('vega_lite_chart')]


def chart(at):
    charts = chart_elements(at)
    assert len(charts) == 1
    proto = charts[0].proto
    rows = pa.ipc.open_stream(proto.datasets[0].data.data).read_all().to_pylist()
    return json.loads(proto.spec), rows


def force_profile_load(app, monkeypatch):
    import streamlit as st

    original = st.button

    def forged_button(*args, **kwargs):
        clicked = original(*args, **kwargs)
        return True if kwargs.get("key") == "_radt_profile_load" else clicked

    with monkeypatch.context() as patch:
        patch.setattr(st, "button", forged_button)
        app.run()
        healthy(app)


def save_profile(at, name):
    at.text_input(key='_radt_profile_name').input(name).run()
    at.button(key='_radt_profile_save').click().run()
    healthy(at)
    # Save must update the menu immediately, without an extra rerun.
    assert name in at.selectbox(key='_radt_profile_choice').options


def test_initial_fields_cards_metrics_and_hidden_panels(app):
    assert [m.value for m in app.markdown] == ['**Staffing**', '**Delivery**']
    assert set(CONTROL_WIDGETS) <= {w.key for k in CONTROL_WIDGETS.values() for w in app.get(k)}
    assert all(not field(app, key).disabled for key in CONTROL_WIDGETS)
    assert field(app, 'weekly_hours').min == 0
    assert field(app, 'weekly_hours').max == 400
    assert field(app, 'completion_percent').min == 0
    assert field(app, 'completion_percent').max == 100
    assert field(app, 'priority').options == ['Routine', 'Important', 'Urgent']
    assert metrics(app) == {'Weekly capacity': '120 h', 'Completed': '48 h', 'Remaining': '72 h'}
    titles = [x.value for k in ('header', 'subheader') for x in app.get(k)]
    assert 'Profiles' in titles
    assert not any('Audit' in t or 'Runbook' in t for t in titles)
    assert not app.expander
    spec, rows = chart(app)
    assert spec['encoding']['color']['value'] == '#5EEAD4'
    assert rows == [{'Stage': 'Completed', 'Hours': 48.0}, {'Stage': 'Remaining', 'Hours': 72.0}]


def test_all_control_edits_update_real_metrics_chart_and_labels(app):
    app.number_input(key='weekly_hours').set_value(80)
    app.slider(key='completion_percent').set_value(25)
    app.selectbox(key='priority').select('Urgent')
    app.text_input(key='project_name').input('Cobalt / Packaging')
    app.toggle(key='accept_new_work').set_value(False)
    app.color_picker(key='chart_color').set_value('#FBBF24')
    app.run()
    healthy(app)
    assert metrics(app) == {'Weekly capacity': '80 h', 'Completed': '20 h', 'Remaining': '60 h'}
    assert 'Cobalt / Packaging' in [x.value for x in app.subheader]
    assert 'Urgent priority | New work paused' in [x.value for x in app.caption]
    spec, rows = chart(app)
    assert spec['encoding']['color']['value'] == '#FBBF24'
    assert rows == [{'Stage': 'Completed', 'Hours': 20.0}, {'Stage': 'Remaining', 'Hours': 60.0}]


@pytest.mark.parametrize('hours,completion,expected', [
    (0, 100, ('0 h', '0 h', '0 h')),
    (400, 0, ('400 h', '0 h', '400 h')),
    (400, 100, ('400 h', '400 h', '0 h')),
])
def test_capacity_and_completion_boundaries(app, hours, completion, expected):
    app.number_input(key='weekly_hours').set_value(hours)
    app.slider(key='completion_percent').set_value(completion).run()
    healthy(app)
    assert tuple(metrics(app).values()) == expected


def test_workload_notes_navigation_preserves_values(app):
    app.number_input(key='weekly_hours').set_value(90).run()
    app.radio(key='studio_view').set_value('Notes').run()
    healthy(app)
    assert not chart_elements(app)
    assert 'Studio notes' in [x.value for x in app.subheader]
    assert any('Synthetic planning exercise' in x.value for x in app.info)
    app.radio(key='studio_view').set_value('Workload').run()
    healthy(app)
    assert len(chart_elements(app)) == 1
    assert metrics(app)['Weekly capacity'] == '90 h'


def test_named_profile_round_trip_restores_every_control(app):
    expected = {key: field(app, key).value for key in CONTROL_WIDGETS}
    save_profile(app, 'Monday baseline')
    app.number_input(key='weekly_hours').set_value(60)
    app.slider(key='completion_percent').set_value(75)
    app.selectbox(key='priority').select('Routine')
    app.text_input(key='project_name').input('Juniper / Launch')
    app.toggle(key='accept_new_work').set_value(False)
    app.color_picker(key='chart_color').set_value('#FB7185').run()
    save_profile(app, 'Friday revision')
    app.selectbox(key='_radt_profile_choice').select('Monday baseline').run()
    # Selecting previews only; no changes until Load is clicked.
    assert field(app, 'weekly_hours').value == 60
    app.button(key='_radt_profile_load').click().run()
    healthy(app)
    assert {key: field(app, key).value for key in CONTROL_WIDGETS} == expected
    assert metrics(app)['Completed'] == '48 h'
    app.selectbox(key='_radt_profile_choice').select('Friday revision').run()
    app.button(key='_radt_profile_load').click().run()
    healthy(app)
    assert field(app, 'weekly_hours').value == 60
    assert field(app, 'project_name').value == 'Juniper / Launch'
    assert metrics(app)['Completed'] == '45 h'


def test_viewer_is_read_only_and_cannot_load_profile(app, monkeypatch):
    save_profile(app, 'baseline')
    app.number_input(key='weekly_hours').set_value(90).run()
    app.selectbox(key='_radt_profile_choice').select('baseline').run()
    app.selectbox(key='_radt_role').select('Viewer').run()
    healthy(app)
    assert all(field(app, key).disabled for key in CONTROL_WIDGETS)
    assert all(app.button(key=key).disabled for key in ('_radt_profile_save', '_radt_profile_load', '_radt_profile_delete'))
    assert metrics(app)['Weekly capacity'] == '90 h'
    app.radio(key='studio_view').set_value('Notes').run()
    assert 'Studio notes' in [x.value for x in app.subheader]
    # Force the server result to exercise the guard on every Streamlit version.
    force_profile_load(app, monkeypatch)
    assert field(app, 'weekly_hours').value == 90
    app.selectbox(key='_radt_role').select('Admin').run()
    healthy(app)
    assert field(app, 'weekly_hours').value == 90
    assert all(not field(app, key).disabled for key in CONTROL_WIDGETS)


def test_freeze_preserves_controls_and_blocks_profile_restore(app, monkeypatch):
    save_profile(app, 'baseline')
    app.number_input(key='weekly_hours').set_value(70).run()
    app.selectbox(key='_radt_profile_choice').select('baseline').run()
    app.toggle(key='_radt_writable').set_value(False).run()
    healthy(app)
    assert all(field(app, key).disabled for key in CONTROL_WIDGETS)
    assert app.button(key='_radt_profile_load').disabled
    force_profile_load(app, monkeypatch)
    assert field(app, 'weekly_hours').value == 70
    app.toggle(key='_radt_writable').set_value(True).run()
    healthy(app)
    assert all(not field(app, key).disabled for key in CONTROL_WIDGETS)
    app.button(key='_radt_profile_load').click().run()
    healthy(app)
    assert field(app, 'weekly_hours').value == 120


def test_delete_updates_menu_immediately_and_preserves_studio_navigation(app):
    save_profile(app, 'temporary plan')
    app.number_input(key='weekly_hours').set_value(90).run()
    app.radio(key='studio_view').set_value('Notes').run()
    app.selectbox(key='_radt_profile_choice').select('temporary plan').run()
    app.button(key='_radt_profile_delete').click().run()
    healthy(app)
    assert 'temporary plan' not in app.selectbox(key='_radt_profile_choice').options
    assert app.selectbox(key='_radt_profile_choice').value == '(none)'
    assert app.number_input(key='weekly_hours').value == 90
    assert app.radio(key='studio_view').value == 'Notes'
    assert 'Studio notes' in [x.value for x in app.subheader]
    assert [x.value for x in app.get('toast')] == ['Deleted profile: temporary plan']
