from concurrent.futures import Future
from threading import Barrier, Event, Lock, Thread

import pytest

from role_aware_dashboard_toolkit import DashboardPlugin, PluginRegistry


def _start(callback):
    """Keep a failed deadlock regression from hanging the entire test process."""
    result = Future()

    def run():
        try:
            result.set_result(callback())
        except BaseException as exc:
            result.set_exception(exc)

    Thread(target=run, daemon=True).start()
    return result


def _observe_wait(monkeypatch, registry):
    """Arrange the race only after a competing caller actually starts waiting."""
    waiting = Event()
    original = registry._condition.wait

    def wait(timeout=None):
        waiting.set()
        return original(timeout)

    monkeypatch.setattr(registry._condition, "wait", wait)
    return waiting


@pytest.mark.parametrize("dispatch", ["initialize", "render_panels", "render_sidebar"])
def test_shared_registration_setup_finishes_once_before_concurrent_dispatch(monkeypatch, dispatch):
    registry = PluginRegistry()
    started, release, completed = Event(), Event(), Event()
    calls = []

    def setup(context):
        calls.append(("setup", context))
        started.set()
        assert release.wait(5)
        completed.set()

    def render(context):
        assert completed.is_set(), "a session rendered partially initialized state"
        calls.append(("render", context))

    registry.register(DashboardPlugin("shared", setup=setup, render_panel=render, render_sidebar=render))
    waiting = _observe_wait(monkeypatch, registry)
    first = _start(lambda: getattr(registry, dispatch)("first"))
    try:
        assert started.wait(3)
        second = _start(lambda: getattr(registry, dispatch)("second"))
        assert waiting.wait(3)
        assert calls == [("setup", "first")]
        assert not second.done()
    finally:
        release.set()
    assert first.result(3) == second.result(3) == []
    assert [call for call in calls if call[0] == "setup"] == [("setup", "first")]
    if dispatch != "initialize":
        assert sorted(context for stage, context in calls if stage == "render") == ["first", "second"]


def test_waiting_sessions_share_failed_attempt_and_a_later_call_retries(monkeypatch):
    registry = PluginRegistry()
    started, release = Event(), Event()
    setups, rendered = [], []

    def setup(context):
        setups.append(context)
        if len(setups) == 1:
            started.set()
            assert release.wait(5)
            raise ValueError("private setup failure")

    registry.register(DashboardPlugin("retry", setup=setup, render_panel=rendered.append))
    waiting = _observe_wait(monkeypatch, registry)
    first = _start(lambda: registry.render_panels("first"))
    try:
        assert started.wait(3)
        second = _start(lambda: registry.render_panels("second"))
        assert waiting.wait(3)
    finally:
        release.set()
    first_errors, second_errors = first.result(3), second.result(3)
    assert first_errors == second_errors
    assert [error.stage for error in first_errors] == ["setup"]
    assert "private" not in first_errors[0].message
    assert setups == ["first"]
    assert rendered == []
    assert registry.render_panels("retry") == []
    assert setups == ["first", "retry"]
    assert rendered == ["retry"]


def test_setup_control_flow_exit_wakes_waiters_without_initializing(monkeypatch):
    class StopRender(BaseException):
        pass

    registry = PluginRegistry()
    started, release = Event(), Event()
    setups, rendered = [], []

    def setup(context):
        setups.append(context)
        if len(setups) == 1:
            started.set()
            assert release.wait(5)
            raise StopRender()

    plugin = registry.register(DashboardPlugin("interrupted", setup=setup, render_panel=rendered.append))
    waiting = _observe_wait(monkeypatch, registry)
    first = _start(lambda: registry.render_panels("first"))
    try:
        assert started.wait(3)
        second = _start(lambda: registry.render_panels("second"))
        assert waiting.wait(3)
    finally:
        release.set()
    with pytest.raises(StopRender):
        first.result(3)
    assert second.result(3) == []
    assert not plugin._initialized
    assert registry.render_panels("skip", initialize_plugins=False) == []
    assert rendered == []
    assert registry.render_panels("retry") == []
    assert setups == ["first", "retry"]
    assert rendered == ["retry"]


@pytest.mark.parametrize("reuse_object", [False, True])
def test_replacement_during_setup_wakes_old_waiters_and_keeps_new_registration_independent(monkeypatch, reuse_object):
    registry = PluginRegistry()
    started, release = Event(), Event()
    calls = []

    def original_setup(context):
        calls.append(("original setup", context))
        started.set()
        assert release.wait(5)

    plugin = registry.register(DashboardPlugin(
        "replaceable", setup=original_setup,
        render_panel=lambda context: calls.append(("render", context)),
    ))
    waiting = _observe_wait(monkeypatch, registry)
    first = _start(lambda: registry.render_panels("old owner"))
    try:
        assert started.wait(3)
        second = _start(lambda: registry.render_panels("old waiter"))
        assert waiting.wait(3)
        assert registry.unregister("replaceable") is plugin
        replacement = plugin if reuse_object else DashboardPlugin(
            "replaceable", render_panel=lambda context: calls.append(("render", context)),
        )
        replacement.setup = lambda context: calls.append(("replacement setup", context))
        registry.register(replacement)
        # Removal releases old waiters even while the old setup is still blocked.
        assert second.result(3) == []
        assert registry.render_panels("new owner") == []
    finally:
        release.set()
    assert first.result(3) == []
    assert calls == [
        ("original setup", "old owner"),
        ("replacement setup", "new owner"),
        ("render", "new owner"),
    ]
    assert registry.initialize("later") == []
    assert len(calls) == 3


def test_setup_runs_without_holding_registry_lock():
    registry = PluginRegistry()
    started, release = Event(), Event()

    def setup(_context):
        started.set()
        assert release.wait(5)

    registry.register(DashboardPlugin("blocked", setup=setup))
    first = _start(lambda: registry.initialize({}))
    try:
        assert started.wait(3)

        def mutate():
            plugin = registry.register(DashboardPlugin("independent"))
            assert [item["name"] for item in registry.describe()] == ["blocked", "independent"]
            assert registry.unregister("independent") is plugin

        assert _start(mutate).result(3) is None
    finally:
        release.set()
    assert first.result(3) == []


def test_setup_may_reenter_registry_without_recursive_setup_or_early_render():
    registry = PluginRegistry()
    calls = []

    def setup(_context):
        calls.append("setup")
        assert registry.initialize("nested") == []
        assert registry.render_panels("nested") == []
        calls.append("setup complete")

    registry.register(DashboardPlugin("reentrant", setup=setup, render_panel=calls.append))
    assert _start(lambda: registry.render_panels("outer render")).result(3) == []
    assert calls == ["setup", "setup complete", "outer render"]


def test_reciprocal_setup_calls_across_threads_and_registries_do_not_deadlock():
    first, second = PluginRegistry(), PluginRegistry()
    ready = Barrier(2)
    calls = []

    def setup(name, other):
        calls.append(name)
        ready.wait(3)
        assert other.initialize("nested") == []

    first.register(DashboardPlugin("first", setup=lambda _: setup("first", second)))
    second.register(DashboardPlugin("second", setup=lambda _: setup("second", first)))
    results = [_start(lambda: first.initialize("outer")), _start(lambda: second.initialize("outer"))]
    assert [result.result(4) for result in results] == [[], []]
    assert sorted(calls) == ["first", "second"]
    assert first.initialize("later") == second.initialize("later") == []
    assert len(calls) == 2


def test_same_plugin_object_has_independent_concurrent_setup_in_each_registry():
    first, second = PluginRegistry(), PluginRegistry()
    ready = Barrier(2)
    calls = []

    def setup(context):
        calls.append(context)
        ready.wait(3)

    plugin = DashboardPlugin("shared", setup=setup)
    first.register(plugin)
    second.register(plugin)
    results = [_start(lambda: first.initialize("first")), _start(lambda: second.initialize("second"))]
    assert [result.result(4) for result in results] == [[], []]
    assert sorted(calls) == ["first", "second"]
    assert first.initialize("later") == second.initialize("later") == []
    assert len(calls) == 2


def test_old_dispatch_snapshot_cannot_initialize_same_object_reregistered_by_a_callback():
    registry = PluginRegistry()
    calls = []
    victim = DashboardPlugin(
        "z-victim", setup=lambda _: calls.append("setup"),
        render_panel=lambda _: calls.append("render"),
    )

    def replace(_context):
        registry.unregister(victim.name)
        registry.register(victim)

    mutator = registry.register(DashboardPlugin("a-mutator", render_panel=replace))
    registry.register(victim)
    assert registry.initialize({}) == []
    calls.clear()
    assert registry.render_panels({}) == []
    assert calls == []
    registry.unregister(mutator.name)
    assert registry.render_panels({}) == []
    assert calls == ["setup", "render"]


def test_simultaneous_registration_keeps_one_winner_and_its_metadata():
    registry = PluginRegistry()
    ready = Barrier(2)
    winners, rejected = [], []
    lock = Lock()

    def register(description):
        plugin = DashboardPlugin("shared-name", description=description)
        ready.wait(3)
        try:
            registry.register(plugin)
        except KeyError:
            with lock:
                rejected.append(plugin)
        else:
            with lock:
                winners.append(plugin)

    results = [_start(lambda: register("first")), _start(lambda: register("second"))]
    assert [result.result(4) for result in results] == [None, None]
    assert len(winners) == len(rejected) == 1
    assert registry.all() == winners
    assert registry.describe()[0]["description"] == winners[0].description
