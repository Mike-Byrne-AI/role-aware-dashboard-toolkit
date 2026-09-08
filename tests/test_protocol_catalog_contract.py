from role_aware_dashboard_toolkit.packet_core import VALID_PACKET_TYPES
from role_aware_dashboard_toolkit.protocol.catalog import (
    ALLOWLISTED_UNCATALOGED_PACKET_TYPES,
    PROTOCOL_CATALOG,
    RECORD_SCHEMA_VERSIONS,
    get_protocol_entry,
    get_protocol_schema_version,
    list_protocol_entries,
    list_uncataloged_packet_types,
)


def test_protocol_catalog_covers_every_builtin_packet_type():
    assert set(VALID_PACKET_TYPES) <= set(PROTOCOL_CATALOG)
    assert list_uncataloged_packet_types() == []
    assert ALLOWLISTED_UNCATALOGED_PACKET_TYPES == ()


def test_protocol_catalog_contains_only_generic_oss_records():
    rendered = repr(PROTOCOL_CATALOG).lower()
    for forbidden in (
        "repoos",
        "codex_builder",
        "harness",
        "federation",
        "semantic",
        "pack_",
    ):
        assert forbidden not in rendered


def test_protocol_catalog_accessors_return_defensive_values():
    run = get_protocol_entry("run")
    assert run["schema_version"] == RECORD_SCHEMA_VERSIONS["run"]
    assert get_protocol_schema_version("run") == run["schema_version"]
    assert get_protocol_schema_version("missing") is None
    run["builder"] = "changed"
    assert get_protocol_entry("run")["builder"] != "changed"
    assert {entry["name"] for entry in list_protocol_entries()} == set(PROTOCOL_CATALOG)
