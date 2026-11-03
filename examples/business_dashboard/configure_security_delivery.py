"""Inspect or explicitly activate one remote security-event destination offline."""

import argparse
import json
import sqlite3
import sys

from business.db import Database
from business.event_destinations import (
    DestinationDescriptor, destination_status, enable_remote_destination, source_identity,
)


def status(database):
    with database.readonly_snapshot() as connection:
        return {
            "source": source_identity(connection),
            "destinations": [
                destination_status(connection, row[0])
                for row in connection.execute("SELECT destination_id FROM security_destinations ORDER BY enabled_at,destination_id")
            ],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "enable"))
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--mfa-key-file")
    parser.add_argument("--collector-id")
    parser.add_argument("--destination-id")
    parser.add_argument("--endpoint")
    parser.add_argument("--config-file", help="Private JSON configuration; credentials are read only from its private token file")
    parser.add_argument("--maintenance-confirmed", action="store_true",
                        help="Assert ingress and writers are stopped. The command cannot establish this for you.")
    options = parser.parse_args(argv)
    parameters = (options.collector_id, options.destination_id, options.endpoint, options.config_file)
    if options.command == "enable" and (not options.maintenance_confirmed or not all(parameters)):
        parser.error("enable requires --maintenance-confirmed, --collector-id, --destination-id, --endpoint and --config-file")
    if options.command == "status" and (any(parameters) or options.maintenance_confirmed):
        parser.error("status is read-only and does not accept activation parameters")
    try:
        database = Database(options.data_dir, mfa_key_file=options.mfa_key_file)
        if options.command == "status":
            result = status(database)
        else:
            from business.event_config import load_delivery_configuration

            descriptor = DestinationDescriptor(options.destination_id, options.collector_id, options.endpoint)
            with database.readonly_snapshot() as connection:
                identity = source_identity(connection)["source_id"]
            load_delivery_configuration(options.config_file, source_id=identity, descriptor=descriptor)
            with database.transaction() as connection:
                if source_identity(connection)["source_id"] != identity:
                    raise ValueError("Source identity changed during activation.")
                result = enable_remote_destination(connection, descriptor)
            result["scope"] = "all_retained_events_queued"
            result["delivery_verified"] = False
    except (OSError, ValueError, sqlite3.Error):
        print("Security destination operation refused; preserve storage and inspect protected configuration.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
