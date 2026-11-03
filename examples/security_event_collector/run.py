"""Explicit provisioning and HTTPS serving of the independent local reference."""

import argparse
import sqlite3
import sys

from collector.custody import create_backup, restore_quarantined
from collector.private_files import check_private_file
from collector.storage import provision


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("provision")
    setup.add_argument("directory")
    setup.add_argument("--kind", choices=("collector", "inbox"), required=True)
    setup.add_argument("--source-id", required=True)
    setup.add_argument("--destination-id", required=True)
    setup.add_argument("--service-id")
    setup.add_argument("--peer-id")
    setup.add_argument("--inbox-id")
    setup.add_argument("--alert-destination-id")
    setup.add_argument("--inbox-endpoint")
    serve = commands.add_parser("serve")
    serve.add_argument("directory")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--tls-cert", required=True)
    serve.add_argument("--tls-key", required=True)
    serve.add_argument("--inbox-token-file")
    serve.add_argument("--inbox-ca-file")
    configure = commands.add_parser("configure-alerts")
    configure.add_argument("directory")
    configure.add_argument("--inbox-endpoint", required=True)
    for operation in ("backup", "restore-quarantined"):
        command = commands.add_parser(operation)
        command.add_argument("directory")
        command.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "provision":
            provision(args.directory, kind=args.kind, source_id=args.source_id, destination_id=args.destination_id,
                      service_id=args.service_id, peer_id=args.peer_id, inbox_id=args.inbox_id, alert_destination_id=args.alert_destination_id,
                      alert_endpoint=args.inbox_endpoint)
            print("Provisioned private storage. Deliver ingest.token privately to its writer; retain operator.token separately.")
        elif args.command == "backup":
            create_backup(args.directory, args.output)
            print("Private collector snapshot created. Encrypt it and retain independent custody.")
        elif args.command == "restore-quarantined":
            restore_quarantined(args.directory, args.output)
            print("Restored in quarantine. Accepted-ledger continuity is unverified; serving remains disabled.")
        elif args.command == "configure-alerts":
            from collector.storage import Store
            Store(args.directory).configure_alert_endpoint(args.inbox_endpoint)
            print("Fixed notification endpoint recorded. Supply its separate private token and CA files when serving.")
        else:
            if not 1 <= args.port <= 65535:
                raise ValueError("Invalid port.")
            from collector.app import create_app
            import uvicorn
            application = create_app(args.directory, notification_token_file=args.inbox_token_file, notification_ca_file=args.inbox_ca_file)
            uvicorn.run(application, host=args.host, port=args.port, ssl_certfile=str(check_private_file(args.tls_cert)),
                        ssl_keyfile=str(check_private_file(args.tls_key)), proxy_headers=False, access_log=False,
                        server_header=False)
    except (ValueError, OSError, sqlite3.Error):
        print("Collector operation refused. Preserve private files and inspect configuration, custody and schema.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
