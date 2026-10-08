"""Explicit local commands for installed guidance and project creation."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Sequence

from .guidance import inspect_capabilities, list_guide_topics, read_guide, read_starter
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

_COMMAND = "python -m role_aware_dashboard_toolkit"
_RUN_COMMAND = "python -m streamlit run app.py --server.address 127.0.0.1"


class _CommandError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 2,
                 next_step: str = "", **details: Any) -> None:
        super().__init__(message)
        self.status = status
        self.record = {"code": code, "message": message, "next_step": next_step, **details}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _CommandError("USAGE_ERROR", message, next_step=f"{_COMMAND} --help")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json"), default=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true", default=argparse.SUPPRESS)


def _parser() -> tuple[_Parser, dict[str, argparse.ArgumentParser]]:
    parser = _Parser(prog=_COMMAND, add_help=False, allow_abbrev=False,
                     description="Read installed guidance or explicitly create a new dashboard project.")
    _common(parser)
    subparsers = parser.add_subparsers(dest="command", parser_class=_Parser)
    commands = {}
    for name, help_text in (
        ("guide", "Read an offline guide topic or list topics."),
        ("inspect", "Inspect installed capabilities without importing optional hosts."),
        ("example", "Read the packaged starter files."),
        ("init", "Create a new project directory; existing paths are refused."),
    ):
        child = subparsers.add_parser(name, help=help_text, description=help_text,
                                      add_help=False, allow_abbrev=False)
        _common(child)
        commands[name] = child
    commands["guide"].add_argument("topic", nargs="?")
    commands["example"].add_argument("name", nargs="?", default="starter")
    commands["example"].add_argument("--file", dest="filename")
    commands["init"].add_argument("destination", nargs="?")
    commands["init"].add_argument("--dry-run", action="store_true")
    commands["init"].add_argument("--auth", action="store_true",
                                 help="Create the authenticated starter, recommended for shared use.")
    return parser, commands


def _json_requested(arguments: Sequence[str]) -> bool:
    selected = "text"
    for index, arg in enumerate(arguments):
        if arg == "--format" and index + 1 < len(arguments):
            selected = arguments[index + 1]
        elif arg.startswith("--format="):
            selected = arg.split("=", 1)[1]
    return selected == "json"


def _check_path_chain(path: Path) -> None:
    # Check unresolved components before resolve() can erase a symlink/junction.
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise _CommandError("UNSAFE_DESTINATION", "Destination must not traverse a symlink or reparse point.",
                                next_step="Choose a new directory under an ordinary existing parent.")


def _new_destination(destination: str) -> Path:
    if not isinstance(destination, str) or not destination.strip() or not destination.isprintable():
        raise _CommandError("INVALID_DESTINATION", "Provide a nonempty printable destination path.")
    raw = Path(destination).expanduser()
    if ".." in raw.parts:
        raise _CommandError("INVALID_DESTINATION", "Destination must not contain '..' components.",
                            next_step="Use an explicit path to the new project directory.")
    path = raw.absolute()
    _check_path_chain(path)
    if os.path.lexists(path):
        raise _CommandError("DESTINATION_EXISTS", "Destination already exists; no files were changed.",
                            next_step="Choose a new directory, or use guide/example to customize an existing project.")
    if not path.parent.is_dir():
        raise _CommandError("MISSING_PARENT", "The destination parent must already be a directory.",
                            next_step="Create the intended parent explicitly, then retry with a new directory name.")
    return path.resolve(strict=False)


def initialize_project(destination: str, *, dry_run: bool = False,
                       authenticated: bool = False) -> dict[str, Any]:
    """Create only a new directory; report partial output honestly on I/O failure.

    Existing files, directories and links are never merged or overwritten.
    Importing this module never calls this function or writes project files.
    """
    path = _new_destination(destination)
    contents = read_starter(authenticated=authenticated)
    result = {"destination": str(path), "dry_run": bool(dry_run), "files": list(contents),
              "created_files": [], "run_command": _RUN_COMMAND,
              "auth_mode": "authenticated" if authenticated else "demo",
              "setup_required": bool(authenticated)}
    if authenticated:
        result["setup_command"] = f"{_COMMAND} guide authentication"
    if dry_run:
        return result
    created = []
    directory_created = False
    try:
        _check_path_chain(path)
        path.mkdir(exist_ok=False)
        directory_created = True
        for relative, content in contents.items():
            target = path / relative
            _check_path_chain(target)
            target.parent.mkdir(exist_ok=True)
            _check_path_chain(target)
            with target.open("x", encoding="utf-8", newline="\n") as handle:
                # Record the new file immediately: a failed write may leave it partial.
                created.append(relative)
                handle.write(content)
    except (OSError, _CommandError) as exc:
        raise _CommandError(
            "INIT_FAILED", "Project creation did not finish; inspect the reported new directory before retrying.",
            status=1, next_step="Inspect any created files; choose a different new destination to retry.",
            destination=str(path), destination_created=directory_created, created_files=created,
            exception_type=type(exc).__name__,
        ) from None
    result["created_files"] = created
    return result


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "guide":
        if args.topic is None:
            return {"topics": list_guide_topics(), "usage": f"{_COMMAND} guide TOPIC"}
        try:
            return read_guide(args.topic)
        except ValueError as exc:
            raise _CommandError("UNKNOWN_GUIDE", str(exc), next_step=f"{_COMMAND} guide") from None
    if args.command == "inspect":
        return inspect_capabilities()
    if args.command == "example":
        if args.name not in {"starter", "authenticated"}:
            raise _CommandError("UNKNOWN_EXAMPLE", "Unknown example. Available examples: starter, authenticated.",
                                next_step=f"{_COMMAND} example starter")
        files = read_starter(authenticated=args.name == "authenticated")
        if args.filename:
            if args.filename not in files:
                raise _CommandError("UNKNOWN_EXAMPLE_FILE", "Choose one of: " + ", ".join(files),
                                    next_step=f"{_COMMAND} example starter")
            return {"name": args.name, "file": args.filename, "content": files[args.filename]}
        return {"name": args.name, "files": files}
    if args.command == "init":
        if not args.destination:
            raise _CommandError("USAGE_ERROR", "init requires a destination.", next_step=f"{_COMMAND} init --help")
        return initialize_project(args.destination, dry_run=args.dry_run, authenticated=args.auth)
    raise _CommandError("USAGE_ERROR", "Choose guide, inspect, example or init.")


def _render_text(command: str, result: dict[str, Any]) -> str:
    if "help" in result:
        return result["help"]
    if command == "guide":
        if "content" in result:
            return result["content"]
        return "\n".join(f"{item['id']}: {item['title']}\n  {item['command']}" for item in result["topics"])
    if command == "example":
        if "content" in result:
            return result["content"]
        return "\n\n".join(f"--- {name} ---\n{content}" for name, content in result["files"].items())
    if command == "init":
        action = "Would create" if result["dry_run"] else "Created"
        output = f"{action} {result['destination']}:\n" + "\n".join(result["files"])
        if result.get("setup_required"):
            return output + (
                "\n\nAuthenticated dashboard: access stays locked until setup is complete.\n"
                "Configure the provider, protected secrets and explicit account grants first:\n"
                f"{result['setup_command']}\n"
                "Then launch from the generated directory using the guide's secrets-file command.\n"
                "Shared hosting also requires the guide's HTTPS and deployment checks."
            )
        return output + (
            "\n\nLocal demo: self-selected roles do not authenticate users.\n"
            "For a shared dashboard, create a new project with init --auth.\n"
            f"\nFrom the generated directory, run:\n{result['run_command']}"
        )
    return json.dumps(result, indent=2, ensure_ascii=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run an explicit command. JSON mode emits exactly one versioned envelope."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_output = _json_requested(arguments)
    command = ""
    envelope = {"schema_version": 1, "toolkit_version": ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION,
                "command": command, "ok": True}
    status = 0
    try:
        parser, commands = _parser()
        args = parser.parse_args(arguments)
        command = args.command or "help"
        envelope["command"] = command
        json_output = getattr(args, "format", "text") == "json"
        if not args.command or getattr(args, "help", False):
            selected = commands.get(args.command, parser)
            result = {"help": selected.format_help()}
        else:
            result = _dispatch(args)
        envelope["result"] = result
    except _CommandError as exc:
        envelope.update(ok=False, error=exc.record)
        status = exc.status
    except (OSError, UnicodeError) as exc:
        envelope.update(ok=False, error={"code": "RESOURCE_OR_IO_ERROR",
            "message": "Could not read installed resources or inspect the requested filesystem location.",
            "next_step": "Check the installed package and local filesystem access.", "exception_type": type(exc).__name__})
        status = 1
    if json_output:
        print(json.dumps(envelope, ensure_ascii=True, allow_nan=False))
    elif status:
        error = envelope["error"]
        print(f"{error['code']}: {error['message']}\n{error.get('next_step', '')}", file=sys.stderr)
        if "created_files" in error:
            print(f"Destination: {error['destination']}\nCreated files (may be partial): {error['created_files']}", file=sys.stderr)
    else:
        prefix = "# " if command == "example" and "file" in envelope["result"] else ""
        print(f"{prefix}Role-Aware Dashboard Toolkit {ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION}\n")
        print(_render_text(command, envelope["result"]))
    return status


__all__ = ["main", "initialize_project"]
