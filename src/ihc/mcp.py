"""Minimal Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0)."""

from __future__ import annotations

import json
import sys
import traceback
from typing import IO

from . import __version__

PROTOCOL_VERSION = "2024-11-05"

# Test hook: when set, tools/call uses this instead of importing ihc.cli.dispatch.
DISPATCH = None

TOOLS = [
    {
        "name": "status",
        "description": "Last run, drift, pending decisions",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "facts",
        "description": "Mined system facts JSON",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "check",
        "description": "Run the proof pipeline (build only, never switch)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["all", "system", "hm"], "default": "all"},
            },
        },
    },
    {
        "name": "bump",
        "description": "Bump flake inputs and prove the result",
        "inputSchema": {
            "type": "object",
            "properties": {
                "inputs": {"type": "array", "items": {"type": "string"}},
                "max_attempts": {"type": "integer", "default": 3},
            },
        },
    },
    {
        "name": "fix",
        "description": "Attempt to fix a failing target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "enum": ["all", "system", "hm"]},
                "task": {"type": "string"},
            },
        },
    },
    {
        "name": "docs_check",
        "description": "Verify GOALS.md/MAINTENANCE.md citations",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _dispatch(argv: list[str]) -> tuple[int, str]:
    if DISPATCH is not None:
        return DISPATCH(argv)
    from .cli import dispatch

    return dispatch(argv)


def _argv_for(name: str, args: dict) -> list[str]:
    if name == "status":
        return ["status"]
    if name == "facts":
        return ["facts"]
    if name == "check":
        target = args.get("target") or "all"
        return ["check", "--target", target]
    if name == "bump":
        n = args.get("max_attempts", 3)
        argv = ["bump", "--max-attempts", str(n)]
        argv += list(args.get("inputs") or [])
        return argv
    if name == "fix":
        target = args.get("target") or "all"
        argv = ["fix", "--target", target]
        task = args.get("task")
        if task:
            argv += ["--task", task]
        return argv
    if name == "docs_check":
        return ["docs", "check"]
    raise ValueError("unknown tool: %s" % name)


def _error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _result(id_, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _handle_tools_call(id_, params: dict) -> dict:
    name = params.get("name")
    args = params.get("arguments") or {}
    try:
        argv = _argv_for(name, args)
        code, output = _dispatch(argv)
        return _result(id_, {"content": [{"type": "text", "text": output}], "isError": code != 0})
    except Exception:
        return _result(id_, {"content": [{"type": "text", "text": traceback.format_exc()}], "isError": True})


def handle(message: dict) -> dict | None:
    """Process one JSON-RPC message and return the response, or None for notifications."""
    id_ = message.get("id")
    method = message.get("method")
    is_notification = "id" not in message

    if method == "initialize":
        return _result(
            id_,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ihc", "version": __version__},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return _result(id_, {})
    if method == "tools/list":
        return _result(id_, {"tools": TOOLS})
    if method == "tools/call":
        return _handle_tools_call(id_, message.get("params") or {})

    if is_notification:
        return None
    return _error(id_, -32601, "method not found: %s" % method)


def serve(stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> None:
    """Read newline-delimited JSON-RPC requests from stdin, write responses to stdout, until EOF."""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, -32700, "parse error")
        else:
            response = handle(message)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
