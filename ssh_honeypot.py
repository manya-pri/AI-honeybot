"""HTTP-driven SSH-style decoy. It never binds an SSH socket or runs commands."""
from __future__ import annotations

from flask import jsonify, request

_FAKE_COMMAND_OUTPUT = {
    "pwd": "/home/analyst",
    "whoami": "analyst",
    "ls": "Documents  backups  notes.txt",
    "cat /etc/passwd": "root:x:0:0:root:/root:/usr/sbin/nologin\ndemo:x:1000:1000:Demo:/home/demo:/bin/bash",
    "help": "pwd, whoami, ls, cat /etc/passwd, help",
}


def fake_ssh_login():
    return jsonify(service="synthetic-ssh", authenticated=False,
                   message="Authentication failed. This decoy has no account database."), 401


def fake_ssh_session():
    payload = request.get_json(silent=True) or request.form
    command = str(payload.get("command", ""))[:160].strip()
    output = _FAKE_COMMAND_OUTPUT.get(command, "Command unavailable in synthetic session.")
    return jsonify(service="synthetic-ssh", command_observed=command, output=output,
                   executed=False, note="Response generated from fixed synthetic examples."), 200
