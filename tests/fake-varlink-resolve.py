#!/usr/bin/env python3
"""Deterministic io.systemd.Resolve Varlink server for NSS integration tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import socket
import threading

TEST_NAME = "example.test"
TEST_V4 = [192, 0, 2, 123]
TEST_V6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x23]
MAX_MESSAGE = 1024 * 1024


class Server:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stopping = threading.Event()
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(32)
        self.listener.settimeout(0.2)

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def run(self, ready_file: Path) -> None:
        ready_file.write_text("ready\n", encoding="ascii")
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    @staticmethod
    def serve(client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            pending = bytearray()
            try:
                while True:
                    chunk = client.recv(8192)
                    if not chunk:
                        return
                    pending.extend(chunk)
                    if len(pending) > MAX_MESSAGE:
                        return
                    marker = pending.find(0)
                    if marker < 0:
                        continue
                    request = json.loads(pending[:marker].decode("utf-8"))
                    response = dispatch(request)
                    client.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\0")
                    return
            except (OSError, ValueError, json.JSONDecodeError):
                return


def dispatch(request: object) -> dict[str, object]:
    if not isinstance(request, dict):
        return error("org.varlink.service.InvalidParameter")
    method = request.get("method")
    parameters = request.get("parameters")
    if not isinstance(parameters, dict):
        return error("org.varlink.service.InvalidParameter")

    if method == "io.systemd.Resolve.ResolveHostname":
        if parameters.get("name") != TEST_NAME:
            return error("io.systemd.Resolve.NoSuchResourceRecord")
        return {
            "parameters": {
                "addresses": [
                    {"ifindex": 0, "family": socket.AF_INET, "address": TEST_V4},
                    {"ifindex": 0, "family": socket.AF_INET6, "address": TEST_V6},
                ],
                "name": TEST_NAME,
                "flags": 0,
            }
        }

    if method == "io.systemd.Resolve.ResolveAddress":
        family = parameters.get("family")
        address = parameters.get("address")
        if not (
            (family == socket.AF_INET and address == TEST_V4)
            or (family == socket.AF_INET6 and address == TEST_V6)
        ):
            return error("io.systemd.Resolve.NoSuchResourceRecord")
        return {
            "parameters": {
                "names": [{"ifindex": 0, "name": TEST_NAME}],
                "flags": 0,
            }
        }

    return error("org.varlink.service.MethodNotFound")


def error(identifier: str) -> dict[str, object]:
    return {"error": identifier, "parameters": {}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    arguments = parser.parse_args()

    arguments.socket.parent.mkdir(parents=True, exist_ok=True)
    server = Server(arguments.socket)

    def stop(_signum: int, _frame: object) -> None:
        server.stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.run(arguments.ready_file)
    finally:
        server.close()


if __name__ == "__main__":
    main()
