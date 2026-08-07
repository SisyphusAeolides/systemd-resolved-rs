#!/usr/bin/env python3
"""Small deterministic UDP/TCP DNS server for live interface tests."""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import socket
import struct
import threading

TEST_NAME = "example.test"
TEST_ADDRESS = "192.0.2.123"
LOOPBACK = "127.0.0.1"


def question(packet: bytes) -> tuple[int, str, int, int]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    if struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("expected one question")

    offset = 12
    labels: list[bytes] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS name")
        labels.append(packet[offset : offset + length])
        offset += length

    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    return offset + 4, b".".join(labels).decode("ascii").lower(), qtype, qclass


def response(query: bytes) -> bytes:
    end, name, qtype, qclass = question(query)
    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    answer = name == TEST_NAME and qtype == 1 and qclass == 1
    flags = 0x8000 | 0x0080 | (query_flags & (0x0100 | 0x0010))
    packet = bytearray(struct.pack("!HHHHHH", identifier, flags, 1, int(answer), 0, 0))
    packet.extend(query[12:end])
    if answer:
        packet.extend(b"\xc0\x0c")
        packet.extend(struct.pack("!HHIH", 1, 1, 60, 4))
        packet.extend(socket.inet_aton(TEST_ADDRESS))
    return bytes(packet)


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        output.extend(chunk)
    return bytes(output)


class Server:
    def __init__(self) -> None:
        self.stopping = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((LOOPBACK, 0))
        self.port = int(self.udp.getsockname()[1])
        self.udp.settimeout(0.2)

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((LOOPBACK, self.port))
        self.tcp.listen(16)
        self.tcp.settimeout(0.2)

        self.threads = [
            threading.Thread(target=self.serve_udp, daemon=True),
            threading.Thread(target=self.serve_tcp, daemon=True),
        ]

    def run(self, ready_file: Path) -> None:
        for thread in self.threads:
            thread.start()
        ready_file.write_text(f"{self.port}\n", encoding="ascii")
        self.stopping.wait()

    def close(self) -> None:
        self.stopping.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=2)

    def serve_udp(self) -> None:
        while not self.stopping.is_set():
            try:
                query, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.udp.sendto(response(query), peer)
            except (OSError, ValueError):
                continue

    def serve_tcp(self) -> None:
        while not self.stopping.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve_tcp_client, args=(client,), daemon=True).start()

    @staticmethod
    def serve_tcp_client(client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            try:
                while True:
                    length = client.recv(2)
                    if not length:
                        return
                    if len(length) != 2:
                        length += read_exact(client, 2 - len(length))
                    query = read_exact(client, struct.unpack("!H", length)[0])
                    answer = response(query)
                    client.sendall(struct.pack("!H", len(answer)) + answer)
            except (ConnectionError, OSError, ValueError):
                return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready-file", required=True, type=Path)
    arguments = parser.parse_args()

    server = Server()

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
