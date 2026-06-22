"""A tiny, in-process Modbus/TCP fixture server bound to localhost.

Used ONLY by the active-probe tests. It listens on 127.0.0.1 on an
OS-assigned port, answers read/identity requests with canned data, and shuts
down cleanly. No external hosts are ever contacted.
"""
from __future__ import annotations

import socket
import struct
import threading


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class LocalModbusServer:
    """Minimal localhost Modbus/TCP responder for tests (context manager)."""

    def __init__(self, host="127.0.0.1"):
        self.host = host
        self.port = 0
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.requests = []  # function codes received

    def __enter__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(4)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def address(self):
        return f"{self.host}:{self.port}"

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                self._handle(conn)

    def _handle(self, conn):
        conn.settimeout(1.0)
        while not self._stop.is_set():
            head = _recv_exact(conn, 7)
            if head is None:
                return
            tid, pid, length, uid = struct.unpack(">HHHB", head)
            rest = _recv_exact(conn, max(length - 1, 0))
            if rest is None:
                return
            fc = rest[0]
            self.requests.append(fc)
            resp = self._respond(tid, uid, fc, rest[1:])
            try:
                conn.sendall(resp)
            except OSError:
                return

    @staticmethod
    def _frame(tid, uid, pdu):
        return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu

    def _respond(self, tid, uid, fc, body):
        if fc in (0x01, 0x02, 0x03, 0x04):
            if fc in (0x01, 0x02):
                qty = struct.unpack(">HH", body[:4])[1]
                nbytes = (qty + 7) // 8
            else:
                qty = struct.unpack(">HH", body[:4])[1]
                nbytes = qty * 2
            pdu = bytes([fc, nbytes]) + bytes(nbytes)
        elif fc == 0x11:  # report server id
            ident = b"COGNIS-PLC"
            pdu = bytes([fc, len(ident) + 1]) + ident + bytes([0xFF])
        elif fc == 0x2B:  # device identification
            pdu = bytes([fc, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01]) + \
                bytes([0x00, 0x06]) + b"Cognis"
        else:
            pdu = bytes([(fc | 0x80) & 0xFF, 0x01])
        return self._frame(tid, uid, pdu)
