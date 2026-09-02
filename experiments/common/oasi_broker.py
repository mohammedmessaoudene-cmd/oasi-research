#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAGIC = b"OASI2BT1"
RECEIPT_MAGIC = b"OASI2BR2"
VERSION = 1
KIND_PREPARE = 1
KIND_EXECUTE = 2
STATUS_PREPARED = 0x81
STATUS_EFFECT_RECEIPT = 0x82
GENERATION = 152
ATTEMPT = 1
LEASE_EPOCH = 1
MAX_FRAME = 512
HEADER = struct.Struct(">8sBBIQQ32s16sH")
RECEIPT_CORE = struct.Struct(">8sBBIQ32s")
RECEIPT_SIGNATURE_BYTES = 64
KEY_ID = b"rfc8032-test-2".ljust(16, b"\0")
CONTEXT = hashlib.sha256(b"OASI:S1:FIXTURE:CTX").digest()
PREPARE_PAYLOAD = b"FIXTURE_NOOP_V1"
TEST_ONLY_PRIVATE_SEED_DO_NOT_USE = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f"
    "5b8a319f35aba624da8cf6ed4fb8a6fb"
)
GUEST_RECEIPT_FIXTURE_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)


class ProtocolError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signed_frame(kind: int, payload: bytes) -> tuple[bytes, bytes]:
    if kind not in (KIND_PREPARE, KIND_EXECUTE) or len(payload) > 128:
        raise ProtocolError("frame bounds")
    header = HEADER.pack(
        MAGIC,
        VERSION,
        kind,
        GENERATION,
        ATTEMPT,
        LEASE_EPOCH,
        CONTEXT,
        KEY_ID,
        len(payload),
    )
    signed = header + payload
    signature = Ed25519PrivateKey.from_private_bytes(
        TEST_ONLY_PRIVATE_SEED_DO_NOT_USE
    ).sign(signed)
    raw = signed + signature
    return struct.pack(">H", len(raw)) + raw, hashlib.sha256(raw).digest()


def parse_receipt(raw: bytes, expected_status: int, expected_digest: bytes) -> None:
    if len(raw) != RECEIPT_CORE.size + RECEIPT_SIGNATURE_BYTES:
        raise ProtocolError("receipt length")
    core = raw[: RECEIPT_CORE.size]
    signature = raw[RECEIPT_CORE.size :]
    try:
        Ed25519PublicKey.from_public_bytes(
            GUEST_RECEIPT_FIXTURE_PUBLIC_KEY
        ).verify(signature, core)
    except InvalidSignature as exception:
        raise ProtocolError("guest receipt fixture signature") from exception
    magic, version, status, generation, attempt, digest = RECEIPT_CORE.unpack(core)
    if (
        magic != RECEIPT_MAGIC
        or version != VERSION
        or status != expected_status
        or generation != GENERATION
        or attempt != ATTEMPT
        or digest != expected_digest
    ):
        raise ProtocolError("receipt binding")


def recv_exact(channel: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = channel.recv(remaining)
        if not chunk:
            raise ProtocolError("transport truncation")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_receipt(channel: socket.socket, status: int, digest: bytes) -> None:
    prefix = recv_exact(channel, 2)
    length = struct.unpack(">H", prefix)[0]
    if length != RECEIPT_CORE.size + RECEIPT_SIGNATURE_BYTES or length > MAX_FRAME:
        raise ProtocolError(
            f"receipt prefix length={length} raw={prefix.hex()}"
        )
    parse_receipt(recv_exact(channel, length), status, digest)


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        self.seal_path = path.with_suffix(path.suffix + ".sha256")
        existed = path.exists()
        if existed:
            if not self.seal_path.is_file():
                raise ProtocolError("existing ledger has no seal")
            expected = self.seal_path.read_text(encoding="ascii").strip()
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if expected != actual:
                raise ProtocolError("ledger seal mismatch")
        self.connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=DELETE")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS attempts (
              generation INTEGER NOT NULL,
              context TEXT NOT NULL,
              attempt INTEGER NOT NULL,
              state TEXT NOT NULL,
              dispatch_count INTEGER NOT NULL DEFAULT 0,
              receipt_digest TEXT,
              PRIMARY KEY (generation, context, attempt)
            );
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              generation INTEGER NOT NULL,
              context TEXT NOT NULL,
              attempt INTEGER NOT NULL,
              event TEXT NOT NULL,
              previous_hash TEXT NOT NULL,
              record_hash TEXT NOT NULL
            );
            """
        )
        if not existed:
            self._seal()

    def _seal(self) -> None:
        self.connection.execute("PRAGMA wal_checkpoint(FULL)")
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        temporary = self.seal_path.with_suffix(self.seal_path.suffix + ".tmp")
        with temporary.open("w", encoding="ascii", newline="\n") as handle:
            handle.write(digest + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.seal_path)
        directory = os.open(str(self.path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def close(self) -> None:
        self.connection.close()

    def _append_event(self, event: str) -> None:
        row = self.connection.execute(
            "SELECT record_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = row[0] if row else "0" * 64
        record = {
            "generation": GENERATION,
            "context": CONTEXT.hex(),
            "attempt": ATTEMPT,
            "event": event,
            "previous_hash": previous,
        }
        digest = hashlib.sha256(canonical_json(record)).hexdigest()
        self.connection.execute(
            "INSERT INTO events(generation,context,attempt,event,previous_hash,record_hash) VALUES(?,?,?,?,?,?)",
            (GENERATION, CONTEXT.hex(), ATTEMPT, event, previous, digest),
        )

    def prepare(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "INSERT INTO attempts(generation,context,attempt,state) VALUES(?,?,?,?)",
                (GENERATION, CONTEXT.hex(), ATTEMPT, "PREPARED"),
            )
            self._append_event("PREPARED")
            self.connection.execute("COMMIT")
            self._seal()
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def consume(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state,dispatch_count FROM attempts WHERE generation=? AND context=? AND attempt=?",
                (GENERATION, CONTEXT.hex(), ATTEMPT),
            ).fetchone()
            if row != ("PREPARED", 0):
                raise ProtocolError("attempt is not uniquely prepared")
            self.connection.execute(
                "UPDATE attempts SET state='CONSUMED',dispatch_count=1 WHERE generation=? AND context=? AND attempt=?",
                (GENERATION, CONTEXT.hex(), ATTEMPT),
            )
            self._append_event("CONSUMED_BEFORE_FIXTURE_NOOP")
            self.connection.execute("COMMIT")
            self._seal()
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_result(self, receipt_digest: str) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state,dispatch_count FROM attempts WHERE generation=? AND context=? AND attempt=?",
                (GENERATION, CONTEXT.hex(), ATTEMPT),
            ).fetchone()
            if row != ("CONSUMED", 1):
                raise ProtocolError("result without consumed one-shot")
            self.connection.execute(
                "UPDATE attempts SET state='RESULT',receipt_digest=? WHERE generation=? AND context=? AND attempt=?",
                (receipt_digest, GENERATION, CONTEXT.hex(), ATTEMPT),
            )
            self._append_event("FIXTURE_NOOP_RESULT")
            self.connection.execute("COMMIT")
            self._seal()
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def terminal(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state,dispatch_count,receipt_digest FROM attempts WHERE generation=? AND context=? AND attempt=?",
                (GENERATION, CONTEXT.hex(), ATTEMPT),
            ).fetchone()
            if row is None or row[0] != "RESULT" or row[1] != 1 or not row[2]:
                raise ProtocolError("terminal without durable result")
            self.connection.execute(
                "UPDATE attempts SET state='TERMINAL' WHERE generation=? AND context=? AND attempt=?",
                (GENERATION, CONTEXT.hex(), ATTEMPT),
            )
            self._append_event("TERMINAL")
            self.connection.execute("COMMIT")
            self._seal()
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def state(self) -> str:
        row = self.connection.execute(
            "SELECT state FROM attempts WHERE generation=? AND context=? AND attempt=?",
            (GENERATION, CONTEXT.hex(), ATTEMPT),
        ).fetchone()
        return "ABSENT" if row is None else str(row[0])

    def recovery_action(self) -> str:
        state = self.state()
        return {
            "ABSENT": "NO_ACTION",
            "PREPARED": "ABORT_WITHOUT_EFFECT",
            "CONSUMED": "BLOCK_NO_REDISPATCH",
            "RESULT": "EMIT_TERMINAL_ONLY",
            "TERMINAL": "COMPLETE_NO_REDISPATCH",
        }.get(state, "FAIL_CLOSED")

    def verify(self) -> None:
        if self.connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ProtocolError("sqlite integrity")
        previous = "0" * 64
        for generation, context, attempt, event, stored_previous, record_hash in self.connection.execute(
            "SELECT generation,context,attempt,event,previous_hash,record_hash FROM events ORDER BY sequence"
        ):
            record = {
                "generation": generation,
                "context": context,
                "attempt": attempt,
                "event": event,
                "previous_hash": previous,
            }
            expected = hashlib.sha256(canonical_json(record)).hexdigest()
            if stored_previous != previous or record_hash != expected:
                raise ProtocolError("ledger hash chain")
            previous = record_hash
        row = self.connection.execute(
            "SELECT state,dispatch_count FROM attempts WHERE generation=? AND context=? AND attempt=?",
            (GENERATION, CONTEXT.hex(), ATTEMPT),
        ).fetchone()
        if row is not None and (row[1] < 0 or row[1] > 1):
            raise ProtocolError("double effect")


def accept_qemu_channel(
    listener: socket.socket, process: subprocess.Popen[bytes], timeout: float
) -> socket.socket:
    """Accept QEMU as the Unix client, bounded by process liveness and time."""
    deadline = time.monotonic() + timeout
    listener.settimeout(0.25)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProtocolError(f"qemu exited before transport: {process.returncode}")
        try:
            candidate, _ = listener.accept()
        except socket.timeout:
            continue
        candidate.settimeout(20.0)
        return candidate
    raise ProtocolError("transport accept timeout")


def wait_for_terminal(log_path: Path, process: subprocess.Popen[bytes], timeout: float) -> bytes:
    required = (
        b'"success":true,"terminal":true,"zero_survivors":true',
        b'"commit":false',
        b"OASI2_BROKER_GUEST_PASS",
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = log_path.read_bytes() if log_path.exists() else b""
        if all(marker in data for marker in required):
            return data
        if process.poll() is not None:
            raise ProtocolError(f"qemu exited before terminal: {process.returncode}")
        time.sleep(0.05)
    raise ProtocolError("guardian terminal timeout")


def wait_for_guest_ready(
    log_path: Path, process: subprocess.Popen[bytes], timeout: float
) -> None:
    marker = b"OASI2_ED25519_OPENSSL_SELFTEST_PASS"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = log_path.read_bytes() if log_path.exists() else b""
        if marker in data:
            return
        if process.poll() is not None:
            raise ProtocolError(f"qemu exited before guest readiness: {process.returncode}")
        time.sleep(0.05)
    raise ProtocolError("guest readiness timeout")


def drain_uart_startup_noise(channel: socket.socket) -> bytes:
    """Drain only QEMU's optional single 0xff UART startup byte."""
    drained = bytearray()
    channel.settimeout(0.05)
    try:
        while len(drained) < 64:
            try:
                chunk = channel.recv(64 - len(drained))
            except socket.timeout:
                break
            if not chunk:
                raise ProtocolError("transport closed during startup drain")
            drained.extend(chunk)
    finally:
        channel.settimeout(20.0)
    if bytes(drained) not in (b"", b"\xff"):
        raise ProtocolError(f"unexpected uart startup noise={bytes(drained).hex()}")
    return bytes(drained)


def run_qemu(args: argparse.Namespace) -> dict[str, object]:
    for path in (args.ledger, args.socket, args.log):
        if path.exists():
            raise ProtocolError(f"refusing replay: {path}")
    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(args.ledger)
    ledger.prepare()
    prepare_wire, prepare_digest = signed_frame(KIND_PREPARE, PREPARE_PAYLOAD)
    execute_wire, _ = signed_frame(KIND_EXECUTE, prepare_digest)
    command = [
        str(args.qemu),
        "-machine", "pc,accel=tcg",
        "-cpu", "max",
        "-m", "256M",
        "-smp", "1",
        "-no-user-config",
        "-no-reboot",
        "-display", "none",
        "-monitor", "none",
        "-serial", "stdio",
        "-serial", f"unix:{args.socket},server=off",
        "-net", "none",
        "-kernel", str(args.kernel),
        "-initrd", str(args.initrd),
        "-append", "console=ttyS0,115200 rdinit=/init panic=1 quiet loglevel=0",
    ]
    process: subprocess.Popen[bytes] | None = None
    listener: socket.socket | None = None
    channel: socket.socket | None = None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(args.socket))
        listener.listen(1)
        with args.log.open("wb") as log_handle:
            process = subprocess.Popen(command, stdout=log_handle, stderr=subprocess.STDOUT)
        channel = accept_qemu_channel(listener, process, 10.0)
        peer_credential_status = "not_available"
        if hasattr(socket, "SO_PEERCRED"):
            try:
                peer_pid, peer_uid, _ = struct.unpack(
                    "3i",
                    channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                )
            except OSError as exception:
                if exception.errno != errno.EOPNOTSUPP:
                    raise
                peer_credential_status = "unsupported_wsl1_eopnotsupp"
            else:
                if peer_pid != process.pid or peer_uid != os.getuid():
                    raise ProtocolError("qemu peer credential mismatch")
                peer_credential_status = "verified"
        wait_for_guest_ready(args.log, process, 20.0)
        uart_startup_noise = drain_uart_startup_noise(channel)
        channel.sendall(prepare_wire)
        recv_receipt(channel, STATUS_PREPARED, prepare_digest)
        ledger.consume()
        channel.sendall(execute_wire)
        recv_receipt(channel, STATUS_EFFECT_RECEIPT, prepare_digest)
        wait_for_terminal(args.log, process, 20.0)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        terminal_log = args.log.read_bytes()
        result_digest = hashlib.sha256(terminal_log + prepare_digest).hexdigest()
        ledger.record_result(result_digest)
        ledger.terminal()
        ledger.verify()
        result = {
            "schema": "oasi.s1.broker-run.v1",
            "label": args.label,
            "state": ledger.state(),
            "recovery_action": ledger.recovery_action(),
            "generation": GENERATION,
            "attempt": ATTEMPT,
            "context_sha256": CONTEXT.hex(),
            "prepare_transcript_sha256": prepare_digest.hex(),
            "terminal_log_sha256": hashlib.sha256(terminal_log).hexdigest(),
            "fixture_effect": "NOOP_ONLY",
            "real_effect": False,
            "qemu_network": "none",
            "transport_authentication": "mutual_ed25519_fixture",
            "guest_receipt_key": "rfc8032-test-1-fixture",
            "peer_pid_verified": peer_credential_status == "verified",
            "peer_credential_status": peer_credential_status,
            "uart_startup_noise_hex": uart_startup_noise.hex(),
        }
        print(json.dumps(result, sort_keys=True))
        return result
    finally:
        if channel is not None:
            channel.close()
        if listener is not None:
            listener.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        ledger.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--label", required=True)
    run.add_argument("--ledger", type=Path, required=True)
    run.add_argument("--socket", type=Path, required=True)
    run.add_argument("--log", type=Path, required=True)
    run.add_argument("--qemu", type=Path, required=True)
    run.add_argument("--kernel", type=Path, required=True)
    run.add_argument("--initrd", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        run_qemu(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
