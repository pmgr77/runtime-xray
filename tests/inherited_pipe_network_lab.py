
#!/usr/bin/env python3
"""
@file inherited_pipe_network_lab.py
@brief F3 regression: pre-existing pipe -> process -> TCP.

The launcher creates a pipe before RuntimeXRay starts.

The traced application forks:
    Parent: write(secret) -> inherited pipe
    Child:  read(secret)  -> TCP sendto()

The test verifies real syscall observations, resource identity,
fingerprints, a pipe DataFlow edge and TCP delivery.

Copyright 2026 Peter Magram
SPDX-License-Identifier: Apache-2.0
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


SECRET = b"password=RXR_INHERITED_PIPE_NETWORK_2026"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tracee(read_fd, write_fd, port):
    """Executed inside RuntimeXRay tracing."""

    child = os.fork()

    if child == 0:
        try:
            os.close(write_fd)

            data = os.read(read_fd, 4096)
            os.close(read_fd)

            if data != SECRET:
                os._exit(2)

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=30
            ) as connection:
                connection.sendall(data)

            os._exit(0)

        except Exception:
            os._exit(3)

    os.close(read_fd)

    written = os.write(write_fd, SECRET)
    os.close(write_fd)

    require(written == len(SECRET), "incomplete pipe write")

    _, status = os.waitpid(child, 0)

    require(
        os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
        "child process failed"
    )


def validate_trace(json_path, report_path):
    """Validate the actual RuntimeXRay lineage evidence."""

    require(json_path.is_file(), "JSON report missing")
    require(report_path.is_file(), "text report missing")

    json_bytes = json_path.read_bytes()
    report_bytes = report_path.read_bytes()

    require(
        SECRET not in json_bytes,
        "plaintext secret leaked into JSON"
    )

    require(
        SECRET not in report_bytes,
        "plaintext secret leaked into text report"
    )

    report = json.loads(json_bytes)

    lineage = report["lineage"]
    observations = lineage["observations"]
    edges = lineage["edges"]

    # Only completed, fingerprinted pipe writes.
    writes = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") in ("write", "writev")
        and obs.get("resource_type") == "pipe"
        and obs.get("resource_role") == "write"
        and (obs.get("resource_id") or 0) > 0
        and (obs.get("return_value") or 0) > 0
        and bool(obs.get("fingerprint"))
    ]

    # Only completed, fingerprinted pipe reads.
    reads = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "read"
        and obs.get("resource_type") == "pipe"
        and obs.get("resource_role") == "read"
        and (obs.get("resource_id") or 0) > 0
        and (obs.get("return_value") or 0) > 0
        and bool(obs.get("fingerprint"))
    ]

    # Network boundary observations.
    sends = [
        obs for obs in observations
        if obs.get("type") == "event"
        and obs.get("syscall") == "sendto"
        and (obs.get("return_value") or 0) > 0
        and bool(obs.get("fingerprint"))
    ]

    require(writes, "fingerprinted pipe write missing")
    require(reads, "fingerprinted pipe read missing")
    require(sends, "fingerprinted TCP sendto missing")

    # Find one complete, evidence-backed F3 chain.
    matched = None

    for write in writes:
        for read in reads:

            if write["process_instance_id"] == read["process_instance_id"]:
                continue

            if write["resource_id"] != read["resource_id"]:
                continue

            if write["fingerprint"] != read["fingerprint"]:
                continue

            # DataFlow must connect exactly these syscall events.
            pipe_edge = any(
                edge.get("relation") == "dataflow"
                and edge.get("from_seq") == write["seq"]
                and edge.get("to_seq") == read["seq"]
                for edge in edges
            )

            if not pipe_edge:
                continue

            for send in sends:
                if send["process_instance_id"] != read["process_instance_id"]:
                    continue

                if send["fingerprint"] != read["fingerprint"]:
                    continue

                matched = (write, read, send)
                break

            if matched:
                break

        if matched:
            break

    require(
        matched is not None,
        "missing complete write -> read -> sendto evidence chain"
    )

    write, read, send = matched

    print("PASS: pipe endpoints share resource identity")
    print("PASS: parent and child have distinct process instances")
    print("PASS: exact fingerprint across write/read/sendto")
    print("PASS: DataFlow edge connects parent write to child read")
    print("PASS: TCP sendto observed in receiving process")
    print("PASS: plaintext credential redaction")

    print(
        "Evidence: "
        f"write_seq={write['seq']} "
        f"read_seq={read['seq']} "
        f"sendto_seq={send['seq']} "
        f"resource_id={write['resource_id']}"
    )

    # No read -> sendto DataFlow edge is required yet.
    # The network boundary is currently correlated by fingerprint
    # and process identity, not by a separate causal edge.


def launcher(binary):
    """Create pipe and receiver outside the tracing boundary."""

    with tempfile.TemporaryDirectory(prefix="rxray-f3-") as temp:
        directory = Path(temp)

        json_path = directory / "f3.json"
        report_path = directory / "f3-report.txt"
        log_path = directory / "f3-trace.log"

        read_fd, write_fd = os.pipe()

        os.set_inheritable(read_fd, True)
        os.set_inheritable(write_fd, True)

        received = {}
        receiver_error = {}

        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as server:

                server.bind(("127.0.0.1", 0))
                server.listen(1)
                server.settimeout(180)

                port = server.getsockname()[1]

                def receive_tcp():
                    try:
                        connection, _ = server.accept()

                        with connection:
                            connection.settimeout(30)

                            chunks = []

                            while True:
                                chunk = connection.recv(4096)

                                if not chunk:
                                    break

                                chunks.append(chunk)

                            received["payload"] = b"".join(chunks)

                    except Exception as error:
                        receiver_error["error"] = str(error)

                receiver = threading.Thread(
                    target=receive_tcp,
                    daemon=True
                )

                receiver.start()

                command = [
                    str(binary),
                    "trace",
                    "--backend", "ptrace",
                    "--memory-reader", "proc",
                    "--follow-forks",
                    "--json", str(json_path),
                    "--report", str(report_path),
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--tracee",
                    str(read_fd),
                    str(write_fd),
                    str(port)
                ]

                try:
                    with log_path.open("w") as log:
                        result = subprocess.run(
                            command,
                            pass_fds=(read_fd, write_fd),
                            stdin=subprocess.DEVNULL,
                            stdout=log,
                            stderr=subprocess.STDOUT,
                            timeout=180,
                            check=False
                        )

                    receiver.join(timeout=5)

                    require(
                        result.returncode == 0,
                        f"RuntimeXRay returned {result.returncode}"
                    )

                    require(
                        not receiver.is_alive(),
                        "TCP receiver did not finish"
                    )

                    require(
                        not receiver_error,
                        f"TCP receiver failed: {receiver_error}"
                    )

                    require(
                        received.get("payload") == SECRET,
                        "TCP receiver payload mismatch"
                    )

                    print("PASS: exact TCP payload received")

                    validate_trace(json_path, report_path)

                    print("PASS: F3 inherited pipe -> network regression")

                except Exception:
                    if log_path.exists():
                        print("--- RuntimeXRay log ---", file=sys.stderr)
                        print(
                            log_path.read_text(errors="replace")[-6000:],
                            file=sys.stderr
                        )
                    raise

        finally:
            os.close(read_fd)
            os.close(write_fd)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--tracee":
        tracee(
            int(sys.argv[2]),
            int(sys.argv[3]),
            int(sys.argv[4])
        )
        return

    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: inherited_pipe_network_lab.py "
            "/path/to/runtimexray"
        )

    binary = Path(sys.argv[1]).resolve()

    require(binary.is_file(), "RuntimeXRay binary not found")
    require(os.access(binary, os.X_OK), "RuntimeXRay is not executable")

    launcher(binary)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
