#!/usr/bin/env python3
"""
autoscale_shutdown.py idle service auto-shutdown monitor
Target: Debian 13 / systemd

Periodically polls a TCP application service.
Stops the service via systemd after SHUTDOWN_DELAY seconds with no active clients.
Uses a lightweight RCON-compatible control channel for an accurate connected-client count.

RCON packet structure (Source-style RCON protocol, all ints little-endian):
  [4B length][4B request_id][4B type][payload bytes][0x00 0x00]

Authentication: send type=3, expect type=2 (auth response).
The server echoes the same request_id on success, or -1 on failure.
Some implementations send an extra empty RESPONSE_VALUE (type=0) packet
before the AUTH_RESPONSE (type=2); we loop until we see type=2.

Commands: send type=2, read back type=0 (response value).
The status command response is short (<512 bytes), so fragmentation
is not a concern in this use case.

Control-channel configuration requirements (conceptual):
    RCON must be enabled on the target service
    RCON_HOST / RCON_PORT / RCON_PASSWORD must match the service configuration
"""

import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime

# Configuration
SERVICE_NAME    = "application-service"        # systemd unit (without .service)
SERVICE_PORT    = 0                            # TCP port the service listens on
CHECK_INTERVAL  = 30                           # seconds between polls
SHUTDOWN_DELAY  = 600                          # idle seconds before shutdown (10 min)

RCON_HOST       = "127.0.0.1"
RCON_PORT       = 0
RCON_PASSWORD   = "your_rcon_password_here"   #override in deployment

SERVICE_LOG     = "/var/log/application-service/latest.log"
SCRIPT_LOG      = "/var/log/application-service/autoshutdown.log"
LOCKFILE        = "/tmp/application-service_idle.lock"

# Logging
def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [autoshutdown] {msg}"
    print(line, flush=True)
    try:
        with open(SCRIPT_LOG, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass

# RCON client
class RconError(Exception):
    """Errors raised by the RCON control-channel client."""


def _rcon_pack(request_id: int, request_type: int, payload: str) -> bytes:
    """Build one RCON packet."""
    body = struct.pack("<ii", request_id, request_type) + payload.encode("utf-8") + b"\x00\x00"
    return struct.pack("<i", len(body)) + body


def _rcon_recv(sock: socket.socket) -> tuple[int, int, str]:
    """
    Read one RCON response packet.
    Returns (request_id, type, payload_string).
    Raises RconError on connection problems or bad packet length.
    """
    raw = b""
    while len(raw) < 4:
        chunk = sock.recv(4 - len(raw))
        if not chunk:
            raise RconError("Connection closed while reading RCON packet length")
        raw += chunk

    length = struct.unpack("<i", raw)[0]
    if length < 10 or length > 4110:
        raise RconError(f"Implausible RCON packet length: {length}")

    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RconError("Connection closed mid-RCON-packet")
        data += chunk

    request_id = struct.unpack("<i", data[0:4])[0]
    response_type = struct.unpack("<i", data[4:8])[0]
    payload = data[8:-2].decode("utf-8", errors="replace")
    return request_id, response_type, payload


def rcon_command(command: str, timeout: float = 5.0) -> str:
    """
    Connect → authenticate → run command → return response string.
    Raises RconError on any failure.
    """
    with socket.create_connection((RCON_HOST, RCON_PORT), timeout=timeout) as s:
        s.settimeout(timeout)

        # Authenticate
        s.sendall(_rcon_pack(1, 3, RCON_PASSWORD))

        auth_id = None
        for _ in range(3):
            request_id, response_type, _ = _rcon_recv(s)
            if response_type == 2:  #SERVERDATA_AUTH_RESPONSE
                auth_id = request_id
                break
            #type=0 (RESPONSE_VALUE) is an extra empty packet — skip and loop

        if auth_id is None:
            raise RconError("Did not receive AUTH_RESPONSE from service")
        if auth_id == -1:
            raise RconError("RCON authentication failed verify RCON_PASSWORD and service configuration")

        #Send command
        s.sendall(_rcon_pack(2, 2, command))
        _rid, _rtype, response = _rcon_recv(s)
        return response

# Connected-client counting
def client_count_rcon() -> int | None:
    """
    Query the service for the live connected-client count via the control channel.
    Returns an int, or None if the channel is unavailable.
    """
    try:
        #By convention, the "list" command returns a human-readable status line,
        #e.g. "There are 3 of a max of 20 clients online: alice, bob".
        response = rcon_command("list")
        match = re.search(r"There are\s+(\d+)\s+of a max", response, re.IGNORECASE)
        if match:
            return int(match.group(1))

        #Fallback: count identifiers after the colon (handles variant formats)
        if "online:" in response.lower():
            after = response.split(":", 1)[-1].strip()
            return len([entry for entry in after.split(",") if entry.strip()]) if after else 0

        log(f"Control-channel 'list' unexpected format: {response!r}")
        return 0

    except RconError as exc:
        log(f"RCON error: {exc}")
        return None
    except OSError as exc:
        log(f"RCON connection failed: {exc}")
        return None


def client_count_log_fallback() -> int:
    """
    Estimate connected clients from the application log.
    Unreliable after log rotation — used only as a last resort.
    """
    if not os.path.isfile(SERVICE_LOG):
        return 0
    try:
        with open(SERVICE_LOG, "r", errors="replace") as fh:
            text = fh.read()
        started = text.count("joined the session")
        ended = len(re.findall(r"left the session|lost connection", text))
        return max(0, started - ended)
    except OSError:
        return 0


def get_client_count() -> tuple[int, str]:
    """Returns (count, source) where source is 'rcon' or 'log-fallback'."""
    count = client_count_rcon()
    if count is not None:
        return count, "rcon"
    log("WARNING: control channel unavailable — falling back to log parsing (may be inaccurate)")
    return client_count_log_fallback(), "log-fallback"

#Port / service helpers
def service_port_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", SERVICE_PORT), timeout=2):
            return True
    except OSError:
        return False


def stop_service() -> None:
    log("Writing lockfile — signals any wake-on-demand proxy that this shutdown is intentional …")
    try:
        with open(LOCKFILE, "w") as fh:
            fh.write(f"shutdown by autoshutdown at {datetime.now().isoformat()}\n")
    except OSError as exc:
        log(f"Warning: could not write lockfile: {exc}")

    log(f"Running: sudo systemctl stop {SERVICE_NAME}")
    result = subprocess.run(
        ["sudo", "systemctl", "stop", SERVICE_NAME],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log(f"systemctl stop returned {result.returncode}: {result.stderr.strip()}")
    else:
        log("Service stopped. A wake-on-demand proxy can restart it on next client connection.")

# Clean exit
def _on_exit(signum=None, frame=None) -> None:
    log("Signal received — removing lockfile and exiting.")
    try:
        os.remove(LOCKFILE)
    except FileNotFoundError:
        pass
    sys.exit(0)


signal.signal(signal.SIGTERM, _on_exit)
signal.signal(signal.SIGINT, _on_exit)

# Main loop
def main() -> None:
    #Remove any stale lockfile from an abnormal previous exit
    try:
        os.remove(LOCKFILE)
        log("Removed stale lockfile from previous run.")
    except FileNotFoundError:
        pass

    log("=" * 60)
    log("Auto-shutdown monitor started.")
    log(f"  Service        : {SERVICE_NAME}.service")
    log(f"  Shutdown delay : {SHUTDOWN_DELAY}s | Poll interval : {CHECK_INTERVAL}s")
    log(f"  Control        : {RCON_HOST}:{RCON_PORT}")
    log(f"  Lockfile       : {LOCKFILE}")
    log("=" * 60)

    idle_since: float = 0.0   #monotonic clock time when the service last became idle

    while True:
        time.sleep(CHECK_INTERVAL)

        #1. Is the service port open?
        if not service_port_open():
            if idle_since:
                log("Port closed service appears offline. Resetting idle timer.")
                idle_since = 0.0
            continue

        #2. Service is up clear stale lockfile if present
        if os.path.exists(LOCKFILE):
            log("Service is back online removing lockfile.")
            try:
                os.remove(LOCKFILE)
            except FileNotFoundError:
                pass

        #3. Connected-client count
        count, source = get_client_count()
        now = time.monotonic()

        #4. Act on count
        if count > 0:
            if idle_since:
                log(f"Clients reconnected: {count} (via {source}) idle timer reset.")
            else:
                log(f"Clients connected: {count} (via {source}).")
            idle_since = 0.0

        else:
            if not idle_since:
                idle_since = now
                log(
                    f"Service idle (via {source}). "
                    f"Shutdown in {SHUTDOWN_DELAY}s if no clients connect."
                )
            else:
                idle = now - idle_since
                remaining = SHUTDOWN_DELAY - idle
                log(
                    f"Idle {idle:.0f}s / {SHUTDOWN_DELAY}s "
                    f"({remaining:.0f}s until shutdown, count via {source})."
                )

                if idle >= SHUTDOWN_DELAY:
                    log(f"Service idle for {idle:.0f}s — shutting down.")
                    stop_service()
                    idle_since = 0.0


if __name__ == "__main__":
    main()