#!/usr/bin/env python3
"""

Target: Debian 13 / systemd

Holds a configured TCP port while the target service is offline.
Correctly handles the length-prefixed binary protocol:
  next_state=1 (Status/ping) -> returns a JSON "sleeping" status response
  next_state=2 (Login)       -> sends a Disconnect packet, then starts service
  Legacy pings (0xFE)        -> minimal response so old clients don't hang
  Loopback (127.0.0.1/::1)  -> silently dropped (health checks)

No external dependencies.
"""

import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime

# Config

PORT       = 0        #TCP port the proxy listens on (set to your service's port)
SERVICE    = ".service"
BOOT_WAIT  = 120      #max seconds to poll after starting service
LOCKFILE   = "/tmp/.wake_proxy.lock"
LOG_FILE   = "/var/log/wake-proxy.log"

#Returned in the status response while the service is offline.
#protocol -1 causes compatible clients to show the version string as is.
SLEEP_STATUS = json.dumps({
    "version": {"name": "Sleeping connect to wake!", "protocol": -1},
    "players": {"max": 0, "online": 0, "sample": []},
    "description": {"text": "Service is sleeping connect to wake it up."},
    "enforcesSecureChat": False,
})

#Disconnect message sent to clients that attempt a full login
DISCONNECT_MESSAGE = "Service is starting up.\nPlease wait about 90 seconds, then reconnect."

# Thread-safe logging

_log_lock = threading.Lock()

def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [wake-proxy] {msg}"
    with _log_lock:
        print(line, flush=True)
        try:
            with open(LOG_FILE, "a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

#VarInt codec (length-prefixed integer encoding used by the protocol)
def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value, shift = 0, 0
    while True:
        if offset >= len(data):
            raise ValueError("VarInt truncated")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
        if shift >= 35:
            raise ValueError("VarInt > 32 bits")

def encode_varint(n: int) -> bytes:
    out = b""
    n &= 0xFFFFFFFF
    while True:
        part = n & 0x7F
        n >>= 7
        out += bytes([part | (0x80 if n else 0)])
        if not n:
            return out

def encode_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return encode_varint(len(b)) + b

def make_packet(packet_id: int, payload: bytes) -> bytes:
    body = encode_varint(packet_id) + payload
    return encode_varint(len(body)) + body

#Reliable socket I/O
def recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf

def read_packet(sock: socket.socket, timeout: float = 3.0) -> bytes | None:
    """Read one length-prefixed packet. Returns body bytes or None."""
    sock.settimeout(timeout)
    try:
        raw = b""
        for _ in range(5):
            b = sock.recv(1)
            if not b:
                return None
            raw += b
            try:
                length, consumed = decode_varint(raw, 0)
                break
            except ValueError:
                continue
        else:
            return None

        already = raw[consumed:]
        remaining = length - len(already)
        if remaining < 0:
            return None
        rest = recv_exactly(sock, remaining) if remaining else b""
        if rest is None:
            return None
        return already + rest

    except (OSError, socket.timeout):
        return None

# Protocol response handlers
def handle_status_request(sock: socket.socket) -> None:
    """
    Respond to a status/ping handshake with a JSON status payload.
    Handshake sequence:
      C->S  Status Request  (0x00)
      S->C  Status Response (0x00, JSON)
      C->S  Ping Request    (0x01, 8-byte payload)  [optional]
      S->C  Pong Response   (0x01, same 8 bytes)
    """
    read_packet(sock, timeout=2.0)   #discard Status Request
    sock.sendall(make_packet(0x00, encode_string(SLEEP_STATUS)))
    ping = read_packet(sock, timeout=2.0)
    if ping:
        try:
            pkt_id, off = decode_varint(ping, 0)
            if pkt_id == 0x01 and len(ping) - off >= 8:
                sock.sendall(make_packet(0x01, ping[off:off + 8]))
        except (ValueError, OSError):
            pass

def handle_login_request(sock: socket.socket) -> None:
    """Send a login-state Disconnect packet (0x00) with a JSON reason string."""
    reason = json.dumps({"text": DISCONNECT_MESSAGE})
    try:
        sock.sendall(make_packet(0x00, encode_string(reason)))
    except OSError:
        pass

def handle_legacy_ping(sock: socket.socket) -> None:
    """Respond to legacy-format status pings (first byte 0xFE) so clients don't hang."""
    fields = "\x001\x00Service Starting\x00Waking up — reconnect in ~90s\x000\x000"
    encoded = fields.encode("utf-16-be")
    length = len(fields).to_bytes(2, "big")
    try:
        sock.sendall(b"\xff" + length + encoded)
    except OSError:
        pass

#Handshake classifier
def classify_and_respond(conn: socket.socket, addr: tuple) -> bool:
    """
    Parse the opening handshake and respond appropriately.
    Returns True  if this is a real connection attempt (trigger service start).
    Returns False for status probes, health checks, or unrecognised traffic.
    """
    try:
        data = read_packet(conn, timeout=3.0)
        if not data:
            return False

        # Legacy-format ping
        if data[0:1] == b"\xfe":
            handle_legacy_ping(conn)
            return False

        try:
            pkt_id, off = decode_varint(data, 0)
        except ValueError:
            return True  #unreadable -> wake defensively

        if pkt_id != 0x00:
            log(f"Unexpected opening packet 0x{pkt_id:02X} from {addr[0]}")
            return True

        #Parse Handshake fields: VarInt proto | String host | UShort port | VarInt nextState
        try:
            _proto, off  = decode_varint(data, off)
            addr_len, off = decode_varint(data, off)
            off += addr_len + 2          #skip host string + port bytes
            next_state, _ = decode_varint(data, off)
        except (ValueError, IndexError):
            log(f"Malformed handshake from {addr[0]}")
            return True

        if next_state == 1:
            handle_status_request(conn)
            return False
        elif next_state == 2:
            log(f"Connection attempt from {addr[0]}:{addr[1]}")
            handle_login_request(conn)
            return True
        else:
            log(f"Unknown next_state={next_state} from {addr[0]}")
            return False

    except Exception as exc:
        log(f"Error handling {addr[0]}: {exc}")
        return False
    finally:
        try:
            conn.close()
        except OSError:
            pass

# Wake / service-start logic
def service_is_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=2):
            return True
    except OSError:
        return False

def release_port_and_start_service(proxy: socket.socket) -> None:
    """
    Release the proxy socket before starting the target service so the
    service can bind the same port without a conflict.
    """
    log(f"Releasing port {PORT} and starting {SERVICE}")
    for fn in (proxy.shutdown, proxy.close):
        try:
            fn(socket.SHUT_RDWR) if fn == proxy.shutdown else fn()
        except OSError:
            pass

    subprocess.run(["sudo", "systemctl", "start", SERVICE], check=False)
    try:
        os.remove(LOCKFILE)
    except FileNotFoundError:
        pass

    log(f"Polling for service readiness (up to {BOOT_WAIT}s) …")
    for elapsed in range(1, BOOT_WAIT + 1):
        time.sleep(1)
        if service_is_up():
            log(f"Service ready after {elapsed}s. Proxy exiting.")
            return
    log("WARNING: Service did not become ready in time; systemd will restart this proxy.")

_wake_requested = threading.Event()

def connection_handler(conn: socket.socket, addr: tuple,
                       proxy: socket.socket) -> None:
    is_real_client = classify_and_respond(conn, addr)
    if is_real_client and not _wake_requested.is_set():
        _wake_requested.set()
        release_port_and_start_service(proxy)  #closes proxy -> main loop exits via OSError

# Main loop
def run_proxy() -> None:
    log("=" * 60)
    log(f"Wake proxy started — holding port {PORT} for {SERVICE}")
    log("=" * 60)

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass

    proxy.bind(("", PORT))
    proxy.listen(8)
    proxy.settimeout(10)

    while True:
        try:
            conn, addr = proxy.accept()
        except socket.timeout:
            continue
        except OSError:
            return  #proxy was closed by release_port_and_start_service

        if addr[0] in ("127.0.0.1", "::1"):
            try:
                conn.close()
            except OSError:
                pass
            continue

        log(f"Connection from {addr[0]}:{addr[1]}")
        threading.Thread(
            target=connection_handler,
            args=(conn, addr, proxy),
            daemon=True,
        ).start()

if __name__ == "__main__":
    if service_is_up():
        log("Service already running waiting for it to stop before taking port")
        while service_is_up():
            time.sleep(10)
    run_proxy()