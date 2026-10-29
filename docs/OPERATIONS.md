# Operating the Debian network-service lab

## Prerequisites

- Debian or another compatible Linux host with **Python 3.10+** and systemd.
- An existing service compatible with the published TCP handshake and RCON-style client counter.
- A private control interface and intentionally scoped firewall/tunnel rules.
- A service account with only the permissions required to inspect logs and request the target service's start/stop.

## Configuration map

The checked-in Python files contain illustrative, **nonworking placeholders**. Review and set the following in your own private deployment copy rather than committing real host configuration:

| File | Values to configure |
| --- | --- |
| [wake.py](../scripts/wake.py) | TCP listener \`PORT\`, \`SERVICE\` unit, readiness timeout, log/lock paths |
| [autoscale_shutdown.py](../scripts/autoscale_shutdown.py) | Service name/port, RCON host/port/password, log and lock paths, idle interval |
| [ufw_rules.conf](../configs/ufw_rules.conf) | Examples of default policies only; no executable firewall installation is included |

**Integration caution:** the two scripts currently use different lockfile names; reconcile lifecycle coordination before running them together. Also validate how the listener releases and reacquires its port when the real service starts and stops.

## Manual verification

1. Validate the service starts and stops with the intended restricted account and permissions.
2. Check that an offline status request receives the sleeping response without starting the service.
3. Check that a login-style request triggers startup and the readiness check completes before clients reconnect.
4. Validate connected-client detection and the idle timer while users are active, then after the last user leaves.
5. Simulate control-channel unavailability. Confirm warnings appear, and do **not** assume the log fallback gives an accurate client count.
6. Review systemd journal output and the script logs without publishing client addresses, session IDs, or personal player names.

These are **recommended tests**, not an assertion that an automated suite or a fresh-host deployment passed. Run private tests with disposable data and port/service names first.

## Troubleshooting

- **Cannot bind port:** the target service may already own it, or the process lacks permission.
- **Startup does not happen:** inspect the exact service name and narrowly scoped systemd permissions.
- **Unexpected idle stop:** inspect RCON parsing, reachability and recent log rotation; a fallback count can be wrong.
- **Missing log output:** verify log directory ownership and service account permissions.

[Back to project overview](../README.md) · [Topology](ARCHITECTURE.md) · [Security limits](../SECURITY.md).