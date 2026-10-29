# Debian Network Service Lab

A Python and systemd homelab exploring **wake-on-demand TCP services**, **idle shutdown**, and operational troubleshooting on Debian Linux. The scripts were written around a Minecraft-compatible connection protocol and an RCON-compatible control channel; the underlying techniques include sockets, binary parsing, subprocess management, timeouts and service-state checks.

[Architecture and topology](docs/ARCHITECTURE.md) · [Operations](docs/OPERATIONS.md) · [Security and limitations](SECURITY.md) · [Sample events](logs/Sample%20log%20output.md)

## How it works

1. [Wake listener](scripts/wake.py) binds a configured port while the application service is offline. Status probes receive a sleeping response; connection attempts can trigger systemd startup.
2. After requesting startup, the listener checks readiness on the service port. It does not itself operate as an authentication gateway.
3. [Idle monitor](scripts/autoscale_shutdown.py) checks the running service and queries a connected-client count through RCON. After a configured idle period, it requests systemd shutdown.
4. The monitor can fall back to estimating activity from application logs if RCON is unavailable. That fallback can be inaccurate.

The [topology diagram](docs/ARCHITECTURE.md) shows the lifecycle and operational trust boundaries.

## Implementation

| Component | Source | Technical focus |
| --- | --- | --- |
| TCP wake listener | [scripts/wake.py](scripts/wake.py) | Length-prefixed packets, VarInt decoding, status/login classification, socket and readiness timeouts |
| Idle monitor | [scripts/autoscale_shutdown.py](scripts/autoscale_shutdown.py) | RCON packet encoding/decoding, client activity estimation, monotonic idle timing, service stop requests |
| Firewall notes | [configs/ufw_rules.conf](configs/ufw_rules.conf) | Documented default-deny inbound policy and conceptual tunnel-based access |
| Operating procedure | [docs/OPERATIONS.md](docs/OPERATIONS.md) | Configuration, service permissions, observing logs and manual validation |
| Example records | [Shutdown events](logs/Automated%20shutdown%20logs.md) · [Parsed log examples](logs/Sample%20log%20output.md) | Interpreting operational events; samples are not proof of an implemented SIEM |

## Repository layout

~~~text
scripts/              Python networking and lifecycle monitoring
configs/              Documented firewall policy examples
logs/                 Sanitized, illustrative event samples
docs/
  ARCHITECTURE.md      Lifecycle and topology map
  OPERATIONS.md        Lab setup, operations and validation
SECURITY.md            Threat boundaries and known limitations
runbook.md             Backward-compatible operations entry point
~~~

## Scope

This is **lab source**, not a plug-and-play deployment. The published scripts contain placeholder ports, service names, RCON credentials and host paths. There are no complete systemd unit files, automated tests, or reproducible tunnel/firewall deployment in this repository. Integrating both scripts requires matching configuration and lock coordination before running on a host.

The documented UFW settings are **policy examples**, not a script that applies rules. RCON is a management protocol and is not inherently encrypted. Keep the control channel on a trusted interface, limit systemd privileges, and review [security notes](SECURITY.md) before connecting these scripts to real services.

Related work: [Ubuntu Network Service Lab](https://github.com/AlexV4981/Ubuntu-network-service-lab) demonstrates a Java Discord bot, a Python container controller, SQLite audit records and a separate event ingestion process.