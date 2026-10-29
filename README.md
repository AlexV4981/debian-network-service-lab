# Debian Network Service Lab

**Linux administration, Python networking, firewall policy, and service automation in a personal self-hosted lab.**

I built this project to manage a service that starts when clients connect and stops after an idle period. It combines TCP communication, systemd service control, documented access policies, and operational logging.

## Recruiter quick links: source first

- [Python TCP handshake and wake-on-demand listener](https://github.com/AlexV4981/debian-network-service-lab/blob/main/scripts/wake.py)
- [Python idle shutdown and RCON response checks](https://github.com/AlexV4981/debian-network-service-lab/blob/main/scripts/autoscale_shutdown.py)
- [Documented UFW firewall defaults](https://github.com/AlexV4981/debian-network-service-lab/blob/main/configs/ufw_rules.conf)
- [Operational runbook](https://github.com/AlexV4981/debian-network-service-lab/blob/main/runbook.md) · [Example logs](https://github.com/AlexV4981/debian-network-service-lab/blob/main/logs/Sample%20log%20output.md)

These are lab examples with placeholder deployment configuration; source code and documentation do not independently establish a tested production deployment.

## Explore the Project

### [Cybersecurity Skills & Code](#cybersecurity-skills--code)
Firewall defaults, control-channel authentication handling, protocol checks, and operational visibility.

### [Linux & Python Automation](#linux--python-automation)
Wake-on-demand networking, idle detection, service management, and troubleshooting.

For SQL and database examples, see the separate [Ubuntu database guide](https://github.com/AlexV4981/Ubuntu-network-service-lab/blob/main/DATABASE.md).

## Cybersecurity Skills & Code

| Skill | Direct evidence | What to review |
| --- | --- | --- |
| Firewall policy | [Documented firewall defaults](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/configs/ufw_rules.conf) | Default-deny inbound and forwarded traffic, outbound traffic allowed, and tunnel-based service access described in comments |
| Control-channel authentication handling | [RCON client and response handling](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/autoscale_shutdown.py) | Packet construction, authentication-response checks, socket timeouts, and explicit connection/authentication errors |
| Protocol handling | [TCP wake listener](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/wake.py) | Length-prefixed packet parsing, status-versus-login classification, handling of malformed packets, and loopback checks in the main listener |
| Operational visibility | [Shutdown monitor logging](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/autoscale_shutdown.py) · [Wake listener logging](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/wake.py) | Logs describing activity counts, fallback behavior, idle timers, startup, and readiness checks |

The firewall file documents policy defaults; it is not a complete executable UFW setup or proof of every deployed firewall rule. RCON authentication is a control-channel protocol feature, not evidence of encryption.

## Linux & Python Automation

### Wake-on-demand service startup

[Open `wake.py`](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/wake.py)

The listener holds a configured TCP port while the target service is offline. It handles status requests, identifies login-style connection attempts, releases the port, and requests service startup through `systemctl`. It then polls the local service port for readiness.

This demonstrates Python sockets, binary-protocol handling, subprocess calls, threading, timeouts, and coordination with systemd.

### Idle service shutdown

[Open `autoscale_shutdown.py`](https://github.com/AlexV4981/debian-network-service-lab/blob/a327d77e2d6beb2bcebb6eb1dc8ee338ba6d765a/scripts/autoscale_shutdown.py)

The monitor polls the service, queries connected-client counts through an RCON-compatible channel, and tracks an idle period with a monotonic timer. After the configured delay, it requests service shutdown and records the outcome. If the control channel is unavailable, it falls back to estimating activity from logs.

The public defaults are a 30-second polling interval and a 600-second idle period. Ports, service names, credentials, and paths must be configured for the target environment.

### Documentation and topology

- [Network topology](network_topology/topology.png)
- [Operational runbook](runbook.md)

The runbook contains earlier names such as `shutdown.py` and `hold.py`. The current source files are `scripts/autoscale_shutdown.py` and `scripts/wake.py`; use those as the implementation references.

## Deployment prerequisites

This repository contains configurable lab scripts rather than a complete installation package.

1. Use a Debian/Linux host with Python 3.10 or newer and systemd.
2. Configure the target service, listener port, control-channel port, credentials, and log locations. The public scripts intentionally use placeholder deployment settings.
3. Enable the service's RCON-compatible control channel where needed, and keep credentials out of public commits.
4. Configure appropriate permissions for log writes and narrowly scoped service start/stop operations.
5. Set and verify firewall/tunnel access for the intended clients.

The Python scripts use the standard library. Matching systemd unit files and a full reproducible firewall/tunnel installation are not included.

## Validation checkpoints

- Confirm the configured service can be started and stopped with the intended operating-system permissions.
- Confirm status probes and client connection attempts take the expected paths through the wake listener.
- Confirm active clients prevent idle shutdown and reconnecting clients reset the timer.
- Simulate a control-channel failure and inspect the fallback warning and behavior.
- Check startup-readiness logs and service output when troubleshooting.

These are suggested manual checks, not a claim of an automated test suite or a verified fresh-host deployment.

## Current scope and limitations

- The wake listener is not an authentication gateway. Some malformed or unexpected packets can trigger startup.
- The log-based activity fallback can miscount clients, especially after log rotation. Unexpected control-channel output can also be interpreted as zero clients.
- The public scripts use placeholder settings and different lockfile names; their integration needs configuration and validation.
- The repository's sample log documents illustrate event interpretation; they do not establish an implemented SIEM pipeline or production incident-response experience.
- Wazuh monitoring remains planned. Encryption, penetration testing, and a production security architecture are not demonstrated here.

## Related project

[Ubuntu Network Service and Security Lab](https://github.com/AlexV4981/Ubuntu-network-service-lab) adds Java/Discord role checks, a Python Flask controller, SQLite audit records, and incremental structured-event ingestion.

[Cybersecurity Skills & Code](https://github.com/AlexV4981/Ubuntu-network-service-lab/blob/main/CYBERSECURITY.md) · [Database Skills & Code](https://github.com/AlexV4981/Ubuntu-network-service-lab/blob/main/DATABASE.md)

