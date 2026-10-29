# Architecture and topology

This lab coordinates a TCP **wake listener**, an application service managed by **systemd**, and an independent **idle monitor**. The checked-in scripts are configurable examples; the diagram illustrates their intended integration, not a verified live deployment.

## Service lifecycle

~~~mermaid
flowchart TD
    C["Remote client / status checker"]
    FW["Host firewall / optional external tunnel"]
    W["Python wake listener: scripts/wake.py"]
    SD["systemd service control"]
    S["Target TCP application service"]
    M["Python idle monitor: scripts/autoscale_shutdown.py"]
    R["RCON control channel (loopback preferred)"]
    L["Application logs (fallback)"]
    C -->|"TCP (configured port)"| FW
    FW --> W
    W -->|"Status probe: sleeping response"| C
    W -->|"Login-style request: systemctl start"| SD
    SD -->|"Start / stop"| S
    W -->|"Port readiness polling"| S
    C -->|"Reconnect after startup"| S
    M -->|"Connected-client query"| R
    R --> S
    M -.->|"If control query fails"| L
    L -.-> M
    M -->|"No clients beyond idle interval: stop"| SD
~~~

## Main components

- **Handshake parser:** [wake.py](../scripts/wake.py) decodes length-prefixed VarInt packets and distinguishes a status handshake from a login attempt. Unexpected or malformed packet types may trigger startup. After releasing the listener port, it requests systemd startup and checks readiness.
- **Idle policy:** [autoscale_shutdown.py](../scripts/autoscale_shutdown.py) polls every 30 seconds by default and requests a stop after 600 seconds with no clients, subject to configuration. It checks activity through an RCON-compatible command channel, with a log-derived fallback.
- **Firewall note:** [ufw_rules.conf](../configs/ufw_rules.conf) records example policy defaults only. No application of those rules, tunnel setup or firewall bypass prevention is established by this file.
- **Visibility:** [Event examples](../logs/Sample%20log%20output.md) and [RCON session examples](../logs/Automated%20shutdown%20logs.md) demonstrate how logs can be interpreted; there is no shipped Wazuh pipeline.

## Trust boundaries and operational risks

| Boundary | Important implication |
| --- | --- |
| Untrusted client → wake listener | This is a **wake trigger**, not user authentication. It can potentially be activated by unexpected traffic. |
| Python process → systemd | Start/stop must use narrowly scoped OS permissions, not unrestricted root execution. |
| Monitor → RCON | Keep the control endpoint private; RCON authentication is not transport encryption. |
| Log files → activity fallback | Log rotation, missing lines and unexpected formats can produce incorrect estimates. |

The wake and idle scripts also use different lockfile defaults. Their coordination is **not fully validated** by committed tests or service units. See [operations](OPERATIONS.md) and [security](../SECURITY.md).