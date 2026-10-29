# Security and disclosure boundaries

This repository demonstrates service lifecycle automation in a **personal lab**. It has not undergone an independent security assessment and should not be published as an authenticated proxy or production-grade service controller.

## Current design limitations

- The Python wake listener handles untrusted TCP packets. It can trigger startup on some unexpected or malformed input; it does **not** establish a client's identity.
- The control client uses an RCON-compatible protocol. Password authentication does not encrypt the network traffic. Keep RCON on loopback or a strictly trusted management network.
- The sample UFW file describes policy defaults, not an actual provisioning script or proof of enforcement.
- The idle script falls back to application logs if it cannot query the control channel. This can produce inaccurate client counts, particularly after log rotation.
- Neither fully integrated systemd units nor a validated automated test suite are committed. The wake/idle lockfile defaults differ.

## Avoid committing

Real host IPs or DNS names, public ports bound to a private machine, credentials, RCON passwords, player identities, world coordinates, private log extracts, access tokens, SSH keys, backup archives, and unredacted networking diagrams.

The [example logs](logs/Sample%20log%20output.md) are illustrative and use synthetic player identifiers. **Earlier Git history may contain the original sample material**; replacing a file in the latest commit does not remove it from historical commits.

If credentials ever appear in commits, rotate them and treat history remediation as a separate, reviewed operation. Do not publish credentials in public GitHub issues. No Wazuh/SIEM integration or production incident-response coverage is claimed.