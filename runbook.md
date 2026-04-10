# Self-Hosted Network Lab - Runbook

This runbook documents the setup, workflow, and monitoring procedures for the self-hosted network lab server. The system uses automated scripts to manage server uptime based on user activity.

---

## Workflow Overview

1. **Startup Process**
   - When the server service is started, the **shutdown monitoring script** (`shutdown.py`) also starts automatically.  
   - The **shutdown script** monitors server activity and, if no users are detected for 10 minutes, shuts the server down and reactivates the **hold script** (`hold.py`) to wait for new connections.  
   - This loop ensures the server only runs when needed, optimizing resources.

2. **Scripts**
   - `hold.py` Listens for an incoming connection on the server port and waits up to 10 minutes before booting the server.  
   - `shutdown.py` Monitors active users every 30 seconds and shuts down the server after 10 minutes of inactivity.  

---

## Starting the Server

Use the non-root server user:

```bash
sudo -u <serveruser> systemctl start <server_name>.service

---
## Stopping the server
