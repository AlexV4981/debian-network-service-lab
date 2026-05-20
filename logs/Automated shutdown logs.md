RCON Shutdown Log Overview

Log Group: RCON Client Shutdown (Session #95)
[14May2026 13:08:49.210] [RCON Client /localhost #95/INFO] Thread RCON Client /localhost shutting down

What this shows:
An active RCON session was closed. This typically happens when a remote console command finishes executing or when a client disconnects normally.

Purpose of this event:
To confirm the end of an administrative or automated RCON session.

---

Log Group: RCON Client Start + Immediate Shutdown (Session #96)
[14May2026 13:09:19.213] Thread RCON Client /localhost started
[14May2026 13:09:19.213] Thread RCON Client /localhost shutting down

What this shows:
An RCON client connection was created and then terminated almost immediately.

Purpose of this event:
This usually indicates an automated process such as a script or health check that opens an RCON connection, performs a quick action, and then closes it.

---

Log Group: Repeated RCON Cycle (Session #97)
[14May2026 13:09:49.215] Thread RCON Client /localhost started
[14May2026 13:09:49.216] Thread RCON Client /localhost shutting down

What this shows:
The same pattern repeats: RCON starts, then immediately shuts down.

Purpose of this event:
Indicates a looping or scheduled automation process interacting with the server through RCON.
