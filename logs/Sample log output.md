# Illustrative service-event examples

The following are **synthetic, privacy-safe examples**, modeled on common server log formats. They are not a reproducible security detection test, actual private gameplay evidence, or a shipped SIEM pipeline.

## Connection event

**Example source:**

~~~text
[01Jan2026 12:00:00.000] [Server thread/INFO] [net.minecraft.server.players.PlayerList/]: example-player[<REDACTED_IP>] logged in with entity id 100 at (<REDACTED_POSITION>)
~~~

**Example interpretation:**

~~~text
[CONNECTION EVENT]
Actor: example-player (synthetic)
Status: Login observed
Network address: redacted
Location: redacted
~~~

## Gameplay event

~~~text
[01Jan2026 12:00:05.000] [Server thread/INFO] [net.minecraft.server.MinecraftServer/]: example-player has made a generic advancement
~~~

A source line may record gameplay activity. Do not treat a gameplay event as proof of authentication or authorization.

## Application warning

~~~text
[01Jan2026 12:00:10.000] [Server thread/WARN] [net.minecraft.world.level.entity.PersistentEntitySectionManager/]: ExampleEntity removed because its stored region state could not be found
~~~

Interpretation: an application warning that may need investigation; not independently an intrusion indicator.

## Movement warning

~~~text
[01Jan2026 12:00:15.000] [Server thread/WARN] [net.minecraft.server.network.ServerGamePacketListenerImpl/]: example-player moved too quickly! <REDACTED_VECTOR>
~~~

Interpretation: a game movement sanity-check warning, not a confirmed malicious event.

These examples describe **manual log interpretation**. A parser producing these event summaries, an active Wazuh agent, and a completed intrusion-detection pipeline are **not implemented** in this repository. See [the Python monitor](../scripts/autoscale_shutdown.py) for the actual log-fallback code.