Sample Structured Log Output

---

Authentication Event

RAW LOG:
[09May2026 22:21:28.140] [Server thread/INFO] [net.minecraft.server.players.PlayerList/]: OliBird00[<IP>] logged in with entity id 108266 at (6614.903378633761, 63.0, -3959.019824697843)

STRUCTURED LOG:
[AUTH EVENT]
User: OliBird00
Status: Successful login
Session ID: 108266
Position: (6614, 63, -3959)
Notes: Authentication successful. <IP>

---

Gameplay Event

RAW LOG:
[09May2026 22:21:47.434] [Server thread/INFO] [net.minecraft.server.MinecraftServer/]: gumgoos has made the advancement [Ice Bucket Challenge]

STRUCTURED LOG:
[GAME EVENT]
Player: gumgoos
Event: Advancement unlocked
Achievement: Ice Bucket Challenge

---

System Warning (Entity Desync)

RAW LOG:
[09May2026 22:21:55.224] [Server thread/WARN] [net.minecraft.world.level.entity.PersistentEntitySectionManager/]: Entity PokemonEntity['Wilbert'/100227, l='ServerLevel[world]', x=1411.50, y=91.91, z=-7404.82, removed=DISCARDED] wasn't found in section SectionPos{x=88, y=5, z=-463} (destroying due to DISCARDED)

STRUCTURED LOG:
[WARN - ENTITY SYSTEM]
Entity: PokemonEntity (Wilbert)
Status: Persistence mismatch detected
Location: Chunk section desync
Action: Entity discarded by PersistentEntitySectionManager

---

Movement Anomaly

RAW LOG:
[09May2026 22:21:32.605] [Server thread/WARN] [net.minecraft.server.network.ServerGamePacketListenerImpl/]: MoogerV2 moved too quickly! 27.218456240145315,-5.0,-7.4172348593034485

STRUCTURED LOG:
[WARN - PHYSICS]
Player: MoogerV2
Event: Movement threshold exceeded
Velocity spike detected
Status: Flagged by server movement validator
