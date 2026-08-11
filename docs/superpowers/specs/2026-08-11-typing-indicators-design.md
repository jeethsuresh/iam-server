# Typing Indicators + Leave Button Placement

Date: 2026-08-11

## Decisions

| Choice | Decision |
|--------|----------|
| Typing copy | Above composer: 1 / 2 / “Several people”; exclude self; animated dots |
| Backend | Existing `RoomServer.set_typing` + `m.typing` ephemeral PubSub |
| Idle | Clear typing after 2s with no composer changes (text may remain) |
| Throttle | Refresh typing true at most every 1.5s while actively typing |
| Server TTL | ~4s backup if client never sends typing false |
| Leave | Bottom of Room Info panel only (not chat header) |

## Tests

- Unit: `TypingLabel` formatting / mxid filtering
- Existing RoomServer typing unit coverage
- Browser: leave control in Room Info footer, absent from header
