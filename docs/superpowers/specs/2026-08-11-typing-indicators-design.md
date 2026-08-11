# Typing Indicators + Leave Button Placement

Date: 2026-08-11

## Decisions

| Choice | Decision |
|--------|----------|
| Typing copy | Above composer: 1 / 2 / “Several people…”; exclude self |
| Backend | Existing `RoomServer.set_typing` + `m.typing` ephemeral PubSub |
| Throttle | Refresh typing true at most every 2s while composer non-empty |
| Leave | Bottom of Room Info panel only (not chat header) |

## Tests

- Unit: `TypingLabel` formatting / mxid filtering
- Existing RoomServer typing unit coverage
- Browser: leave control in Room Info footer, absent from header
