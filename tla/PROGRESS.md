# TLA+ model of Hashi: progress

## Done

- Explored design docs, Move package, node, and Guardian.
- Wrote the informal protocol description in `tla/PROTOCOL.md`.

## Remaining

- Agree on module decomposition and abstractions (PROTOCOL.md section 13).
- Check that the TLA+ tools (tla2tools.jar / TLC, optionally Apalache) are
  installed.
- Write and check `Reconfig`.
- Write and check `Bridge`.
- Write and check `Presig`.
- Write and check `Guardian`.
- Triage flagged points (PROTOCOL.md section 12) against model results.
