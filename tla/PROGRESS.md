# TLA+ model of Hashi: progress

## Done

- Explored design docs, Move package, node, and Guardian.
- Wrote the informal protocol description in `tla/PROTOCOL.md`.
- Four sub-agents reviewed PROTOCOL.md against the code (reconfig/governance,
  bridge, MPC/presig, Guardian). Folded their errors, omissions, and property
  corrections into the document. Section 12 now records a status per flagged
  point.
- Installed OpenJDK 21 (Homebrew) and tla2tools.jar v1.7.4 in
  `~/.local/share/tla/`. Run TLC with `tla/tlc.sh -config X.cfg X.tla`.
- `Presig` (first cut):
  - `PresigSmall.cfg` (MaxIndex 2, MaxRand 3): passes all invariants,
    3.9M distinct states, 35 s.
  - `PresigNoTagCheck.cfg`: NonceSafety violated (stale slot signed with the
    new epoch's pool), as expected.
  - `PresigCodeChange.cfg`: NonceSafety violated (index-to-presignature map
    changes across restart), confirming PROTOCOL.md 8.5 residual case.
  - Abstractions: batches, seals, and digest mismatch are folded into the
    per-node map; `RecordSig` is nondeterministic; signers are honest nodes
    and any member may request a signature.

## Remaining

- `Presig`: result of full config (`Presig.cfg`, MaxIndex 3, MaxRand 4).
  Consider modelling batches and seals explicitly so the residual case
  arises only from a digest mismatch plus a code change.
- Write and check `Guardian`.
- Write and check `Reconfig`.
- Write and check `Bridge`.
- Triage flagged points (PROTOCOL.md section 12) against model results.
