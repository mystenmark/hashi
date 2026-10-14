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

- `GuardianLimiter` (one enclave session; leaders, proxy, enclave limiter,
  finalize certs, node mirrors). Run via `MC_GuardianLimiter.tla`.
  - `GuardianLimiterDedup.cfg`: NoDoubleConsume violated. A reconcile snap
    taken before the node observes a finalize puts its mirror one seq ahead;
    two leaders request one wid at seq n and n+1; both miss the proxy lookup.
    Confirms flagged point 5.
  - `GuardianLimiterDedupSeed.cfg` (no snapping while behind): same violation
    through a restart seed taken while a withdrawal is in flight. Confirms
    flagged point 22 leads to point 5.
  - `GuardianLimiterFutureOnly.cfg`: real-time rate bound with slack Future
    violated by a past timestamp, confirming review finding E1.
  - `GuardianLimiter.cfg`, `GuardianLimiterRateWide.cfg`: SeqRateBound and
    RealTimeRateBound with slack Past + Future pass (3.7M states).
  - Abstractions: one clock for enclave and nodes; any snap allowed when
    SnapBehind (the code waits about 5 minutes); snaps bounded by MaxSnaps.

- `Presig.cfg` (MaxIndex 3, MaxRand 4): passes, 107.5M distinct states,
  17 min.
- `DkgOutputs` (unit weights, 10 members, default 3333 bps: f = 3, t = 4,
  dealer cert 7, completion 7; the adversary picks the TOB prefix):
  - `DkgOutputs.cfg`: two Byzantine dealers hurt 4 honest members;
    honest holders plus Byzantine = 6 < 7. CanComplete violated.
  - `DkgOutputsOneByz.cfg`: one Byzantine dealer hurts 3 honest members and
    withholds its completion signature; honest holders = 6 < 7.
    HonestCanComplete violated.
  - `DkgOutputsComplaints.cfg`, `DkgOutputsOneByzComplaints.cfg`: pass.
  - Code check: a failed complaint recovery propagates an error
    (`mpc_except_signing.rs:1768-1775`), so the party has no output.

- `Bridge` (via `MC_Bridge.tla`):
  - `Bridge.cfg` (honest certs, faults on): all nine safety invariants pass,
    1.8M states. Coverage probes (`NeverConfirmed`, `NeverChained`,
    `NeverChildFirst`, `NeverBothWithdrawn` in `MC_Bridge.tla`) are all
    violated, so confirmation, chaining, and child-first are reachable.
  - `BridgeFee.cfg` (fee 1 per request): passes, 3.1M states.
  - `BridgeByzCerts.cfg` (arbitrary certs): chain-only invariants pass,
    127.4M states, 16 min.
  - `BridgeRecovery.cfg`, `BridgeRecoveryBacking.cfg`: RecordSound and
    Backing fail (F7).
  - `BridgeLive.cfg` (no faults, leader guard): liveness passes.
    `BridgeLiveRecovery.cfg`: WithdrawalCompletes fails (F6).
  - `BridgePausedBroadcast.cfg`: fails (F8).
- `Reconfig` (chain reconfig after genesis, node driver, Guardian committee
  chain):
  - `Reconfig.cfg`: all safety properties pass, 13.5M states.
  - `ReconfigNoGate.cfg`: Guardian adopts an aborted committee (F10).
  - `ReconfigLive.cfg`: HashiCatchesUp passes (no transient failures, no
    holds). With holds, governance toggling forever defeats liveness; that
    environment is unrealistic, so the config disables holds.
  - `ReconfigLiveTransient.cfg`: fails at the last Sui epoch (R9, F11).
  - `ReconfigGuardianLive.cfg`: GuardianCatchesUp fails (F9).
  - Not modelled: genesis, committee membership changes, governance votes.
- Validation: F1 reproduced in a Rust test on branch
  `mlogan-f1-dkg-complaint-test` (see FINDINGS.md F1).

## Remaining

- `Presig`: result of full config (`Presig.cfg`, MaxIndex 3, MaxRand 4).
  Consider modelling batches and seals explicitly so the residual case
  arises only from a digest mismatch plus a code change.
- Guardian: model sessions, heartbeat fence, S3 durability, and activation
  (safety 19); committee chain and proxy handoff gate (safety 16); liveness
  "consumed implies finalized".
- After the full system model: revisit `tla/FINDINGS.md` with code owners.
