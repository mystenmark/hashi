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
  - `GuardianLimiter.cfg` (33k states), `GuardianLimiterRateWide.cfg` (3.7M
    states): SeqRateBound and RealTimeRateBound with slack Past + Future
    pass.
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
- F9 fix switch in `Reconfig` (`NoCommitteeFails`); reconcile is strongly
  fair. `ReconfigGuardianLiveFix.cfg` passes.
- `BridgeReconfig` (via `MC_BridgeReconfig.tla`): Reconfig drives Bridge's
  epoch and reconfiguring flag; the Guardian signs only on the current
  Hashi committee.
  - `BridgeReconfig.cfg`: Bridge and Reconfig safety plus
    `GuardianSignsCompleted` pass, 295k states. Probes reach Guardian
    signing, confirmation, and deposit confirmation after an epoch change.
  - `BridgeReconfigLive.cfg`: `WithdrawalCompletes` fails (F9 consequence).
  - `BridgeReconfigLiveFix.cfg`: all bridge and reconfig liveness passes.
  - `BridgeReconfigTwo.cfg` (two requests, two W): passes, 18.2M
    states.
  - R14 analysed: not separate from the PROTOCOL.md 2.4 stall.
- `GuardianLimiter` gains `gMax` and `Rotate` (`RotateTo`; equal to `Max`
  disables it). Existing configs give unchanged results.
- `BridgeLimiter` (via `MC_BridgeLimiter.tla`): commit-input-sigs, Guardian
  signing, and finalize are joint steps with the limiter.
  - `BridgeLimiter.cfg`: Bridge and limiter safety plus `GsigLogged`,
    `FinalizedLogged`, `SignableByGuardian` pass, 157k states. Probes reach
    one and two finalized withdrawals.
  - `BridgeLimiterRotate.cfg`: `SignableByGuardian` fails (F12).
  - `BridgeLimiterRotateStuck.cfg`: `StuckIsPermanent` and
    `StuckBlocksCommits` pass, 418k states.
  - R3 safety holds; R3 liveness not checked (bounded clock).
- `GuardianSessions` (via `MC_GuardianSessions.tla`): heartbeat fence,
  attempt timeout with late durability, activation scan, limiter recovery.
  Session `a` starts active; `b` may take over.
  - `GuardianSessions.cfg`: all pass, 62.2M states (with withdrawal ids). Probe reaches a
    handover with records from both sessions.
  - `GuardianSessionsAhead1.cfg`: pass, 74.4M states.
  - `GuardianSessionsAhead2.cfg`, `GuardianSessionsLate.cfg`: `UniqueSeq`
    fails (F13). `GuardianSessionsWriterAhead.cfg`: `OneWriter` fails.
  - `GuardianSessionsRollback.cfg` (three sessions, scaled fence):
    `RecoveryExact` fails (R12 rollback).
  - Not modelled: committee records.
- Validation: F1 reproduced in a Rust test on branch
  `mlogan-f1-dkg-complaint-test` (see FINDINGS.md F1). F2 reproduced on
  `mlogan-f2-guardian-double-sign-test`. F9 reproduced on
  `mlogan-f9-guardian-reconcile-gate-test`. F12 reproduced on
  `mlogan-f12-guardian-max-lowering-test`.
- R10: analysed by code (pause loop; removal via IgnoreMember).
- R16: analysed, liveness only (first seal wins on chain).
- Reorgs and R7: analysed, no new model (FINDINGS.md "Reorgs", R7 row).
- F13 host hold: checked by code and AWS docs. The hold is bounded near
  15 min only if headers and body share one TLS record; otherwise no
  documented bound. Writer retries the same key; model unaffected.

## Remaining

- F13: experiment (PUT through a byte-trickling proxy to a test bucket) to
  settle the hold bound. Needs a bucket and the user's go-ahead.
- After the full system model: revisit `tla/FINDINGS.md` with code owners.

## Done in this pass

- Reconfiguration end to end: `EventuallyCanComplete => HashiCatchesUp`
  and `=> GuardianCatchesUp` (F9 fix) pass with key generation allowed to
  fail; table in FINDINGS.md.

- Deposits end to end: `DepositMinted` holds with refiling, with
  reconfiguration; fails without refiling and with the pause loop. Table
  in FINDINGS.md.

- Guardian link: `GuardianSigns => RequestPaid` in Bridge without Guardian
  fairness; `ReadyConsumed` in `GuardianLimiterSeq`; `ReadyIsMpcRec` in
  `BridgeLimiter`. End-to-end table in FINDINGS.md.

- End-to-end `RequestPaid` holds in `Bridge` and in `BridgeReconfig` with
  the F9 fix; fails without it. Chain of supporting lemmas is listed in
  the session notes; remaining links: Guardian composition into Bridge
  fairness, and a fee model.
- `MpcSigning.tla`: signing liveness holds with up to one cumulative
  skipping node (7 members, 1 Byzantine); two skips on different batches
  stall the epoch (F14); an epoch change recovers.

- Guardian liveness: holds on `GuardianLimiterSeq` (seq-only abstraction),
  with refinement from `GuardianLimiter` checked on small configs. The
  full-model liveness run was stopped at 59M states.
- `GuardianSessions` now has withdrawal ids: the host alone releases two
  withdrawals at one seq (F13).
- `reduction/`: F1 and R10 margins on mainnet weights.

- `DkgRotation.tla`: removed Byzantine dealers in the rotation that removes
  them. One alone cannot block; one plus one offline new member can; two
  can.
- `GuardianLimiterByz.cfg`: one Byzantine member gets one wid consumed at
  three seqs (F2).
- `Presig.cfg` full config passed earlier (107.5M states); batches and
  seals closed by R16 analysis.
