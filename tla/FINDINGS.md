# Findings

This file records findings from the TLA+ models and the code review behind
`PROTOCOL.md`. Each finding needs confirmation from the owners of the code
before anyone acts on it. We will return to these after the full system model
is complete.

Status values: **model-confirmed** (TLC produced a trace and the code was
checked), **review-confirmed** (reviewers traced it in code; no model yet),
**closed** (the model shows the property holds).

## Model findings

### F1. One Byzantine member can block every DKG and key rotation

- **Status:** model-confirmed. Severity: liveness of the whole bridge.
- **Model:** `DkgOutputs.tla`, configs `DkgOutputs.cfg`,
  `DkgOutputsOneByz.cfg`. Controls: `DkgOutputsComplaints.cfg`,
  `DkgOutputsOneByzComplaints.cfg` pass.
- **Setting:** default `mpc_max_faulty_in_basis_points = 3333`
  (`core/mpc_config.move:18`) and the default complaint policy, which answers
  no complaints (`crates/hashi/src/config.rs:253-262`).
- **Mechanism:**
  1. A dealer certificate needs `t + f` of reduced weight. Byzantine receivers
     always sign, so a Byzantine dealer can give bad shares to up to
     `W - t - f = f` of honest weight and still get a certificate.
  2. The adversary orders the TOB, so its certificate can land in the
     selected prefix.
  3. An honest party with bad shares from a selected dealer sends complaints.
     Nobody answers. `recover_dkg_shares_via_complaint(...).await?` fails
     (`mpc_except_signing.rs:1768-1775`, error at `:4572`), so the party never
     gets an output. Rotation follows the same path (`:2084`).
  4. The Byzantine member withholds its completion signature.
- **Trace (10 unit-weight members, f = 3, t = 4, completion 7):** one
  Byzantine dealer hurts 3 honest members. Honest holders = 6 < 7. With two
  Byzantine dealers, even if both sign, holders plus Byzantine = 6 < 7.
- **Consequence:** completion cannot gather 2/3. The pending reconfiguration
  aborts when the Sui epoch ends, and the next one can be blocked the same
  way. While a reconfiguration is pending, every BTC committee step except
  `confirm_withdrawal` stops (`PROTOCOL.md` 2.4). At genesis no old committee
  exists to fall back on.
- **Context:** the config comment says allow-listing a dealer "can leak
  private shares to the dealer". The policy is therefore a deliberate
  trade-off; the open question is whether this impact was accounted for.
- **Open questions:** Does weight reduction change the bound in practice? Is
  there an operator runbook for populating the allow-list during an attack?
  Could the protocol exclude a dealer with verified complaints from the
  prefix instead of answering complaints?

### F2. A withdrawal can be signed twice by the Guardian, debiting the limiter twice

- **Status:** model-confirmed. Severity: limiter accounting and liveness. No
  extra BTC moves, because both signatures cover the same transaction.
- **Model:** `GuardianLimiter.tla` via `MC_GuardianLimiter.tla`, configs
  `GuardianLimiterDedup.cfg` and `GuardianLimiterDedupSeed.cfg`. Invariant
  `NoDoubleConsume`.
- **Mechanism:**
  1. A node's limiter mirror gets one `seq` ahead of the Guardian. Two paths
     reach this:
     - **Seed:** a node restarts and seeds its mirror from `GetGuardianInfo`
       while a withdrawal is in flight. The Guardian has already consumed it.
       When the finalize lands, the mirror applies it again
       (`lib.rs:1043-1061`, `onchain/mirror.rs:529`).
     - **Snap:** reconcile snaps the mirror to the Guardian before the node
       has applied a finalize it has not yet observed.
  2. Two leaders (turns overlap) request the same wid, at `seq = n` and
     `seq = n + 1`.
  3. The proxy looks the wid up, misses for both, and forwards both. Lookup
     and forward are not atomic (`hashi-guardian-proxy/src/node/cache.rs:153-185`).
  4. The enclave has no wid dedup. It signs at `n`, then at `n + 1`.
- **Consequence:** the limiter is debited twice for one transaction. The
  surplus `seq` leaves node mirrors and the Guardian out of step until the
  next reconcile, which stalls withdrawals for about 5 minutes.
- **Fix directions:** dedup by wid inside the enclave, or make the proxy's
  lookup-and-forward atomic per wid; do not double-apply a seeded consume.

### F3. The rate-limit bound must include the past timestamp window

- **Status:** model-confirmed. Severity: documentation of the security bound.
- **Model:** `GuardianLimiter.tla`, config `GuardianLimiterFutureOnly.cfg`
  (fails) and `GuardianLimiter.cfg`, `GuardianLimiterRateWide.cfg` (pass).
- **Mechanism:** the enclave accepts `ts` in `[now - 1800 s, now + 300 s]`
  (`standard_withdrawal.rs:19-21, 99-114`). The limiter refills by `ts`, not by
  enclave time. A request with an old `ts` drains the bucket; requests with
  later `ts` refill it at the same enclave time.
- **Trace:** at enclave time 3, records with `ts = 1` and `ts = 3` each release
  2 units; 4 > `max + rate * future` = 3.
- **Correct bound:** outflow during any enclave-time window is at most
  `max + rate * (window + 2100 s)`. With an honest committee, signers bound
  `ts` to within 600 s of their checkpoint time (`withdrawals.rs:68, 944-952`),
  which gives `max + rate * (window + 900 s)`. Both hold for one limiter
  config; a Guardian rotation can change `max` and `rate`.

### F4. Nonce reuse after a code change in the middle of an epoch

- **Status:** model-confirmed for the abstract mechanism; the concrete code
  path needs owner confirmation. Severity: key-share leak for one node,
  narrow preconditions.
- **Model:** `Presig.tla`, config `PresigCodeChange.cfg` (fails);
  `Presig.cfg` (passes, 107.5M states) with the map fixed.
- **Mechanism:** a node maps a global presig index to a local presignature by
  cumulative batch sizes, which come from code (`BATCH_SIZE_PER_WEIGHT`,
  admission rules; `service.rs:2495-2502`, `signing.rs:914-960`). The seal
  stores only the dealer-set digest. Scenario:
  1. A node's digest for batch `k` disagrees with the seal, so its size for
     batch `k` differs from the canonical size.
  2. Its digest for batch `k + 1` matches. It signs index `g1` with local
     position `p`.
  3. An upgrade in the same epoch changes the size computation. After restart,
     `p` maps to index `g2`, which is re-enabled.
  4. The node signs a different request with presignature `p`.
- **Fix direction:** put the batch size or start index in the seal, or check
  local start indices against seal-derived sizes.

### F5. Nonce safety holds under the stated assumptions

- **Status:** closed for the model's scope.
- **Model:** `Presig.cfg` passes `NonceSafety`, `UniquePendingIndex`,
  `PendingBelowAlloc`, `TagNotAhead`, `ViewNotAhead`.
- **Scope:** honest nodes with lagging views, crash and restart, epoch change
  and abort, reallocation, nondeterministic recording of signatures. The
  epoch-tag check is necessary: `PresigNoTagCheck.cfg` fails.
- **Not yet modelled:** explicit batches and seals, digest mismatch.

## Review findings not yet modelled

These come from the sub-agent code review (`PROTOCOL.md` section 12). They
are review-confirmed unless marked otherwise.

| # | Finding | Where to model |
|---|---|---|
| R1 | The Guardian follows any handoff signed by its current committee. Honest members sign handoffs to targets that are later aborted. Only the proxy gate, which matches by epoch numbers and trusts its fullnode, stops adoption. | `Reconfig` + Guardian committee chain |
| R2 | Followers check neither pause nor reconfiguration on the MPC signing RPC, the input-signature cert, or the Guardian-request cert. One Byzantine member can obtain Guardian signatures while paused and broadcast an MPC-complete transaction without `finalize_withdrawal`. | `Bridge` |
| R3 | The Guardian-request certificate is signed after checking only `W` exists and the timestamp. The limiter check happens later, at finalize, after the Guardian has consumed tokens. | `GuardianLimiter` (partly modelled) |
| R4 | "One unsigned `W` at a time" is enforced only off chain. Concurrent leaders can commit several. A `W` that never becomes fully signed blocks all later commits by honest leaders. | `Bridge` |
| R5 | Burn happens at commit; no cancel or replace path exists. A `W` with an input that is invalid on Bitcoin (conflicting spend, deep reorg, recovery spend) reaches FullySigned and rebroadcasts forever; hBTC stays burned and chained children are stranded. | `Bridge` |
| R6 | The 60-day recovery leaf lets the MPC key alone spend pool UTXOs, bypassing the Guardian and the limiter. Consolidation of old UTXOs is best effort. | `Bridge` |
| R7 | Change outputs are not validated on chain (address, amount, txid). Relies on an honest 2/3. | `Bridge` |
| R8 | A Guardian committee push that runs while the Guardian is not activated still sets the per-epoch gate. Finalize stalls until the next Hashi epoch. | `Reconfig` + Guardian |
| R9 | `start_reconfig` triggers make at most 3 attempts. Clearing `reconfig_hold` triggers nothing. | `Reconfig` |
| R10 | A member with 5% weight can pause alone; more than 1/3 can block unpause. | `Reconfig` / governance |
| R11 | Limiter config is per Guardian session; activation only caps tokens. A rotation can raise `max` or `rate`. | Guardian sessions |
| R12 | Limiter recovery at activation reads only two hour directories. Writer-ahead clock skew above about 1 hour can roll back `seq` and tokens or allow a second activation. | Guardian sessions |
| R13 | Proxy replay data is kept 30 days; a retry after that consumes tokens again. | Guardian sessions |
| R14 | Repeated reconfigurations re-approve deposits and restart the delay, which can starve confirmation. | `Bridge` |
| R15 | The node panics on any unclassified Move abort in `end_reconfig`. | `Reconfig` |
| R16 | Seal signatures are kept in memory only; after a restart a node may sign a different dealer-set digest. Liveness only. | `Presig` (batches) |
