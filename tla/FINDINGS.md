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

- **Status:** reproduced in a Rust test (DKG). Severity: liveness of the
  whole bridge until operators act.
- **Test:** branch `mlogan-f1-dkg-complaint-test` (commit `ed9512e8`),
  `crates/hashi/src/mpc/mpc_except_signing_tests.rs`:
  `test_dkg_byzantine_dealer_blocks_completion_under_deny_all_policy` and
  the contrast `test_dkg_byzantine_dealer_recovered_under_allow_all_policy`.
  Ten unit-weight members; dealer 0 corrupts shares for members 1-3 and its
  certificate is first in TOB order. Under deny-all, members 1-3 fail with
  "Not enough valid complaint responses" and members 4-9 (weight 6) hold
  outputs; the completion threshold is 7. Under allow-all, all 9 honest
  members produce the same key. The test drives the real receiver,
  `run_dkg`, and `handle_complain_request` paths.
- **Refinements from the test:** the failed recovery aborts the whole party
  phase; the party does not move on to later dealers. Each complaint is
  retried up to 10 times, and `handle_reconfig` then retries the protocol
  until the window closes, hitting the same denial each time. Recovery
  requires operators to allow-list `(epoch, dealer)` or the epoch to end in
  an abort. Rotation uses the same `?` pattern but was not tested.
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

### F4. Nonce reuse if batch derivation changes within an epoch

- **Status:** model-confirmed for the abstract mechanism; downgraded to a
  hardening suggestion after code review. Severity if triggered: key-share
  leak for one node.
- **Model:** `Presig.tla`, config `PresigCodeChange.cfg` (fails);
  `Presig.cfg` (passes, 107.5M states) with the map fixed.
- **Mechanism:** a node maps a global presig index to a local position by
  cumulative installed batch sizes (`signing.rs:920-950`). After a restart,
  recovery disables indices using the new binary's map; nothing records
  which presignature an index used. If a release changes the size of an
  installed batch below an index the node already signed, a still-Pending
  index can resolve to the used position and sign a second request.
- **Why it is unlikely:** `BATCH_SIZE_PER_WEIGHT` has been 10 since it was
  introduced (`cc3845c6`), and its override is rejected on mainnet and
  testnet (`lib.rs:740-749`). The reviewer's digest-mismatch precondition is
  largely closed: batches with node-local skips are discarded
  (`service.rs:831-837`), sizes are checked against admitted weight
  (`service.rs:856-860`), and batches install contiguously. The admission
  rules that set batch sizes have changed in releases (#841, its revert,
  #953), but the team gated a past derivation change on an activation epoch
  "chosen at least one epoch ahead" (removed in `bb3f6811`), which is the
  discipline that rules this out.
- **Suggestion:** persist each installed batch's start index and size per
  epoch, and refuse to install a different one after a restart in the same
  epoch. This turns a silent leak into a loud failure if a future release
  gets the gating wrong.

### F5. Nonce safety holds under the stated assumptions

- **Status:** closed for the model's scope.
- **Model:** `Presig.cfg` passes `NonceSafety`, `UniquePendingIndex`,
  `PendingBelowAlloc`, `TagNotAhead`, `ViewNotAhead`.
- **Scope:** honest nodes with lagging views, crash and restart, epoch change
  and abort, reallocation, nondeterministic recording of signatures. The
  epoch-tag check is necessary: `PresigNoTagCheck.cfg` fails.
- **Not yet modelled:** explicit batches and seals, digest mismatch.

### F6. Merged into F7

The stranded-withdrawal sequence that was F6 is the aftermath of F7 and is
described there.

### F7. The Guardian's protection of a pool UTXO lapses after 60 days

- **Status:** review-confirmed design analysis; the aftermath is
  model-confirmed. Severity: a compromised or colluding committee (current,
  or past with retained key material) can spend idle pool funds without the
  Guardian or the rate limiter; unrelated users' withdrawals are stranded
  afterwards.
- **Model:** `Bridge.tla` via `MC_Bridge.tla`. `BridgeRecovery.cfg`
  (`RecordSound` fails), `BridgeRecoveryBacking.cfg` (`Backing` fails), and
  `BridgeLiveRecovery.cfg` (`WithdrawalCompletes` fails) show the effect of a
  recovery spend. The model does not represent committees or key shares;
  the facts below come from the code and design docs.

**Facts.**

1. **Recovery leaf.** Every pool UTXO, deposit and change alike, is
   `tr(NUMS, {multi_a(2, guardian, h), and_v(older(60 days), pk(h))})`
   (`design/docs/address-scheme.mdx`, `deposits.rs:403-406`). The MPC key
   alone can spend it 60 days after it confirms: no Guardian signature, no
   limiter, no onchain step.
2. **Rotation keeps the key.** Key rotation reshares the same group key; the
   new key must equal the old one (`mpc_except_signing.rs:4936-4945`,
   `committee_set.move:501`). Shares from any past committee that meet that
   committee's threshold reconstruct today's key.
3. **Refresh is opportunistic.** Only spending a UTXO resets its 60-day
   clock. Old UTXOs (more than 4,320 blocks, about 30 days;
   `utxo_pool/mod.rs:66`) are prioritised only as extra consolidation inputs
   to a withdrawal that is already being built, and only when it has change,
   the fee rate is below the high threshold, and the batch is under its
   per-request input cap (`utxo_pool/mod.rs:880-893`). No dedicated refresh
   transaction exists.
4. **Old key material is erased on a schedule.** Shares are rebuilt from a
   node's per-epoch encryption keys plus dealer and rotation messages. The
   live database keeps those for the target, previous, and preceding
   committees plus 7 epochs (`db.rs:627-655`, `service.rs`
   `build_pruning_references`). Epoch backups contain them
   (`db.rs:131-148`) and are deleted locally after 14 days, 30 for the
   newest (`backup.rs:50-52`); the documented S3 lifecycle target is also
   14 days (`design/docs/node-backup.mdx`). The same doc says "Keep
   longer-term copies elsewhere", does not sweep a decommissioned host's
   archives, and notes S3 expiry is "not guaranteed deletion on day 14".

**Consequence.** The Guardian exists "to protect against vulnerabilities and
against malicious past committees" (`design/docs/guardian.mdx`). For any
UTXO older than 60 days that protection is gone:

- **Current committee.** Members holding threshold weight who collude, or
  whose nodes are compromised, can spend it directly on Bitcoin. This is
  the committee compromise the Guardian is meant to stop.
- **Past committees.** With the erasure policy followed, old material is
  gone within about 2-4 weeks, before the 60-day delay opens. Members who
  kept it, or material that survived in long-term backup copies,
  decommissioned hosts, or unexpired S3 versions, can do the same. The set
  of such groups grows with every epoch.

Idle funds are the most exposed: in a quiet period, or while high fees
disable consolidation, pool UTXOs age past 60 days.

**Aftermath: stranded withdrawals.** Hashi does not detect the spend. The
stolen outputs' pool records stay Available, and the next withdrawals that
select them fail. The loss lands on whichever users' requests are batched
with those inputs.

**Objects involved.**

- `O`: a Bitcoin output that Hashi controls, for example a confirmed
  deposit.
- `U`: the pool record for `O`, a `UtxoRecord` in `UtxoPool.utxo_records`.
  The pool is the onchain list of outputs Hashi believes it can spend.
- `R`: a user's `WithdrawalRequest`. It escrows the user's hBTC.
- `W`: a `WithdrawalTransaction`, the onchain object that
  `commit_withdrawal_tx` creates. It describes one Bitcoin transaction that
  pays one or more requests, with its inputs, outputs, change, and
  signatures.
- `T_W`: the Bitcoin transaction that `W` describes.

**Precondition.** `O` is spent on Bitcoin by a transaction Hashi did not
create through `W`, while `U` stays Available in the pool. Ways this can
happen:

- the 60-day recovery leaf: holders of the MPC key spend `O` without the
  Guardian (F7);
- a deposit transaction reorged deeper than the confirmation threshold;
- any other spend of `O` outside the withdrawal flow.

Nothing on chain or in the node removes or invalidates `U` when `O` is
spent elsewhere.

**Sequence.**

1. The leader selects `U` as an input and builds `W` for request `R`.
   Committee members check `U` only against `utxo_records`; they do not ask
   Bitcoin whether `O` exists (`withdrawals.rs:638-676`).
2. `commit_withdrawal_tx` succeeds. `U` becomes Locked by `W`. `R` becomes
   Committed. The user's escrowed hBTC is burned. `W`'s change output is
   inserted into the pool as a new Available-pending record `C`.
3. The committee signs every input of `T_W` with MPC, and the Guardian
   co-signs. Neither checks Bitcoin.
4. Committee members sign the finalize certificate. Their
   `testmempoolaccept` check rejects `T_W` with `missing-inputs`, which the
   code classifies as `RejectedOther`, not a script failure, so they sign
   anyway (`finalize_bitcoin_check.rs:63-75, 99-108`).
   `finalize_withdrawal` marks `W` fully signed.
5. The leader broadcasts `T_W`. Bitcoin rejects it because `O` is spent.
   The leader sees "not found" and rebroadcasts on every tick, forever.
6. `confirm_withdrawal` never runs, because committee members require `T_W`
   to be confirmed on Bitcoin.

**End state.**

- `R` is Committed. `cancel_withdrawal` refuses committed requests, so the
  user cannot get the hBTC back, and the BTC never arrives.
- `W` stays fully signed and unconfirmed. No entry function cancels or
  replaces it.
- `U` stays Locked forever.
- `C` sits in the pool as Available-pending but does not exist on Bitcoin.
  If a later withdrawal `W2` selects `C` as an input, `W2` and its requests
  are stranded the same way.
- Every other input of `W` is Locked too, so their BTC is unusable until
  someone intervenes, even though those outputs still exist on Bitcoin.

**Model trace (`BridgeLiveRecovery.cfg`).** A deposit output is mined; a
recovery transaction spends it; the deposit is requested, approved, and
confirmed, so its pool record is Available; a user requests a withdrawal
and it is approved; `CommitWithdrawal` takes the record as input; MPC and
Guardian sign; `FinalizeWithdrawal` succeeds; then nothing can happen to
`W`.

**Fix directions for the aftermath.** Check that each confirmed input exists and is unspent on
Bitcoin before signing the commit certificate. Add a path that, on a
certificate showing an input is spent on Bitcoin, unwinds `W`: unlock the
other inputs, remove `C`, and re-mint or refund `R`'s hBTC. Treat
`missing-inputs` at finalize as a reason to refuse.

**Fix directions for the cause.**

- A guaranteed refresh: spend every pool UTXO before about 45 days,
  independent of withdrawal traffic and fee rate.
- Monitoring that alerts when a pool output is spent outside the protocol,
  plus a certified way to remove its record.
- Reconsider whether the recovery leaf should use the same key that rotation
  carries across committees, for example a key that only the current
  committee holds, or a much longer delay.

**Open questions.** Is a past committee's threshold the reduced-weight `t`
of that epoch? How large does the pool's share of UTXOs older than 60 days
get in practice? Should the backup doc's advice to keep longer-term copies
exclude key material older than the erasure window?

### F8. Pause does not stop Bitcoin outflow of a committed withdrawal

- **Status:** model-confirmed consequence of review finding R2.
- **Model:** `Bridge.tla`, config `BridgePausedBroadcast.cfg` (action
  property `PausedNoWithdrawalBroadcast` fails).
- **Trace:** a withdrawal is committed; governance pauses; MPC signing and
  Guardian signing proceed (neither checks pause); the transaction is
  broadcast without `finalize_withdrawal`.
- **Caveat:** the model takes the absence of pause checks from the code
  review (`withdrawals.rs:70-101, 956-976, 1403-1500`; the Guardian has no
  pause input). The trace shows the consequence, not new evidence for the
  premise. An honest leader stops all work while paused, so this needs one
  Byzantine committee member to drive signing.

### F9. The Guardian can stay on an old committee for a whole Hashi epoch

- **Status:** model-confirmed (review finding R8); code read directly.
  Severity: liveness of withdrawal signing.
- **Model:** `Reconfig.tla`, config `ReconfigGuardianLive.cfg`
  (`GuardianCatchesUp` fails).
- **Mechanism:** each node reconciles the Guardian's committee at most once
  per Hashi epoch while leader (`leader/guardian.rs:30-51`). If
  `GetGuardianInfo` reports no committee, as a standby or not-yet-activated
  Guardian does, `reconcile_guardian_committee` returns `Ok` (`:263-266`),
  and the leader keeps its per-epoch gate set (`leader/mod.rs:452-458` only
  clears it on error).
- **Trace:** the Guardian is down; a reconfiguration completes; every node
  takes a leader turn and sets its gate; the Guardian comes back on the old
  committee. Nothing retries until the next Hashi epoch or a node restart.
  Until then the Guardian rejects certificates from the new committee
  (`cert.epoch` must equal its committee epoch), so finalize stalls.
- **Fix direction:** treat "no committee reported" as a failure so the gate
  clears and the next tick retries.

### F10. Without the proxy gate the Guardian adopts an aborted committee

- **Status:** model-confirmed (review finding R1). The proxy gate closes it.
- **Model:** `Reconfig.tla`, config `ReconfigNoGate.cfg`
  (`GuardianCompleted` fails); `Reconfig.cfg` passes with the gate.
- **Mechanism:** honest outgoing members sign a handoff to whatever
  committee is pending (`withdrawals.rs:1263-1297`,
  `onchain/mod.rs:695-704`). A pending target can later abort. The enclave
  accepts any handoff its current committee signed
  (`committee_update.rs:19-78`); only the proxy checks that the chain stores
  the handoff (`hashi-guardian-proxy/src/node/handoffs.rs`).
- **Residual exposure:** the gate trusts the proxy's fullnode and assumes no
  path to the enclave bypasses the proxy. Once the Guardian adopts a
  committee, it cannot go back.

### F11. Reconfiguration driver: no unclassified aborts, and bounded start retries

- **Status:** closed for safety; liveness gap confirmed as by design.
- **Model:** `Reconfig.tla`. `Reconfig.cfg` passes `NoPanic`,
  `PendingWindow`, `CompleteXorAbort`, `NoEpochReuse`, `HandoffChain`,
  `GuardianCompleted`, `GuardianNotAhead`, and `HashiMonotone` with
  transient failures, holds, MPC failure, and lagging node views.
  `ReconfigLive.cfg` passes `HashiCatchesUp` without transient failures or
  holds.
- **Code check:** completion and handoff signatures are verified one by one
  before aggregation (`hashi-types/src/committee.rs:757-830`), so a
  Byzantine member's bad signature cannot drive an honest node into the
  panic at `service.rs:2045-2065`.
- **Liveness gap (R9):** `ReconfigLiveTransient.cfg` fails. If every node's
  `start_reconfig` attempts fail for one trigger, nothing retries until the
  next Sui epoch change, abort notification, or restart. Clearing
  `reconfig_hold` likewise triggers nothing; `design/docs/reconfiguration.mdx`
  documents this. The delay is at most one Sui epoch.

## Review findings not yet modelled

These come from the sub-agent code review (`PROTOCOL.md` section 12). They
are review-confirmed unless marked otherwise.

| # | Finding | Where to model |
|---|---|---|
| R3 | The Guardian-request certificate is signed after checking only `W` exists and the timestamp. The limiter check happens later, at finalize, after the Guardian has consumed tokens. | `GuardianLimiter` (partly modelled) |
| R4 | "One unsigned `W` at a time" is enforced only off chain. Concurrent leaders can commit several. A `W` that never becomes fully signed blocks all later commits by honest leaders. | `Bridge` |
| R7 | Change outputs are not validated on chain (address, amount, txid). Relies on an honest 2/3. | `Bridge` |
| R10 | A member with 5% weight can pause alone; more than 1/3 can block unpause. | `Reconfig` / governance |
| R11 | Limiter config is per Guardian session; activation only caps tokens. A rotation can raise `max` or `rate`. | Guardian sessions |
| R12 | Limiter recovery at activation reads only two hour directories. Writer-ahead clock skew above about 1 hour can roll back `seq` and tokens or allow a second activation. | Guardian sessions |
| R13 | Proxy replay data is kept 30 days; a retry after that consumes tokens again. | Guardian sessions |
| R14 | Repeated reconfigurations re-approve deposits and restart the delay, which can starve confirmation. | `Bridge` |
| R16 | Seal signatures are kept in memory only; after a restart a node may sign a different dealer-set digest. Liveness only. | `Presig` (batches) |
