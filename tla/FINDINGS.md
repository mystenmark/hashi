# Findings

This file records findings from the TLA+ models and the code review behind
[`PROTOCOL.md`](PROTOCOL.md). Each finding needs confirmation from the owners of the code
before anyone acts on it. We will return to these after the full system model
is complete.

Status values: **model-confirmed** (TLC produced a trace and the code was
checked), **review-confirmed** (reviewers traced it in code; no model yet),
**closed** (the model shows the property holds).

## Model findings

### F1. One Byzantine member can block every DKG and key rotation

- **Status:** reproduced in a Rust test (DKG). Severity: liveness of the
  whole bridge until operators act.
- **Test:** branch [`mlogan-f1-dkg-complaint-test`](https://github.com/mystenmark/hashi/tree/mlogan-f1-dkg-complaint-test) (commit [`ed9512e8`](https://github.com/mystenmark/hashi/commit/ed9512e825c1f1daab79d74126fc86cd92f0f4ca)),
  [`crates/hashi/src/mpc/mpc_except_signing_tests.rs`](https://github.com/mystenmark/hashi/blob/ed9512e825c1f1daab79d74126fc86cd92f0f4ca/crates/hashi/src/mpc/mpc_except_signing_tests.rs):
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
- **Model:** [`DkgOutputs.tla`](DkgOutputs.tla), configs [`DkgOutputs.cfg`](DkgOutputs.cfg),
  [`DkgOutputsOneByz.cfg`](DkgOutputsOneByz.cfg). Controls: [`DkgOutputsComplaints.cfg`](DkgOutputsComplaints.cfg),
  [`DkgOutputsOneByzComplaints.cfg`](DkgOutputsOneByzComplaints.cfg) pass.
- **Setting:** default `mpc_max_faulty_in_basis_points = 3333`
  ([`core/mpc_config.move:18`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/core/mpc_config.move#L18)) and the default complaint policy, which answers
  no complaints ([`crates/hashi/src/config.rs:253-262`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/config.rs#L253-L262)).
- **Mechanism:**
  1. A dealer certificate needs `t + f` of reduced weight. Byzantine receivers
     always sign, so a Byzantine dealer can give bad shares to up to
     `W - t - f = f` of honest weight and still get a certificate.
  2. The adversary orders the TOB, so its certificate can land in the
     selected prefix.
  3. An honest party with bad shares from a selected dealer sends complaints.
     Nobody answers. `recover_dkg_shares_via_complaint(...).await?` fails
     ([`mpc_except_signing.rs:1768-1775`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/mpc_except_signing.rs#L1768-L1775), error at [`:4572`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/mpc_except_signing.rs#L4572)), so the party never
     gets an output. Rotation follows the same path ([`:2084`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/mpc_except_signing.rs#L2084)).
  4. The Byzantine member withholds its completion signature.
- **Trace (10 unit-weight members, f = 3, t = 4, completion 7):** one
  Byzantine dealer hurts 3 honest members. Honest holders = 6 < 7. With two
  Byzantine dealers, even if both sign, holders plus Byzantine = 6 < 7.
- **Consequence:** completion cannot gather 2/3. The pending reconfiguration
  aborts when the Sui epoch ends, and the next one can be blocked the same
  way. While a reconfiguration is pending, every BTC committee step except
  `confirm_withdrawal` stops ([`PROTOCOL.md`](PROTOCOL.md) 2.4). At genesis no old committee
  exists to fall back on.
- **Context:** the config comment says allow-listing a dealer "can leak
  private shares to the dealer". The policy is therefore a deliberate
  trade-off; the open question is whether this impact was accounted for.
- **Open questions:** Does weight reduction change the bound in practice? Is
  there an operator runbook for populating the allow-list during an attack?
  Could the protocol exclude a dealer with verified complaints from the
  prefix instead of answering complaints?

### F2. A withdrawal can be signed twice by the Guardian, debiting the limiter twice

- **Status:** reproduced in Rust tests. Severity: limiter accounting and
  liveness. No extra BTC moves, because both signatures cover the same
  transaction.
- **Tests:** branch [`mlogan-f2-guardian-double-sign-test`](https://github.com/mystenmark/hashi/tree/mlogan-f2-guardian-double-sign-test) (commit
  [`f15cf122`](https://github.com/mystenmark/hashi/commit/f15cf1227a66011167bbe8f3145d668dcf2d72f1)):
  - [`crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs`](https://github.com/mystenmark/hashi/blob/f15cf1227a66011167bbe8f3145d668dcf2d72f1/crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs):
    `same_wid_at_consecutive_seqs_is_signed_and_debited_twice`. Two
    certified requests for one wid at seq 0 and 1 both succeed;
    `next_seq = 2`, tokens are debited twice, and two withdraw records are
    written.
  - [`crates/hashi-guardian-proxy/src/node/cache.rs`](https://github.com/mystenmark/hashi/blob/f15cf1227a66011167bbe8f3145d668dcf2d72f1/crates/hashi-guardian-proxy/src/node/cache.rs):
    `concurrent_same_wid_at_consecutive_seqs_are_both_forwarded`. A barrier
    in the stub enclave releases only if both concurrent requests are
    forwarded; it releases, so the proxy does not serialise per wid.
- **Checked and not preventing it:** the enclave's single control lock
  orders requests but does not dedup; committee members certify a
  `StandardWithdrawalRequest` at any seq ([`withdrawals.rs:956`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L956)); leader
  pacing state is per leader ([`guardian_limiter.rs:196-241`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/guardian_limiter.rs#L196-L241)); the stall
  reconcile fires only after about 5 minutes
  ([`guardian_limiter.rs:244-285`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/guardian_limiter.rs#L244-L285)).
- **Model:** [`GuardianLimiter.tla`](GuardianLimiter.tla) via [`MC_GuardianLimiter.tla`](MC_GuardianLimiter.tla), configs
  [`GuardianLimiterDedup.cfg`](GuardianLimiterDedup.cfg) and [`GuardianLimiterDedupSeed.cfg`](GuardianLimiterDedupSeed.cfg). Invariant
  `NoDoubleConsume`.
- **Mechanism:**
  1. A node's limiter mirror gets one `seq` ahead of the Guardian. Two paths
     reach this:
     - **Seed:** a node restarts and seeds its mirror from `GetGuardianInfo`
       while a withdrawal is in flight. The Guardian has already consumed it.
       When the finalize lands, the mirror applies it again
       ([`lib.rs:1043-1061`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/lib.rs#L1043-L1061), [`onchain/mirror.rs:529`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/onchain/mirror.rs#L529)).
     - **Snap:** reconcile snaps the mirror to the Guardian before the node
       has applied a finalize it has not yet observed.
  2. Two leaders (turns overlap) request the same wid, at `seq = n` and
     `seq = n + 1`.
  3. The proxy looks the wid up, misses for both, and forwards both. Lookup
     and forward are not atomic ([`hashi-guardian-proxy/src/node/cache.rs:153-185`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/cache.rs#L153-L185)).
  4. The enclave has no wid dedup. It signs at `n`, then at `n + 1`.
- **Consequence:** the limiter is debited twice for one transaction. The
  surplus `seq` leaves node mirrors and the Guardian out of step until the
  next reconcile, which stalls withdrawals for about 5 minutes.
- **Fix directions:** dedup by wid inside the enclave, or make the proxy's
  lookup-and-forward atomic per wid; do not double-apply a seeded consume.

### F3. The rate-limit bound must include the past timestamp window

- **Status:** model-confirmed. Severity: documentation of the security bound.
- **Model:** [`GuardianLimiter.tla`](GuardianLimiter.tla), config [`GuardianLimiterFutureOnly.cfg`](GuardianLimiterFutureOnly.cfg)
  (fails) and [`GuardianLimiter.cfg`](GuardianLimiter.cfg), [`GuardianLimiterRateWide.cfg`](GuardianLimiterRateWide.cfg) (pass).
- **Mechanism:** the enclave accepts `ts` in `[now - 1800 s, now + 300 s]`
  ([`standard_withdrawal.rs:19-21`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs#L19-L21), [`99-114`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs#L99-L114)). The limiter refills by `ts`, not by
  enclave time. A request with an old `ts` drains the bucket; requests with
  later `ts` refill it at the same enclave time.
- **Trace:** at enclave time 3, records with `ts = 1` and `ts = 3` each release
  2 units; 4 > `max + rate * future` = 3.
- **Correct bound:** outflow during any enclave-time window is at most
  `max + rate * (window + 2100 s)`. With an honest committee, signers bound
  `ts` to within 600 s of their checkpoint time ([`withdrawals.rs:68`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L68), [`944-952`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L944-L952)),
  which gives `max + rate * (window + 900 s)`. Both hold for one limiter
  config; a Guardian rotation can change `max` and `rate`.

### F4. Nonce reuse if batch derivation changes within an epoch

- **Status:** model-confirmed for the abstract mechanism; downgraded to a
  hardening suggestion after code review. Severity if triggered: key-share
  leak for one node.
- **Model:** [`Presig.tla`](Presig.tla), config [`PresigCodeChange.cfg`](PresigCodeChange.cfg) (fails);
  [`Presig.cfg`](Presig.cfg) (passes, 107.5M states) with the map fixed.
- **Mechanism:** a node maps a global presig index to a local position by
  cumulative installed batch sizes ([`signing.rs:920-950`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/signing.rs#L920-L950)). After a restart,
  recovery disables indices using the new binary's map; nothing records
  which presignature an index used. If a release changes the size of an
  installed batch below an index the node already signed, a still-Pending
  index can resolve to the used position and sign a second request.
- **Why it is unlikely:** `BATCH_SIZE_PER_WEIGHT` has been 10 since it was
  introduced ([`cc3845c6`](https://github.com/MystenLabs/hashi/commit/cc3845c6)), and its override is rejected on mainnet and
  testnet ([`lib.rs:740-749`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/lib.rs#L740-L749)). The reviewer's digest-mismatch precondition is
  largely closed: batches with node-local skips are discarded
  ([`service.rs:831-837`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/service.rs#L831-L837)), sizes are checked against admitted weight
  ([`service.rs:856-860`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/service.rs#L856-L860)), and batches install contiguously. The admission
  rules that set batch sizes have changed in releases ([#841](https://github.com/MystenLabs/hashi/pull/841), [its revert](https://github.com/MystenLabs/hashi/commit/1fe63837),
  [#953](https://github.com/MystenLabs/hashi/pull/953)), but the team gated a past derivation change on an activation epoch
  "chosen at least one epoch ahead" (removed in [`bb3f6811`](https://github.com/MystenLabs/hashi/commit/bb3f6811)), which is the
  discipline that rules this out.
- **Suggestion:** persist each installed batch's start index and size per
  epoch, and refuse to install a different one after a restart in the same
  epoch. This turns a silent leak into a loud failure if a future release
  gets the gating wrong.

### F5. Nonce safety holds under the stated assumptions

- **Status:** closed for the model's scope.
- **Model:** [`Presig.cfg`](Presig.cfg) passes `NonceSafety`, `UniquePendingIndex`,
  `PendingBelowAlloc`, `TagNotAhead`, `ViewNotAhead`.
- **Scope:** honest nodes with lagging views, crash and restart, epoch change
  and abort, reallocation, nondeterministic recording of signatures. The
  epoch-tag check is necessary: [`PresigNoTagCheck.cfg`](PresigNoTagCheck.cfg) fails.
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
- **Model:** [`Bridge.tla`](Bridge.tla) via [`MC_Bridge.tla`](MC_Bridge.tla). [`BridgeRecovery.cfg`](BridgeRecovery.cfg)
  (`RecordSound` fails), [`BridgeRecoveryBacking.cfg`](BridgeRecoveryBacking.cfg) (`Backing` fails), and
  [`BridgeLiveRecovery.cfg`](BridgeLiveRecovery.cfg) (`WithdrawalCompletes` fails) show the effect of a
  recovery spend. The model does not represent committees or key shares;
  the facts below come from the code and design docs.

**Facts.**

1. **Recovery leaf.** Every pool UTXO, deposit and change alike, is
   `tr(NUMS, {multi_a(2, guardian, h), and_v(older(60 days), pk(h))})`
   ([`design/docs/address-scheme.mdx`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/design/docs/address-scheme.mdx), [`deposits.rs:403-406`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/deposits.rs#L403-L406)). The MPC key
   alone can spend it 60 days after it confirms: no Guardian signature, no
   limiter, no onchain step.
2. **Rotation keeps the key.** Key rotation reshares the same group key; the
   new key must equal the old one ([`mpc_except_signing.rs:4936-4945`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/mpc_except_signing.rs#L4936-L4945),
   [`committee_set.move:501`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/core/committee/committee_set.move#L501)). Shares from any past committee that meet that
   committee's threshold reconstruct today's key.
3. **Refresh is opportunistic.** Only spending a UTXO resets its 60-day
   clock. Old UTXOs (more than 4,320 blocks, about 30 days;
   [`utxo_pool/mod.rs:66`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/utxo_pool/mod.rs#L66)) are prioritised only as extra consolidation inputs
   to a withdrawal that is already being built, and only when it has change,
   the fee rate is below the high threshold, and the batch is under its
   per-request input cap ([`utxo_pool/mod.rs:880-893`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/utxo_pool/mod.rs#L880-L893)). No dedicated refresh
   transaction exists.
4. **Old key material is erased on a schedule.** Shares are rebuilt from a
   node's per-epoch encryption keys plus dealer and rotation messages. The
   live database keeps those for the target, previous, and preceding
   committees plus 7 epochs ([`db.rs:627-655`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/db.rs#L627-L655), [`service.rs`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/service.rs#L2730)
   `build_pruning_references`). Epoch backups contain them
   ([`db.rs:131-148`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/db.rs#L131-L148)) and are deleted locally after 14 days, 30 for the
   newest ([`backup.rs:50-52`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/backup.rs#L50-L52)); the documented S3 lifecycle target is also
   14 days ([`design/docs/node-backup.mdx`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/design/docs/node-backup.mdx)). The same doc says "Keep
   longer-term copies elsewhere", does not sweep a decommissioned host's
   archives, and notes S3 expiry is "not guaranteed deletion on day 14".

**Consequence.** The Guardian exists "to protect against vulnerabilities and
against malicious past committees" ([`design/docs/guardian.mdx`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/design/docs/guardian.mdx)). For any
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
   Bitcoin whether `O` exists ([`withdrawals.rs:638-676`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L638-L676)).
2. `commit_withdrawal_tx` succeeds. `U` becomes Locked by `W`. `R` becomes
   Committed. The user's escrowed hBTC is burned. `W`'s change output is
   inserted into the pool as a new Available-pending record `C`.
3. The committee signs every input of `T_W` with MPC, and the Guardian
   co-signs. Neither checks Bitcoin.
4. Committee members sign the finalize certificate. Their
   `testmempoolaccept` check rejects `T_W` with `missing-inputs`, which the
   code classifies as `RejectedOther`, not a script failure, so they sign
   anyway ([`finalize_bitcoin_check.rs:63-75`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/finalize_bitcoin_check.rs#L63-L75), [`99-108`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/finalize_bitcoin_check.rs#L99-L108)).
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

**Model trace ([`BridgeLiveRecovery.cfg`](BridgeLiveRecovery.cfg)).** A deposit output is mined; a
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
- **Model:** [`Bridge.tla`](Bridge.tla), config [`BridgePausedBroadcast.cfg`](BridgePausedBroadcast.cfg) (action
  property `PausedNoWithdrawalBroadcast` fails).
- **Trace:** a withdrawal is committed; governance pauses; MPC signing and
  Guardian signing proceed (neither checks pause); the transaction is
  broadcast without `finalize_withdrawal`.
- **Caveat:** the model takes the absence of pause checks from the code
  review ([`withdrawals.rs:70-101`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L70-L101), [`956-976`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L956-L976), [`1403-1500`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L1403-L1500); the Guardian has no
  pause input). The trace shows the consequence, not new evidence for the
  premise. An honest leader stops all work while paused, so this needs one
  Byzantine committee member to drive signing.

### F9. The Guardian can stay on an old committee for a whole Hashi epoch

- **Status:** reproduced in Rust tests (review finding R8). Severity:
  liveness of withdrawal signing.
- **Tests:** branch [`mlogan-f9-guardian-reconcile-gate-test`](https://github.com/mystenmark/hashi/tree/mlogan-f9-guardian-reconcile-gate-test) (commit
  [`774b87d3`](https://github.com/mystenmark/hashi/commit/774b87d3b8897338367fbb3344f8ae8d31fbf464)), [`crates/hashi/src/leader/guardian.rs`](https://github.com/mystenmark/hashi/blob/774b87d3b8897338367fbb3344f8ae8d31fbf464/crates/hashi/src/leader/guardian.rs):
  `no_committee_reply_holds_the_epoch_gate_while_guardian_is_behind` and the
  contrast `unavailable_guardian_clears_the_epoch_gate_and_is_retried`. A
  real `GuardianClient` talks to a stub Guardian server. With a no-committee
  reply the gate stays at the current epoch and later checks start no
  reconcile, even after the stub reports an older committee. With an error
  reply the gate clears and the next check retries. Gap: the gate-clearing
  arm sits inline in `run()`'s `select!`; the test copies its logic in a
  helper.
- **When the Guardian reports no committee:** a standby
  (ProvisionerInitialized, not Activated) returns `Ok` with no committee
  epoch ([`hashi-guardian/src/enclave.rs:614`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/enclave.rs#L614)). A failing or unreachable
  Guardian yields `Err`, which clears the gate. The proxy caches successful
  info replies, including no-committee ones, for 30 s
  ([`hashi-guardian-proxy/src/guardian_info.rs:18`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/guardian_info.rs#L18),[`53-77`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/guardian_info.rs#L53-L77)).
- **Why the Guardian comes up behind:** activation installs the latest
  committee in the Guardian's S3 log ([`operator_activate.rs:50-55`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/operator_activate.rs#L50-L55)). If the
  old Guardian stopped before receiving the new epoch's handoff, the new
  one starts on the previous committee. A standby activation that spans one
  full leader rotation (100 checkpoints per turn) then sets every node's
  gate.
- **Model:** [`Reconfig.tla`](Reconfig.tla), config [`ReconfigGuardianLive.cfg`](ReconfigGuardianLive.cfg)
  (`GuardianCatchesUp` fails). With the fix (`NoCommitteeFails`),
  [`ReconfigGuardianLiveFix.cfg`](ReconfigGuardianLiveFix.cfg) passes. Both use strong fairness on
  reconcile, because a failed reconcile is retried every tick.
- **Bridge consequence:** [`BridgeReconfig.tla`](BridgeReconfig.tla) composes `Bridge` with
  `Reconfig`. In [`BridgeReconfigLive.cfg`](BridgeReconfigLive.cfg), `WithdrawalCompletes` fails: the
  Guardian is down while Hashi moves from epoch 0 to 2, the leader sets its
  gate at epoch 2, the Guardian comes back on committee 0, and a withdrawal
  committed and MPC-signed at epoch 2 never gets a Guardian signature. An
  honest leader commits no new `W` while one is unsigned (R4), so all
  withdrawals stop. [`BridgeReconfigLiveFix.cfg`](BridgeReconfigLiveFix.cfg) (fix on) passes
  `WithdrawalCompletes`, `RequestServed`, `DepositCompletes`,
  `HashiCatchesUp`, and `GuardianCatchesUp`.
- **Node behaviour while stalled:** the Guardian returns `Unauthenticated`
  for the epoch mismatch, which the leader counts as "GuardianUnavailable"
  and retries every checkpoint with no backoff ([`leader/guardian.rs:90-104`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/guardian.rs#L90-L104)).
  The check runs before the Guardian's limiter, so retries consume no
  tokens ([`standard_withdrawal.rs:37-58`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs#L37-L58)).
- **Mechanism:** each node reconciles the Guardian's committee at most once
  per Hashi epoch while leader ([`leader/guardian.rs:30-51`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/guardian.rs#L30-L51)). If
  `GetGuardianInfo` reports no committee, as a standby or not-yet-activated
  Guardian does, `reconcile_guardian_committee` returns `Ok` ([`:263-266`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/guardian.rs#L263-L266)),
  and the leader keeps its per-epoch gate set ([`leader/mod.rs:452-458`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/mod.rs#L452-L458) only
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
- **Model:** [`Reconfig.tla`](Reconfig.tla), config [`ReconfigNoGate.cfg`](ReconfigNoGate.cfg)
  (`GuardianCompleted` fails); [`Reconfig.cfg`](Reconfig.cfg) passes with the gate.
- **Mechanism:** honest outgoing members sign a handoff to whatever
  committee is pending ([`withdrawals.rs:1263-1297`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L1263-L1297),
  [`onchain/mod.rs:695-704`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/onchain/mod.rs#L695-L704)). A pending target can later abort. The enclave
  accepts any handoff its current committee signed
  ([`committee_update.rs:19-78`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/committee_update.rs#L19-L78)); only the proxy checks that the chain stores
  the handoff ([`hashi-guardian-proxy/src/node/handoffs.rs`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/handoffs.rs)).
- **Residual exposure:** the gate trusts the proxy's fullnode and assumes no
  path to the enclave bypasses the proxy. Once the Guardian adopts a
  committee, it cannot go back.

### F11. Reconfiguration driver: no unclassified aborts, and bounded start retries

- **Status:** closed for safety; liveness gap confirmed as by design.
- **Model:** [`Reconfig.tla`](Reconfig.tla). [`Reconfig.cfg`](Reconfig.cfg) passes `NoPanic`,
  `PendingWindow`, `CompleteXorAbort`, `NoEpochReuse`, `HandoffChain`,
  `GuardianCompleted`, `GuardianNotAhead`, and `HashiMonotone` with
  transient failures, holds, MPC failure, and lagging node views.
  [`ReconfigLive.cfg`](ReconfigLive.cfg) passes `HashiCatchesUp` without transient failures or
  holds.
- **Code check:** completion and handoff signatures are verified one by one
  before aggregation ([`hashi-types/src/committee.rs:757-830`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-types/src/committee.rs#L757-L830)), so a
  Byzantine member's bad signature cannot drive an honest node into the
  panic at [`service.rs:2045-2065`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/mpc/service.rs#L2045-L2065).
- **Liveness gap (R9):** [`ReconfigLiveTransient.cfg`](ReconfigLiveTransient.cfg) fails. If every node's
  `start_reconfig` attempts fail for one trigger, nothing retries until the
  next Sui epoch change, abort notification, or restart. Clearing
  `reconfig_hold` likewise triggers nothing; [`design/docs/reconfiguration.mdx`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/design/docs/reconfiguration.mdx)
  documents this. The delay is at most one Sui epoch.

### F12. Lowering the Guardian's max capacity can halt all withdrawals

- **Status:** model-confirmed; code facts checked by a sub-agent. Severity:
  liveness of all withdrawals. Recovery requires another operator rotation.
- **Model:** [`BridgeLimiter.tla`](BridgeLimiter.tla) composes `Bridge` with `GuardianLimiter`.
  [`BridgeLimiter.cfg`](BridgeLimiter.cfg) (no rotation) passes all safety, including
  `SignableByGuardian`. [`BridgeLimiterRotate.cfg`](BridgeLimiterRotate.cfg) violates
  `SignableByGuardian`. [`BridgeLimiterRotateStuck.cfg`](BridgeLimiterRotateStuck.cfg) passes
  `StuckIsPermanent` and `StuckBlocksCommits`.
- **Trace:** two requests are approved and batched into `W1` with outflow 2
  under max 2. An operator rotation starts a Guardian session with max 1.
  The Guardian refuses `W1` on every attempt, so `W1` is never fully signed.
  No other withdrawal is committed while `W1` is unsigned.
- **Code facts:**
  - The limiter config is fixed per Guardian session, and a new session may
    set a different max or rate. Activation takes the new session's config;
    nothing compares it with the previous one ([`operator_activate.rs:36`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/operator_activate.rs#L36)).
    Recovery caps tokens to the new max ([`limiter_recovery.rs:44-85`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/s3_reader/limiter_recovery.rs#L44-L85),
    [`limiter.rs:46-49`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-types/src/guardian/limiter.rs#L46-L49)). Nodes adopt the new config within about 15 s
    ([`guardian_limiter.rs:157-166`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/guardian_limiter.rs#L157-L166), [`lib.rs:1238`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/lib.rs#L1238)).
  - The commit check compares outflow with the max at commit time
    ([`withdrawals.rs:781-786`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/withdrawals.rs#L781-L786)). A `W` committed before the change is not
    re-checked.
  - The Guardian refuses an amount above its capacity with
    `RateLimitExceeded` and consumes no seq ([`limiter.rs:94-117`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-types/src/guardian/limiter.rs#L94-L117)). The leader
    retries forever and never drops or marks `W`
    ([`withdrawal_transactions.rs:427-441`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/withdrawal_transactions.rs#L427-L441), [`leader/guardian.rs:83-104`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/guardian.rs#L83-L104)).
  - No Move path cancels, unlocks, or replaces a committed `W`. Archive
    requires confirmation ([`withdrawal_queue.move:620`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/btc/withdrawal_queue.move#L620),[`685`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/btc/withdrawal_queue.move#L685)).
    `remove_withdrawal_txn` ([`withdrawal_queue.move:539`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/btc/withdrawal_queue.move#L539)) has no callers.
  - The leader commits nothing while any `W` is not fully signed, with no
    timeout ([`onchain/mod.rs:871-879`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/onchain/mod.rs#L871-L879), [`withdrawal_request_flow.rs:412-415`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/withdrawal_request_flow.rs#L412-L415)).
  - The Guardian has no other signing mode ([`withdraw_mode/mod.rs:9-13`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/withdraw_mode/mod.rs#L9-L13)).
- **Why it matters:** lowering the max is a plausible response to an
  incident. If any committed withdrawal exceeds the new max, the bridge stops
  all withdrawals until an operator rotates again with a max at least as
  large as that withdrawal.
- **Fix directions:** refuse to activate a session whose max is below the
  outflow of any committed, unsigned `W`; or let the leader skip a `W` that
  exceeds the Guardian's max and add an on-chain path to unlock its inputs
  and restore its requests.

### F13. The Guardian's single-writer fence rests on a host that does not delay writes

- **Status:** model-confirmed as a boundary; the host capability needs
  confirmation. Severity: limiter bound (safety 18, 19) under a malicious
  host; at most one record per session handover.
- **Model:** [`GuardianSessions.tla`](GuardianSessions.tla) (time in minutes, Q = 10, budget 1,
  attempt timeout 5). Session `a` is active at time 0; `b` may initialise
  and activate later. Results:
  - [`GuardianSessions.cfg`](GuardianSessions.cfg) (equal clocks, no late durability): all pass,
    33.1M states.
  - [`GuardianSessionsAhead1.cfg`](GuardianSessionsAhead1.cfg) (`b`'s clock 1 minute ahead): pass, 39.8M
    states.
  - [`GuardianSessionsAhead2.cfg`](GuardianSessionsAhead2.cfg) (2 minutes ahead): `UniqueSeq` fails.
  - [`GuardianSessionsLate.cfg`](GuardianSessionsLate.cfg) (equal clocks, a timed-out PUT lands up to
    2 minutes after its deadline): `UniqueSeq` fails.
  - [`GuardianSessionsWriterAhead.cfg`](GuardianSessionsWriterAhead.cfg) (`a`'s clock 130 minutes ahead):
    `OneWriter` fails, because `a`'s heartbeats fall outside `b`'s
    three-hour scan.
  These match README assumptions 1 and 4 exactly: reader-ahead skew plus
  post-deadline durability must stay within the 1-minute budget.
- **Trace (late durability):** `a` heartbeats last at minute 0, starts a
  withdraw write for seq 0 at minute 3 (3 + 5 < 0 + 10 - 1), and the host
  holds the PUT. At minute 10, `b` sees `a` quiet, activates, and recovers
  next seq 0. `a`'s PUT lands at minute 10. `b` writes its own seq 0.
- **Why the host can do this:** the enclave runs TLS itself, but its S3
  traffic leaves through VSOCK forwarders on the host
  ([`s3_client.rs:139-160`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/s3_client.rs#L139-L160)). The host cannot read or change a PUT, but can
  hold it. The README says "The S3 bucket operator is untrusted"
  ([`hashi-guardian/README.md:5`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/README.md?plain=1#L5)). Assumption 4 ("S3 does not make a
  timed-out request durable arbitrarily later") is about S3; it does not
  say what bounds a host-held request.
- **How long the host can hold a PUT:** S3 rejects a SigV4 request whose
  signed time differs from its own clock by more than 15 minutes
  (`RequestTimeTooSkewed`). AWS does not document a limit on how long a
  request may take to arrive. S3 closes a socket that sees no bytes for a
  while (`RequestTimeout`), but a host that forwards a few bytes at a time
  keeps the socket open. S3 can only check the date after it has decrypted
  the TLS record that holds the headers. Two cases follow:
  - The headers and the small JSON body share one TLS record. The host
    holds that record and forwards its last byte up to about 15 minutes
    after signing. The hold is bounded near 15 minutes.
  - The headers and body arrive in separate records. The host forwards the
    headers at once, so the date check passes, and then trickles the body.
    No documented bound applies.
  Either case is far above the 1-minute budget. To settle which case holds,
  an experiment can PUT through a proxy that trickles bytes to a test
  bucket.
- **Retries:** a timed-out attempt does not panic at once. The writer
  retries the same record every 10 s, up to 5 attempts, while a new
  5-minute attempt still fits before the fence, and panics after that
  ([`log_writer.rs:83-142`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/log_writer.rs#L83-L142)).
  Every attempt writes the same key with
  `If-None-Match: *` ([`s3_client.rs:213-226`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/s3_client.rs#L213-L226)),
  so a held earlier attempt that lands late is the same object. The model
  treats a timed-out write as fatal; the retries do not add new records,
  so the safety results stand.
- **Consequence:** the late record is durable, so the proxy can replay its
  signatures. The new session recovered its limiter without that debit,
  so outflow can exceed the rate bound by that record's amount (at most
  `max`). Two records share a seq. The object key is
  `<hour>/<seq>-wid<wid>.json`
  ([`withdrawal.rs:35-46`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-types/src/guardian/s3/log_messages/withdrawal.rs#L35-L46)),
  so `If-None-Match` stops a second write only for the same seq, wid, and
  hour. The proxy index does not detect the same seq with different wids
  ([`widlog.rs:96-125`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/widlog.rs#L96-L125)).
  Each handover can leak at most one record, because the old session's
  writes are serialized and it does not start the next record until the
  current one is confirmed. Handovers need the key provisioners
  (`ProvisionerInit`), which limits repetition.
- **Clock skew over an hour (R12):** a writer clock more than about an hour
  ahead hides its heartbeats from the activator (`WriterAhead`). The same
  skew also breaks limiter recovery. A record written with a far-ahead
  clock lands in a future hour directory, and recovery reads only the
  newest non-empty hour and the one before it. A later session then
  recovers a low seq and reuses seqs ([`limiter_recovery.rs:48-110`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian/src/s3_reader/limiter_recovery.rs#L48-L110)).
  [`GuardianSessionsRollback.cfg`](GuardianSessionsRollback.cfg) confirms it with three sessions; the fence
  constants are scaled down (Q 4, attempt 1), since the path depends on
  hour directories. `a`'s clock is 130 minutes ahead and writes seq 0 into
  hour 3. `b` recovers next seq 1 and writes seq 1 into hour 1. `c`
  recovers from hours 2 and 3 only, gets next seq 1 instead of 2, and
  `RecoveryExact` fails.
- **Fix directions:** make the fence independent of delivery time. For
  example, the reader could reject records whose signed timestamp is after
  the writer's last heartbeat plus `Q - Budget - Attempt`, or recovery could
  scan all hours whose records could still be durable. If the experiment
  shows the hold is bounded near 15 minutes, another option is to record
  that bound as the late-durability budget and raise `Q` to match.

## Review findings not yet modelled

These come from the sub-agent code review ([`PROTOCOL.md`](PROTOCOL.md) section 12). They
are review-confirmed unless marked otherwise.

| # | Finding | Where to model |
|---|---|---|
| R3 | The Guardian-request certificate is signed after checking only `W` exists and the timestamp. The limiter check happens later, at finalize, after the Guardian has consumed tokens. | Composed in `BridgeLimiter`: `GsigLogged` and `FinalizedLogged` hold. A finalize refused by follower mirrors is retried; the proxy replays the logged signatures, so tokens are not debited again, and mirrors are snapped after about 5 minutes ([`cache.rs:161-170`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/cache.rs#L161-L170), [`guardian_limiter.rs:244-283`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/guardian_limiter.rs#L244-L283)). Liveness was not model-checked, because the limiter clock is bounded. |
| R4 | "One unsigned `W` at a time" is enforced only off chain. Concurrent leaders can commit several. A `W` that never becomes fully signed blocks all later commits by honest leaders. | Modelled. Consequences in F9 ([`BridgeReconfigLive.cfg`](BridgeReconfigLive.cfg)) and F12 ([`BridgeLimiterRotateStuck.cfg`](BridgeLimiterRotateStuck.cfg)). |
| R7 | Change outputs are not validated on chain (address, amount, txid). Relies on an honest 2/3. | `Bridge` |
| R10 | A member with 5% weight can pause alone; more than 1/3 can block unpause. | `Reconfig` / governance |
| R11 | Limiter config is per Guardian session; activation only caps tokens. A rotation can raise `max` or `rate`. | Lowering is modelled as F12. Raising `max` or `rate` loosens the rate bound and is a policy question for the operator. |
| R12 | Limiter recovery at activation reads only two hour directories. Writer-ahead clock skew above about 1 hour can roll back `seq` and tokens or allow a second activation. | Modelled in F13 ([`GuardianSessionsWriterAhead.cfg`](GuardianSessionsWriterAhead.cfg), [`GuardianSessionsRollback.cfg`](GuardianSessionsRollback.cfg)). Correction: recovery reads the newest non-empty hour and the one before it, not a window around the current time. |
| R13 | Proxy replay data is kept 30 days; a retry after that consumes tokens again. | Not modelled. Confirmed by code reading ([`widlog.rs:66`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/widlog.rs#L66), [`218-219`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/widlog.rs#L218-L219), [`cache.rs:172-181`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi-guardian-proxy/src/node/cache.rs#L172-L181)). The enclave signs again only if the request's seq equals `next_seq`. The second debit over-counts outflow, which is conservative; it needs a `W` that is Guardian-signed but not finalized for 30 days. |
| R14 | Repeated reconfigurations re-approve deposits and restart the delay, which can starve confirmation. | Analysed, not a separate issue. Only a completed reconfiguration triggers re-approval; an abort keeps the epoch, so stored certs stay valid ([`leader/deposits.rs:64-76`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/crates/hashi/src/leader/deposits.rs#L64-L76), [`deposit.move:159-161`](https://github.com/MystenLabs/hashi/blob/97021d258adc2dc276017defe2f84e4bd3cd9162/packages/hashi/sources/btc/deposit.move#L159-L161)). Completions happen at most once per Sui epoch (about 24 h) and the delay is 10 min, so starvation needs a reconfiguration pending most of each epoch. That is the bridge stall of PROTOCOL.md 2.4 (for example F1), in which unconfirmed requests also expire after 24 h and must be resubmitted. [`BridgeReconfigLiveFix.cfg`](BridgeReconfigLiveFix.cfg) checks `DepositCompletes` with re-approval across epochs. |
| R16 | Seal signatures are kept in memory only; after a restart a node may sign a different dealer-set digest. Liveness only. | `Presig` (batches) |
