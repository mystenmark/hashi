# Hashi: informal protocol description for TLA+ modelling

This document describes the Hashi protocol at the level of detail a TLA+ model
needs. It abstracts cryptography into ideal objects (certificates, shares,
signatures). Sources are the design docs in `design/docs/`, the Move package in
`packages/hashi/sources/`, the node in `crates/hashi/src/`, the Guardian in
`crates/hashi-guardian/src/`, and the proxy in `crates/hashi-guardian-proxy/src/`.
Citations use paths relative to those roots.

## 1. Actors and environment

| Actor | Role | Fault model to consider |
|---|---|---|
| Sui chain | Holds the `Hashi` object. Executes entry functions atomically in a total order. Provides a Sui epoch counter, a clock, and `Random`. | Correct. |
| Sui validators | Register with Hashi. A registered subset forms each Hashi committee, weighted by Sui voting power. | Byzantine below the security threshold; crashed below the liveness threshold. Crash with state loss (lost DB) is a separate class: the node cannot sign for its seat. |
| Committee nodes | Run the `hashi` service. Sign BLS certificates, run MPC, drive leader work. | Each node acts on a local view of the chain that lags and never leads it. |
| Leader | `turn = checkpointHeight / 100`, `leader = turn mod |members|` (`leader/mod.rs:547`). Member count, not weight. Tasks outlive their turn, and followers do not check the caller is leader. | Model as "any member may perform any leader action". |
| Guardian enclave | Second signer for every normal Bitcoin spend. Enforces a token-bucket limiter and verifies committee certificates. | Correct code. The process can crash. Several sessions can exist. |
| Guardian proxy | Front end for the enclave. Replays responses by withdrawal ID. Forwards handoffs only when its Sui fullnode shows them stored. | Correct, but its lookup-then-forward is not atomic. Trusts its fullnode. |
| Bitcoin | UTXO ledger. A transaction confirms after `bitcoin_confirmation_threshold` blocks (default 6, governable). | Reorgs shallower than the threshold. Conflicting spends. Unmined or evicted transactions. |
| Users | Send BTC to deposit addresses. Submit deposit and withdrawal requests. Cancel withdrawals. | Arbitrary. Anyone can submit any `Utxo` value in a deposit request. |
| Governance | Proposals by committee members. | A member with 5% weight can pause alone. More than 1/3 Byzantine weight can block unpause. |

**Bitcoin script.** Every deposit and change address is
`tr(NUMS, {multi_a(2, guardian, h), and_v(older(60 days), pk(h))})`
(`deposits.rs:403-406`). The normal leaf needs MPC and Guardian. The recovery
leaf lets the MPC key alone spend a UTXO 60 days after it confirms. No node code
builds recovery spends. Consolidation prefers UTXOs older than 4,320 blocks, but
only when a withdrawal has change and fees are low (`utxo_pool/mod.rs:887-925`).
The model needs an environment action `RecoverySpend(u)`, enabled when
`age(u) >= 60 days` and the signers hold the MPC threshold.

## 2. Epochs and committees

### 2.1 State

- `suiEpoch`: the Sui epoch. It only increases. It is an environment variable.
- `hashiEpoch` (`committee_set.epoch`): the epoch of the current committee. Only
  `end_reconfig` writes it.
- `committees`: a map from epoch to committee. It holds the current committee,
  every past committee, and the pending committee. A committee is a list of
  members with weights (all `> 0`) and keys, plus a snapshot of the epoch
  config. A committee never changes after `start_reconfig` forms it. It is
  either activated or removed by an abort.
- `pending`: `None` or `{epoch, handoffCert}`. A reconfiguration is in progress
  exactly when `pending` is not `None`.
- `mpcKey`: empty before genesis. The first `end_reconfig` sets it (33 bytes).
  It never changes afterwards.
- `handoffs`: a map from source epoch to `{nextEpoch, cert}`.
- `members`: registration records with flags `ignored`, `resigned`, and
  next-epoch keys. Committee formation, `resign`, and `remove_inactive_member`
  read these flags.
- `launched`: set once by `finish_publish`. It gates genesis only.
- `reconfigHold`, `paused`: config flags written by governance.

Invariants expected after genesis: `hashiEpoch < suiEpoch` whenever a
reconfiguration is pending, `hashiEpoch < pending.epoch <= suiEpoch`, and a
committee exists for `hashiEpoch`. Equality `hashiEpoch = pending.epoch = 0`
can occur only before genesis on a network still in Sui epoch 0. Hashi epochs
are a subsequence of Sui epochs and can skip values.

Every entry function also requires the package version to be enabled.
`DisableVersion` can therefore stop every action, including abort and end. The
model can assume the version gate holds.

### 2.2 Actions

**SuiEpochAdvance** (environment): `suiEpoch' = suiEpoch + 1`.

**StartReconfig** (anyone, `core/reconfig.move:85`). Preconditions:
`!reconfigHold`, `pending = None`, genesis implies `launched`, no committee
exists for `suiEpoch`, and `hashiEpoch = 0 \/ hashiEpoch # suiEpoch`. The
action forms committee `C` from active Sui validators that are registered, not
ignored, not resigned, and have BLS and encryption keys set. It sets
`committees[suiEpoch] = C` and `pending = {suiEpoch, None}`. `C` must be
non-empty.

**DKG / KeyRotation** (offchain, section 8.2). The pending committee runs DKG
if `mpcKey` is empty and key rotation otherwise. Some honest members may finish
without an output (section 8.2).

**SignHandoff** (honest outgoing member, `withdrawals.rs:1263-1297`,
`onchain/mod.rs:695-704`). An honest member of the committee for `from` signs
`CommitteeTransitionRequest{c}` for the next committee `c` on chain after
`from`, pending or completed. It checks only that it and the caller are members
of the `from` committee. It does not check that the target will complete.
Honest members therefore sign handoffs to targets that are later aborted. The
model must export the set of signed handoffs to the Guardian module.

**SubmitCommitteeHandoff(e, cert)** (anyone, standalone entry,
`reconfig.move:178`). Preconditions: `pending.epoch = e = suiEpoch`, `mpcKey`
non-empty, `cert` is signed by 2/3 of the **current** committee over
`CommitteeTransitionRequest{committees[e]}`, and no handoff cert is stored yet
on `pending` (bare assert, `committee_set.move:471`). Effect:
`pending.handoffCert = cert`.

**EndReconfig(key, cert)** (`reconfig.move:109`). Preconditions:
`pending.epoch = n = suiEpoch` where `n = cert.epoch`, `cert` is signed by 2/3
of the **pending** committee over `ReconfigCompletionMessage{n, key}`, and
`key` is 33 bytes. If `mpcKey` is empty it is set to `key`. Otherwise a handoff
cert must be present and `key = mpcKey`. Effects: `hashiEpoch' = n`,
`pending' = None`, the presig allocator resets to 0, and the handoff is stored
at `handoffs[oldEpoch]`. Honest nodes submit the handoff and `end_reconfig` in
one Sui transaction (`sui_tx_executor.rs:75-100`).

**AbortReconfig(e)** (anyone, no certificate, `committee_set.move:526`).
Preconditions: `pending.epoch = e` and `e # suiEpoch`. Effects:
`pending' = None` and `committees[e]` is removed. `hashiEpoch`, the current
committee and `mpcKey` are unchanged. At genesis Hashi returns to its
pre-genesis state.

Completion requires `pending.epoch = suiEpoch`. Abort requires
`pending.epoch # suiEpoch`. The two are never both enabled. An aborted epoch
number is never reused, because `suiEpoch` has passed it.

**Registration and membership** (`validator.move`): register, set next-epoch
BLS key (with proof of possession bound to the current Sui epoch), set
encryption key, set TLS key, resign, withdraw resignation, remove inactive
member. None of these alter the current or pending committee. A node registers
fresh keys for each target epoch. `start_reconfig` captures whatever keys are
registered at that moment.

### 2.3 Node reconfiguration driver (`mpc/service.rs`)

- Triggers for `start_reconfig`: startup, `SuiEpochChanged`, `ReconfigAborted`,
  and the end of `drive_reconfig`. Each trigger makes at most 3 attempts
  (`service.rs:62, 1845`). Clearing `reconfigHold` triggers nothing. If all 3
  attempts fail, nothing retries before the next Sui epoch or a restart. The
  model must not assume weak fairness on `StartReconfig` without this caveat.
- When the node's view shows `suiEpoch > pending.epoch`, it submits
  `abort_reconfig` and then a fresh `start_reconfig`.
- The node runs the MPC protocol while its target is pending and inside the
  window. Once it has an output it loops on `end_reconfig`:
  - `EReconfigAlreadyCompleted`: wait for the local view to show the target as
    no longer pending. Retry if the view does not catch up.
  - A full handoff slot (bare abort at `committee_set.move:471`): retry once
    without the handoff call (`service.rs:2318-2335`).
  - `ENotReconfiguring`, `EReconfigWindowClosed`, `EWrongReconfigEpoch`:
    target dead; stop.
  - Non-Move errors: retry.
  - Any other Move abort: panic (`service.rs:2045-2065`), which is a crash and
    restart.

### 2.4 Bridge stall during reconfiguration

All BTC committee steps except `confirm_withdrawal` stop while a
reconfiguration is pending (section 4). A reconfiguration that cannot complete
halts the bridge for the rest of its Sui epoch. It is then aborted and
restarted. A new committee that fails every epoch halts the bridge
indefinitely. The only recovery is governance setting `reconfigHold` after an
abort, so that the last committed committee keeps serving.

## 3. Certificates

A certificate is a BLS aggregate over
`intent || hashi_id || epoch || bcs(message)` with a signer bitmap.
Verification (`committee.move:191-273`) requires `cert.epoch = committee.epoch`
and signer weight `>= ceil(totalWeight * 6667 / 10000)`.

- BTC operations verify against the **current** committee
  (`hashi.move:136`). A certificate therefore stops verifying once
  `end_reconfig` advances the epoch. An aborted reconfiguration leaves it valid.
- The intent separates message types. The epoch prevents replay across
  committees.
- For modelling, a certificate for message `m` at epoch `e` exists iff the
  members of `committees[e]` that signed `m` have weight at or above the
  threshold. Byzantine members sign anything. Honest members sign only after
  their local checks pass.

| Message | Intent | Signed by |
|---|---|---|
| `CommitteeTransitionRequest{newCommittee}` | 0x0001 | current committee |
| `ReconfigCompletionMessage{epoch, mpcKey}` | 0x0002 | pending committee |
| `PresigDealerSetMessage{epoch, batch, digest}` | 0x0007 | current committee |
| `DepositConfirmationMessage{requestId, utxo}` | 0x0100 | current committee |
| `RequestApprovalMessage{requestId}` | 0x0101 | current committee |
| `WithdrawalCommitmentMessage{requests, inputs, outputs, txid}` | 0x0102 | current committee |
| `MpcInputSignaturesMessage{wid, indices, sigs}` | 0x0103 | current committee |
| `WithdrawalSignedMessage{wid, mpcSigs, guardianSigs}` | 0x0104 | current committee |
| `WithdrawalConfirmationMessage{wid}` | 0x0105 | current committee |
| `StandardWithdrawalRequest{wid, utxos, ts, seq}` | 0x0106 | Guardian's committee; `cert.epoch` must equal the Guardian's committee epoch |

## 4. Gating

### 4.1 On chain

| Function | Paused blocks | Reconfiguring blocks | Certificate |
|---|---|---|---|
| deposit | yes | no | none |
| approve_deposit | yes | yes | DEPOSIT_CONFIRMATION |
| confirm_deposit | yes | yes | stored cert re-verified |
| delete_expired_deposit | no | no | none |
| request_withdrawal | yes | no | none |
| cancel_withdrawal | no | no | sender check |
| approve_request | yes | yes | REQUEST_APPROVAL |
| commit_withdrawal_tx | yes | yes | COMMITMENT |
| commit_input_signatures | yes | yes | MPC_INPUT_SIGNATURES |
| reallocate_presigs | yes | yes | none |
| finalize_withdrawal | yes | yes | WITHDRAWAL_SIGNED |
| confirm_withdrawal | yes | **no** | CONFIRMATION (outgoing committee during a reconfiguration) |
| archive_*, cleanup_spent_utxos | no | no | none |
| submit_dkg_cert, submit_rotation_cert, submit_nonce_cert | no | no | none verified; sender must control the dealer |
| submit_presig_dealer_set | no | no | PRESIG_DEALER_SET (current committee) |
| destroy_key_gen_certs, destroy_nonce_certs | no | no | none |
| reconfig, governance, registration | no | no | as in section 2 |

"Reconfiguring blocks" also blocks before genesis, since no current committee
exists.

### 4.2 Off chain

- Only the leader loop checks `paused`, from its own view
  (`leader/mod.rs:493-497`). An honest leader stops all leader work while
  paused, including broadcast, confirm, and garbage collection.
- Follower signing paths check neither pause nor reconfiguration. This covers
  the MPC signing RPC, the input-signature cert, and the Guardian-request cert
  (`withdrawals.rs:70-101, 956-976, 1403-1500`). A Byzantine member can
  therefore drive MPC signing and Guardian signing while paused.

## 5. UTXO pool

`UtxoPool` (`btc/utxo_pool.move`) has two maps. `utxo_records` maps a UTXO id
to `{utxo, producedBy, spentBy, spentEpoch}`. `spent_utxos` holds tombstones.

States of a UTXO id. `producedBy` and `spentBy` are independent:

| State | Encoding |
|---|---|
| Absent | in neither map |
| Available-confirmed | record, `producedBy = None`, `spentBy = None` |
| Available-pending | record, `producedBy = Some(W)`, `spentBy = None` (unconfirmed change, selectable) |
| Locked | record, `spentBy = Some(W')`, `producedBy` either value |
| MarkedSpent | Locked and `spentEpoch = Some(e)`, `producedBy` either value |
| Spent | tombstone only (permanent) |

Transitions:

- insert-active (deposit confirm) and insert-pending (change at commit). Both
  require the id to be Absent.
- confirm-pending (parent withdrawal confirm). It only clears `producedBy`. It
  is a no-op if the record is gone.
- lock (commit). It requires `spentBy = None`.
- mark-spent (withdrawal confirm).
- cleanup (anyone). It moves a MarkedSpent record to a tombstone.

No transition unlocks a UTXO. Child-before-parent confirmation on Sui is
reachable with an honest committee, because the two confirms are separate Sui
transactions. Move handles it: the child marks the pending record spent, and
the parent's later confirm-pending is a no-op.

## 6. Deposits

### 6.1 Request states

`Requested -> Approved(e, t) -> Confirmed`. `Approved(e, t) -> Approved(e', t')`
is allowed when `e # e'` (re-approval after a reconfiguration).
`Deleted` is reachable from `Requested` and `Approved` after expiry (1 day after
creation).

### 6.2 Actions

1. **SendDeposit** (user, Bitcoin): create a Bitcoin output to the address
   derived for Sui recipient `r`. A request without a recipient maps to the
   root address, which is also the change address (`deposits.rs:440-445`).
2. **Deposit(utxo)** (anyone, `btc/deposit.move:85`): requires unpaused,
   `amount >= max(min, 546)`, and the UTXO id not in the pool. Several requests
   may name the same UTXO id. The `Utxo` value is user-supplied and may be
   false. BTC sent in an amount below the minimum can never be requested.
3. **ApproveDeposit(req, cert)** (`deposit.move:132`): requires unpaused, not
   reconfiguring, UTXO id not in the pool, no stored cert from the current
   epoch, and a current-committee cert over `{requestId, utxo}`. Effect: store
   the cert and `approvedAt = now`.
   - Honest signer checks (`deposits.rs:95-246`): the request matches chain
     state; the UTXO id is not in the pool or tombstones; the Bitcoin output
     has `>= threshold` confirmations (`max(threshold, 100)` for coinbase,
     `deposit_tracker.rs:595`); it is unspent at the Bitcoin Core tip; its
     amount and script match. Optional sanctions screening.
4. **ConfirmDeposit(req)** (anyone, `deposit.move:197`): requires unpaused,
   not reconfiguring, UTXO id not in the pool, the stored cert re-verifies
   against the **current** committee, and `approvedAt + delay <= now`
   (default 10 min). Expiry is not checked. Effect: mint `amount` to `r` if a
   recipient is set, insert the UTXO as Available-confirmed, move the request
   to `processed`.
5. **DeleteExpiredDeposit(req)** (anyone): requires `now > created + 1 day`.
   The leader's garbage collection also deletes expired requests, including
   approved ones. The user can resubmit, since `deposit` checks only the pool.
6. After a reconfiguration the leader re-approves deposits that carry an
   old-epoch cert. Re-approval re-checks Bitcoin and restarts the delay.
   Repeated reconfigurations can therefore starve confirmation.

The node does not re-check Bitcoin between approval and confirm. Under the
assumption that reorgs are shallower than the threshold, this is safe. The
threshold is governable, so lowering it weakens this.

## 7. Withdrawals

### 7.1 Request states

`Requested -> Approved(e) -> Committed(W) -> Archived`, with `Cancelled`
reachable from `Requested` and `Approved`. Move allows re-approval with a
strictly newer cert, but honest signers refuse to approve a request that is
already approved (`withdrawals.rs:560-571`). Approvals are therefore never
refreshed, and commit accepts an approval from any epoch.

### 7.2 WithdrawalTransaction states

`Signing -> MpcComplete -> FullySigned -> Confirmed -> Archived`. `W` holds
the input list, outputs, change outputs, a `SigningBatch` (one slot per input,
each `Pending(presigIndex)` or `Signed(sig)`, plus the batch epoch), random
bytes, and guardian signatures.

### 7.3 Actions

1. **RequestWithdrawal(amount, addr)** (`btc/withdraw.move:105`): requires
   unpaused and `amount >= max(min, 547)`. `addr` is any 20- or 32-byte witness
   program, which may be a Hashi deposit address. Escrows `amount` hBTC.
2. **CancelWithdrawal(req)** (`withdraw.move:150`): sender only, after a
   1-hour cooldown from creation, only while not committed. Not gated by pause
   or reconfiguration. Returns the escrow. It can race a commit; the losing
   commit aborts.
3. **ApproveRequest(req, cert)** (`withdraw.move:186`): requires unpaused, not
   reconfiguring, not committed, and the stored cert absent or from an older
   epoch. Honest signers check that the request exists and is neither approved
   nor committed, and run optional screening. They make no Bitcoin, pool or
   limiter checks.
4. **CommitWithdrawalTx(requests, inputs, outputs, txid, cert)**
   (`withdraw.move:208`). On-chain requirements:
   - unpaused, not reconfiguring, a current-committee cert;
   - every input present in the pool and not Locked;
   - every request Approved (any epoch) and not Committed;
   - `sum(in) >= sum(out)`, an even fee split, and fee per request within the
     worst-case cap;
   - output `i` equal to `amount_i - feeShare` to request `i`'s address.

   Trailing outputs are change. Their addresses and amounts are not validated
   on chain. Effects: allocate `|inputs|` presig indices, lock the inputs, burn
   the escrowed hBTC, insert change as Available-pending, create `W`.
   Consequence: `sum(in) - sum(change) = sum(request amounts)`.

   Honest signer checks (`withdrawals.rs:591-855`) add:
   - no duplicate requests or inputs; caps on request count, input count,
     weight, and change-output count;
   - change goes to the root address with at least 330 sats;
   - every input has unconfirmed ancestor depth `< 25`;
   - fee within `[1 sat/vB, 3 x (own fee at clamped rate + CPFP deficit of
     unconfirmed ancestors)]`;
   - `inputs - change <= limiter max capacity`;
   - the txid matches the rebuilt transaction.

   An honest leader commits only when its view shows no `W` that is not fully
   signed (`leader/withdrawal_request_flow.rs:412`). Move does not enforce
   this, so concurrent leaders can create several such `W`. One `W` that never
   becomes fully signed blocks all later commits by honest leaders.
5. **SignInputs** (offchain MPC, section 8.4) then
   **CommitInputSignatures(W, indices, sigs, cert)**: requires unpaused, not
   reconfiguring, `W` not fully signed. Pending slots become Signed; Signed
   slots are unchanged. Move checks neither the batch epoch nor the signatures.
   Honest cert signers verify each signature against its sighash and derived
   key, but do not check the batch epoch or slot state
   (`withdrawals.rs:1149-1206`).
6. **ReallocatePresigs(W)** (anyone, no cert): requires unpaused, not
   reconfiguring, `W.batch.epoch # hashiEpoch`. Assigns fresh indices to the
   Pending slots and sets the batch epoch. It redraws randomness only if some
   slot is Pending. It succeeds on a `W` with all slots Signed, and then only
   retags the epoch.
7. **SignGuardianRequest(W, ts, seq)** (cert over
   `StandardWithdrawalRequest`, `leader/guardian.rs:58-68`). The leader picks
   `ts` from its latest checkpoint and `seq` from its local limiter mirror.
   Honest signers check only that `W` exists in their view and
   `|ts - own checkpoint time| <= 600 s` (`withdrawals.rs:956-976`). They do
   not check pause, reconfiguration, `seq`, the limiter, MPC completeness, or
   whether `W` is already fully signed.
8. **GuardianSign** (section 9.4).
9. **FinalizeWithdrawal(W, gsigs, cert)**: requires unpaused, not
   reconfiguring, all slots Signed, `W` not fully signed. Honest signers check
   their local limiter (`validate_consume(seq, ts, amount)`), the timestamp
   bound, all MPC and guardian signatures, the txid, and that
   `testmempoolaccept` reports no script failure. This check happens after the
   Guardian has consumed tokens.
10. **Broadcast**: rebuild the signed transaction and send it. An honest
    leader does this for fully signed `W` and repeats while the transaction is
    not found. Any party holding the MPC signatures (on chain) and the
    Guardian signatures (released) can broadcast without `FinalizeWithdrawal`.
11. **ConfirmWithdrawal(W, cert)**: requires unpaused, but not "not
    reconfiguring". `W` must be fully signed and not confirmed. Honest signers
    check `>= threshold` Bitcoin confirmations of the txid. Effects: mark
    inputs MarkedSpent, clear `producedBy` on change records.
12. **Archive / Cleanup** (anyone): move confirmed `W` and its requests to
    history; turn MarkedSpent records into tombstones.

### 7.4 Batching, change chaining, stuck transactions

- The leader takes approved requests oldest first, skips any above the limiter
  maximum, and stops at the first request that does not fit its local
  limiter's current capacity.
- Coin selection takes funding inputs largest first from confirmed and pending
  UTXOs. A pending UTXO must have mempool chain depth `<= 5`. Consolidation
  inputs are confirmed UTXOs only.
- A withdrawal can therefore spend unconfirmed change of an earlier
  withdrawal. Its fee covers the CPFP deficit of its unconfirmed ancestors.
  This is the only fee-bump mechanism. No RBF and no cancel path exist.
- A `W` whose input is invalid on Bitcoin (conflicting spend, deposit
  reorged deeper than the threshold, recovery spend) still reaches
  FullySigned, because the finalize mempool check blocks only script
  failures. It then rebroadcasts forever. Its hBTC is burned, its inputs stay
  locked, and its chained children are stranded. Nothing on chain removes or
  invalidates a pool record.

## 8. MPC: key generation, presignatures, signing

### 8.1 Thresholds

Let `W` be total committee weight before reduction. The code sets
`f = max(1, W * maxFaultyBps / 10000)`, `t = W - 2f`, and requires `t > f`.
`knapsack_reduce` then reduces member weights within
`weight_reduction_allowed_delta`, and returns a reduced `t` and `f`
(`mpc_except_signing.rs:6649-6700`). All MPC thresholds below use reduced
weight. Each reduced weight unit is one share index. A member reduced to 0
deals nothing.

- Dealer certificate (DKG, rotation): `t + f` of reduced weight.
- Nonce certificate: `W` (AVSS) or `W - f` (AVID).
- Completion, handoff, and seal certificates: 2/3 of unreduced weight.

### 8.2 DKG and rotation

1. Each dealer persists one dealing, then sends encrypted shares to all
   parties. A rotation dealer deals one message per previous share index it
   holds. Roles: new-committee member is dealer and party; old-only member is
   dealer only.
2. A receiver rejects a second, different message from the same dealer. It
   signs `{dealer, hash}` only if its own shares verify (and, for rotation,
   match the previous commitments).
3. The dealer posts its certificate to an onchain append-only log (TOB) for
   `(epoch, protocol)`. First submission per dealer wins. Move does not verify
   the certificate; nodes verify it offchain and skip invalid ones. A junk
   entry only excludes its own sender.
4. Every party reads the log in order. DKG takes the first prefix of valid
   dealers whose weight reaches `t`. Rotation takes the first
   `previousThreshold` share indices. Because the log order and the validity
   check are deterministic, all parties that finish derive the same key.
   Rotation also requires the new key to equal the old key and the on-chain
   key.
5. A party with bad shares from a selected dealer sends complaints to that
   certificate's signers. The default `complaint_response_policy` answers no
   complaints (`config.rs:253-262`). Such a party never gets an output in that
   epoch. A party can also end with `NoShares` or `NoRole`.
6. A party with an output signs `ReconfigCompletionMessage{epoch, key}` and
   serves it to peers. Nodes gather 2/3. For rotation they also gather the
   outgoing committee's handoff signatures (section 2.2).

Consequence: completion needs 2/3 of the new committee's weight to hold an
output. It does not imply that every honest member holds a share.

Rotation liveness also needs enough honest old-committee share holders online
in the new Sui epoch, including members that are no longer Sui validators.

### 8.3 Presignatures

- Per epoch, presignatures come in batches. Batch `k` is formed from AVID
  nonce dealings in the TOB, a dealer set fixed by a time window over the TOB
  order, and an admitted weight `>= W - f`. A seal
  (`submit_presig_dealer_set`, 2/3 cert, first-wins) stores the dealer-set
  digest and on-chain randomness. The seal does not store batch size or start
  index.
- Batch size is `(admittedWeight - (t - 1)) * BATCH_SIZE_PER_WEIGHT`
  (`service.rs:2495`). `BATCH_SIZE_PER_WEIGHT` is a code constant.
- A node maps a global index to `(batch, position)` by cumulative batch sizes
  (`signing.rs:914-960`). A node uses batch `k` only if the seal digest equals
  its own digest.
- `presigAllocator` is a counter on `Hashi`. `commit_withdrawal_tx` allocates
  `[c, c + n)` and stores `Pending(i)` in each input slot, tagged with the
  current epoch. Allocation is not tied to how many presignatures exist. An
  index beyond every generated batch, or in a batch that never sealed, cannot
  be signed in that epoch.
- `end_reconfig` resets the counter to 0. `abort_reconfig` does not. After an
  epoch change, Pending slots keep indices tagged with the old epoch.
  `reallocate_presigs` gives them indices in the new epoch.

### 8.4 Signing

Any committee member can ask a follower to sign any Pending slot at any time.
The follower signs input `j` of `W` with index `i` only if all of these hold
(`withdrawals.rs:1316-1430`, `signing.rs:960-1036`):

- the slot is `Pending(i)` in its view, tagged with its view epoch, and it has
  the signing manager for that epoch;
- the batch containing `i` is installed and contiguous with the previous one;
- the seal for that batch exists and its digest equals the local digest;
- the presig slot has not been taken in this process;
- the rebuilt transaction matches `W.txid`.

The request is `(sighash, derivationAddress, beacon)` where
`beacon = message_delta(W.randomness, j, sighash) + presig_delta(seal.randomness, i, R, digest)`
(`types.rs:1299-1325`). Partial signatures are cached in memory per
`(wid, j)`. A request that differs from the cached one is refused. A
concurrent second request for the same slot fails with `PoolExhausted`.

### 8.5 Nonce safety

**Property.** For each honest node and each of its underlying presignatures,
every partial signature the node releases over that presignature uses one
request `(sighash, derivationAddress, beacon)`. This must hold across crash and
restart. Two different beacons over one presignature reveal the node's share,
even with the same sighash.

**Argument.** Both maps below are functions of on-chain state:

- Index to slot. Within an epoch, index `i` goes to exactly one `(W, j)`.
  `reallocate` moves a slot to a new-epoch index and never re-issues an old
  one.
- Slot to request. The sighash depends on `W`'s inputs and outputs (txid
  checked), the MPC key, and the Guardian key. Both keys are write-once on
  chain. `W.randomness` changes only together with the epoch tag. The seal is
  first-wins.
- Index to presignature. Batch boundaries derive from TOB admission and the
  code constant.

After a restart, the node rebuilds presignatures from the TOB and its DB. It
re-enables only indices at or above the allocator and indices still Pending
with the current tag (`service.rs:956-976`). Re-signing then reproduces the
same partial signature.

**Residual case.** The index-to-presignature map depends on code. Example: a
node's digest for batch `k` disagrees with the seal, so it skips batch `k` and
computes a different size for it. Its digest for batch `k + 1` matches, and it
signs index `g1` with local position `p`. An upgrade in the same epoch changes
the size computation, so `p` now maps to `g2`. If `g2` is re-enabled, the node
signs a different request with presignature `p`. The same hazard applies to
mid-epoch changes of `BATCH_SIZE_PER_WEIGHT`, admission rules, sighash
construction, or delta derivation.

## 9. Guardian

### 9.1 Lifecycle

`None -> OperatorInitialized -> ProvisionerInitialized -> Activated`. Each step
requires its predecessor. Only process death leaves `Activated`. A single
mutex makes every RPC handler atomic. Every panic is a crash.

- `OperatorInit` installs the deployment config and the limiter config
  (`max`, `rate`). Limiter config is per session. Heartbeats start here.
- `ProvisionerInit` reconstructs the BTC key from key-provisioner shares.
- `OperatorActivate`:
  - requires its own last heartbeat at most 3 minutes old;
  - requires every other session's last heartbeat at least `Q = 10 min` old,
    including non-activated standbys, among heartbeats in the three hour
    directories around the reader's clock;
  - derives the committee from the committee-update record with the highest
    epoch (or the genesis record);
  - derives the limiter from the post-state with maximum `seq` in the newest
    non-empty withdraw hour directory and the hour before it, with tokens
    capped to the new `max`;
  - requires the derived state hash to equal the operator's pin;
  - logs activation, then installs the state.

### 9.2 Heartbeat fence

- Heartbeats run each minute. `hb[s]` is the start time of session `s`'s last
  acknowledged heartbeat.
- After its first heartbeat, a session starts a write attempt only if
  `now + 5 min < hb[s] + Q - 1 min`, i.e. before `hb[s] + 4 min`
  (`log_writer.rs:91-101`). Otherwise it panics.
- A write may become durable after its deadline. The enclave then panics, but
  the record is in S3.
- Abstraction: a durable record from session `s` has
  `durableTime < hb[s] + Q` in the reader's clock. `Activate(s')` requires
  `\A s # s' : now >= hb[s] + Q`.
- Assumptions (Guardian README): reader-ahead skew plus late durability under
  1 minute; writer-ahead skew under about 1 hour. With larger writer-ahead
  skew, heartbeats fall outside the scan window and limiter recovery can pick
  an older post-state.

### 9.3 UpdateCommitteeChain

Applies handoffs in order. A target epoch at or below the current one is a
no-op. Each handoff cert must have `cert.epoch` equal to the Guardian's
committee epoch and verify against that committee. The Guardian logs the update
to S3, then installs it. Epochs need not be contiguous.

The proxy forwards a handoff only if its fullnode shows a stored handoff with
the same `(cert.epoch, newCommittee.epoch)`. It does not compare committee
contents. The enclave does not check the chain.

The leader pushes stored handoffs once per Hashi epoch
(`leader/guardian.rs:41-47, 254-262`). If the Guardian is not activated at that
time, the push returns early and the per-epoch gate stays set. Until the push
succeeds, certs from the new committee fail at the Guardian, so finalize stalls.

### 9.4 StandardWithdrawal{wid, utxos, ts, seq, cert}

1. Require `Activated`.
2. Require `cert.epoch` equal to the Guardian's committee epoch, and verify.
3. Require `ts <= now + 300 s` and `now - ts <= 1800 s`.
4. Limiter: require `seq = nextSeq`, `ts >= lastTs`, and `cap = min(max,
   tokens + (ts - lastTs) * rate) >= amount` where `amount = inputs - change`.
   The enclave derives change scripts itself and the sighash commits to input
   amounts, so `amount` is exact. Set `tokens = cap - amount`, `lastTs = ts`,
   `nextSeq = nextSeq + 1`.
5. Sign every input. Write the withdraw record (request, cert, signatures,
   post-state) to S3. Reply only after the write succeeds.

**Release point.** The proxy replays signatures from the S3 record without the
enclave (`widlog.rs:138-176`). A signature is therefore released when its
record becomes durable, not when the enclave replies.

**Proxy replay.** For a wid with a logged record, the proxy returns the logged
response whatever `seq` the request carries. Lookup and forward are not atomic
(`cache.rs:153-185`). Two requests for one wid can both miss and both reach the
enclave. If they carry `seq = n` and `seq = n + 1`, the enclave signs both and
debits the limiter twice. Replay data is kept for 30 days. A retry after that
reaches the enclave and consumes tokens again.

### 9.5 Local limiter mirror on nodes

- Each node seeds a copy from `GetGuardianInfo`. The seed includes any
  in-flight `W` the Guardian already consumed. The mirror advances when the
  node sees a `W` become fully signed, using its own `nextSeq` and the
  finalize checkpoint time. A seed taken during an in-flight `W` therefore
  counts that `W` twice and runs one `seq` ahead.
- Every 15 s the node reconciles. If its `seq` is behind the Guardian's `seq`
  from about 5 minutes earlier, or ahead of the current Guardian `seq`, it
  snaps to the Guardian. If `seq` is equal and tokens differ, it snaps tokens.
- A leader with a mirror ahead of the Guardian presents a future `seq` and
  gets a mismatch. A leader with a mirror behind presents a consumed `seq`,
  which also mismatches unless the wid is replayed. Concurrent leaders race on
  one `seq`; the loser gets a mismatch.
- With a Guardian configured, each leader runs at most one signing task, oldest
  `W` first. A `W` blocked on a `seq` mismatch blocks the rest.

## 10. Governance

- Proposals are created and voted by current committee members. Before
  genesis, any registered member can create one, but none can execute until a
  committee exists. Creating a proposal casts the creator's vote. Execution is
  permissionless.
- Execution needs `sum(weight of voters in the current committee) >=
  threshold`. The threshold is fixed when the proposal is created. Votes
  persist across epochs and are re-weighted against the committee at execution
  time. `remove_vote` does not require committee membership. Expiry is 7 days.
- `EmergencyPause`: pause threshold 5%, unpause threshold 2/3. A single member
  with 5% weight can pause alone. More than 1/3 Byzantine weight can block
  unpause.
- `UpdateConfig` (2/3) can set `paused`, `reconfig_hold`, governance
  thresholds, delays, and the confirmation threshold. Values are not bounded
  on chain.
- `UpdateEpochConfig` (2/3) changes MPC parameters; the next committee formed
  copies them.
- `IgnoreMember` (2/3) excludes a member from the next committee formed.
- `EnableVersion`, `DisableVersion`, `Upgrade` (2/3) manage package versions.
  Disabling a version stops every entry function in it.
- Pause and hold do not block reconfiguration completion or abort.

## 11. Properties to check

Unless stated, safety properties assume Byzantine weight below the certificate
threshold in every committee, reorgs shallower than a fixed confirmation
threshold, and no recovery-leaf or out-of-band spends.

### Safety: chain state (no honesty assumption)

1. **Supply.** With a history variable `donated` (total amount of confirmed
   deposits that had no recipient):
   `hBTCSupply + donated = sum(amount of pool records with spentBy = None)`.
   Escrowed hBTC counts in supply. Pending change counts in the pool.
2. **No double mint.** A UTXO id is inserted into the pool at most once, ever.
3. **Single lock.** A UTXO id is locked by at most one `W`, and never unlocked.
4. **Request integrity.** A withdrawal request is committed at most once and
   is never both cancelled and committed. Its user output equals
   `amount - feeShare` to the requested address.
5. **Key continuity.** `mpcKey` never changes after genesis.
6. **Reconfiguration.** `hashiEpoch` increases strictly. Completion succeeds
   only with a certificate from the committee formed in the same Sui epoch. At
   most one committee completes per Sui epoch. A certificate for an aborted
   epoch never completes its replacement. After genesis, a committee exists
   for `hashiEpoch`.
7. **Handoff chain.** For consecutive completed epochs `a < b` after genesis,
   `handoffs[a] = {b, cert by committees[a] over committees[b]}`.
8. **Pause (chain).** While paused, no mint, approval, commit, input-signature
   commit, finalize, or confirm succeeds.

### Safety: with honest-majority assumptions

9. **Deposit soundness.** Confirming request `r` implies a Bitcoin output at
   `r.utxo.id` with the stated amount and the script derived from `r`'s
   recipient, with `>= threshold` confirmations at approval.
10. **Record soundness.** Every Available-confirmed record matches an unspent
    Bitcoin output with the same amount and script. Every Available-pending
    record's producer `W` is committed, and the output appears in `W`'s
    transaction.
11. **Backing.** With `Out(W) = sum(inputs(W)) - sum(change(W))`:
    `value(Hashi-script UTXOs unspent on Bitcoin) >= hBTCSupply + sum(Out(W) :
    W committed /\ W.tx not confirmed on Bitcoin)`.
12. **No double spend.** Two different transactions signed by MPC and Guardian
    never spend the same input.
13. **Withdrawal confirmation soundness.** `W` confirmed on Sui implies
    `W.txid` has `>= threshold` confirmations on Bitcoin.
14. **Completion.** Every honest signer of a completion certificate holds a
    share of `mpcKey`. Honest share-holding weight in each completed
    committee reaches the MPC threshold.
15. **Nonce safety.** Section 8.5 property, plus:
    - two Pending slots with the same tag have different indices;
    - every `Pending(i)` tagged `hashiEpoch` has `i < allocator`;
    - `W.batch.epoch <= hashiEpoch`, and at most one reallocation per `W` per
      epoch;
    - an honest node signs `Pending(i)` tagged `e` only with its epoch-`e`
      presignatures;
    - (model assumption, which 8.5's residual case breaks) each node's
      index-to-presignature map is injective and fixed within an epoch.
16. **Guardian committee.** The Guardian's epoch never decreases.
    `guardianEpoch <= hashiEpoch`. For each epoch the Guardian adopts, its
    committee equals the chain's stored committee for that epoch, provided the
    proxy is the only path to the enclave, its fullnode is correct, and the
    outgoing committee is below the Byzantine threshold.
17. **Guardian transaction binding.** Every Guardian-signed transaction equals
    the transaction of some on-chain `W`. (Requires an honest committee; the
    Guardian keeps no UTXO state.)
18. **Rate limit.** Over durable withdraw records with consecutive `seq`
    `i < j`: `sum(amount_i..amount_j) <= max + rate * (ts_j - ts_i)`, and each
    `ts_k` lies in `[proc_k - 1800 s, proc_k + 300 s]`. In Guardian time, this
    bounds outflow in a window by `max + rate * (window + 2100 s)`. With an
    honest committee and checkpoint time tracking real time, the bound is
    `max + rate * (window + 900 s)`. Both hold for one limiter config only.
19. **Single Guardian log.** Durable withdraw records form a single chain with
    no two records sharing a `seq`. Each activated session's recovered state is
    the post-state of the highest durable `seq`, capped by its config. (Under
    the skew assumptions in 9.2.)
20. **Pause (Guardian path).** After a pause, Guardian signatures for an
    existing `W` can still be obtained by a Byzantine member, and an
    MPC-complete `W` can reach Bitcoin. This is expected behaviour to confirm,
    not a property to prove.

### Liveness

Assume fairness, an honest and live 2/3 in both outgoing and incoming
committees, protocols that finish within one Sui epoch, an available Guardian
with refill, and Bitcoin that eventually mines any relayed transaction above
the minimum relay fee.

1. **Deposit.** For a valid deposit output `u`: while no request for `u` is
   confirmed, `Deposit(u)` stays enabled. If the system is unpaused and not
   reconfiguring for `delay + epsilon` after approval, some request for `u` is
   confirmed before expiry.
2. **Withdrawal commit.** An approved request with `amount <= max` and
   `amount >= feeShare + 546` is eventually committed or cancelled, provided
   enough Available value exists within chain-depth limits and every earlier
   `W` becomes fully signed.
3. **Withdrawal completion.** Every committed `W` eventually becomes
   FullySigned and Confirmed, provided every allocated index lies in a sealed
   batch (or is reallocated in a later epoch), every input exists on Bitcoin
   with no conflicting spend, and its parents confirm.
4. **Sui-side confirmation.** Once `W.txid` has threshold confirmations and the
   system is unpaused, `ConfirmWithdrawal(W)` eventually happens.
5. **Reconfiguration.** Every pending reconfiguration is eventually completed
   or aborted. If `reconfigHold` is eventually always false and the per-epoch
   assumptions hold, `hashiEpoch = suiEpoch` holds infinitely often. This
   needs a fairness assumption on `StartReconfig` that the node does not fully
   provide (section 2.3).
6. **Guardian.** `guardianEpoch` eventually equals `hashiEpoch`. Tokens
   consumed for `W` imply `W` eventually becomes FullySigned (no pause, proxy
   index available).
7. **Limiter mirror.** Each node's mirror and the Guardian's limiter
   eventually agree.

## 12. Flagged points

Status after review: **confirmed** (behaviour exists and matters),
**by design**, **benign**, or **overstated**.

| # | Point | Status |
|---|---|---|
| 1 | Stale-epoch presig use is blocked only offchain. `commit_input_signatures` does not check `batch.epoch`, and indices restart each epoch. | Benign. Honest nodes check the tag with the same epoch they use to pick the pool; pools are separate per epoch. Worth a model check. |
| 2 | Nonce reuse after restart. | Mostly closed (8.5). Residual case: a code change in the middle of an epoch that changes the index-to-presignature map, after a digest mismatch. |
| 3 | `reallocate_presigs` has no certificate. | Overstated. It acts only on stale slots and cannot run during current-epoch signing. |
| 4 | Guardian follows any handoff its current committee signs. Honest members sign handoffs to targets that are later aborted. | Confirmed. Closed by the proxy gate, which matches by epoch numbers only and trusts its fullnode. |
| 5 | Proxy wid dedup is not atomic. | Confirmed. Two requests for one wid at `seq` `n` and `n + 1` both get signed; the limiter is debited twice. No extra BTC moves. |
| 6 | Limiter mirror divergence; finalize check after Guardian consumes. | Confirmed, liveness only. Recovers through replay and the 5-minute snap. |
| 7 | "One unsigned `W` at a time" is offchain only. | Confirmed. Concurrent leaders race on `seq`. Head-of-line blocking. |
| 8 | Burn before signing; no cancel path. | Confirmed. Relief only through CPFP by children. Permanent if an input is invalid on Bitcoin (7.4). |
| 9 | Change outputs are not validated on chain. | Confirmed. Relies on an honest 2/3 (address, amount, txid). |
| 10 | Withdrawal approvals from old epochs accepted at commit. | By design. Honest nodes never refresh approvals. |
| 11 | Deposits not re-checked between approve and confirm. | Overstated under the reorg assumption. Real if governance lowers the confirmation threshold. |
| 12 | `confirm_withdrawal` is not reconfig-gated. | Benign. Soundness rests on the Bitcoin check. |
| 13 | Complaint responses are off by default. | Confirmed by `DkgOutputs`. With default `mpc_max_faulty_in_basis_points = 3333`, one Byzantine member of weight below `f` can block every DKG or rotation: its certificate enters the prefix, it gives bad shares to `f` honest weight, and it withholds its completion signature. Each pending reconfiguration then aborts, which halts the bridge (2.4). |
| 14 | Dealer certs are not verified on chain. | Confirmed, low impact. A junk entry excludes only its sender. |
| 15 | Child-before-parent confirmation on Sui. | Benign. Reachable with an honest committee; Move handles it. |
| 16 | Governance votes persist across epochs. | Confirmed. Non-members count 0. |
| 17 | Recovery leaf lets the MPC key alone spend UTXOs older than 60 days. | Confirmed. Bypasses the Guardian and the limiter. |
| 18 | Followers do not check pause or reconfiguration on the signing and Guardian-request paths. | Confirmed. A single Byzantine member can obtain Guardian signatures while paused. |
| 19 | A Guardian push that runs while the Guardian is not activated sets the per-epoch gate anyway. | Confirmed. Finalize stalls until the next Hashi epoch. |
| 20 | `start_reconfig` triggers are bounded and clearing `reconfigHold` triggers nothing. | Confirmed, liveness. |
| 21 | Limiter config is per Guardian session; activation only caps tokens. | Confirmed. A rotation can raise `max` or `rate`. |
| 22 | A Guardian-activation seed taken during an in-flight `W` counts that `W` twice in node mirrors. | Confirmed. Produces the mirror-ahead state that enables point 5. |

## 13. Model decomposition

Each module abstracts the others into nondeterministic environment actions.
Amounts and time use small integer domains. Every module models per-node views
that lag the chain.

1. **`Reconfig`**: Sui epoch; start, end, abort, standalone handoff; committee
   formation from a fixed validator set with registration flags; abstract MPC
   state (which members hold an output, old-committee resharing, output
   withholding); honest handoff signing for any committee on chain, exported as
   a set; bounded `start_reconfig` retries; `reconfigHold`, pause, ignore.
   Checks safety 5-7 and 14 and liveness 5.
2. **`Bridge`**: deposits, withdrawals, UTXO pool, treasury; a Bitcoin ledger
   with bounded reorgs, conflicting spends, recovery spends, and a mempool that
   can hold or evict transactions; CPFP as a precondition for a child to
   confirm; the honest-leader "no unsigned `W`" guard; abstract certificates
   with per-message honest predicates; epoch change as an event that
   invalidates stored deposit certs but not withdrawal approvals; the Guardian
   as a sign-or-refuse oracle. Checks safety 1-4, 8-13 and liveness 1-4.
3. **`Presig`**: allocator, `SigningBatch`, reallocation, batches with seals,
   per-node index-to-presignature maps, node signing with epoch checks, crash
   and restart, code change between restarts, epoch change and abort. Checks
   safety 15 and probes points 1-3.
4. **`Guardian`**: enclave lifecycle and sessions, heartbeat fence with an
   abstract clock and bounded skew, S3 log with durability as the release
   point, committee chain and the proxy gate, limiter, proxy replay without
   atomicity, node limiter mirrors with seeding and reconcile, concurrent
   leaders, the Guardian-request certificate with its weak honest predicate.
   Checks safety 16-20 and liveness 6-7, and probes points 4-7, 19, 21, 22.
