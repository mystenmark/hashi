# Hashi: informal protocol description for TLA+ modelling

This document describes the Hashi protocol at the level of detail a TLA+ model
needs. It abstracts cryptography into ideal objects (certificates, shares,
signatures). Sources are the design docs in `design/docs/`, the Move package in
`packages/hashi/sources/`, the node in `crates/hashi/src/`, and the Guardian in
`crates/hashi-guardian*/`. Citations use paths relative to those roots.

## 1. Actors

| Actor | Role | Fault model to consider |
|---|---|---|
| Sui chain | Holds the `Hashi` object. Executes entry functions atomically in a total order. Provides a Sui epoch counter and a clock. | Correct. |
| Sui validators | Register with Hashi. A registered subset forms each Hashi committee, weighted by Sui voting power. | Byzantine up to `t` of weight (safety); crashed up to `f` (liveness). |
| Committee nodes | Run the `hashi` service. Sign BLS certificates, run MPC (DKG, rotation, presigning, signing), drive leader work. | As above. Each node acts on a lagging local snapshot of the chain. |
| Leader | Any committee node. Rotation is `turn = checkpoint_height / 100`, `leader = turn mod n`. Turns overlap in practice. | Model as "any node may act as leader". |
| Guardian enclave | Second signer for every normal Bitcoin spend. Enforces a token-bucket limiter and verifies committee certificates. | Correct code. Process can crash. Two sessions may exist. |
| Guardian proxy | Front end for the enclave. Replays responses by withdrawal ID. Forwards committee handoffs only after the chain stores them. | Correct. Its check-then-forward is not atomic. |
| Bitcoin | Ledger of UTXOs. Transactions confirm after `bitcoin_confirmation_threshold` blocks (default 6). | Reorgs shallower than the threshold. |
| Users | Send BTC to deposit addresses. Submit deposit and withdrawal requests. Cancel withdrawals. | Arbitrary. Anyone can submit any `Utxo` value in a deposit request. |
| Governance | Committee proposals: pause, config, ignore member, upgrades. | Threshold of current committee weight. |

## 2. Epochs and committees

### 2.1 State

- `suiEpoch`: the Sui epoch. It only increases. It is an environment variable.
- `hashiEpoch` (`committee_set.epoch`): the epoch of the current committee. Only
  `end_reconfig` writes it.
- `committees`: a map from epoch to committee. It holds the current committee,
  every past committee, and the pending committee. A committee is a list of
  members with weights and keys, plus a snapshot of the epoch config.
- `pending`: `None` or `{epoch, handoffCert}`. A reconfiguration is in progress
  exactly when `pending` is not `None`.
- `mpcKey`: empty before genesis. The first `end_reconfig` sets it. It never
  changes afterwards.
- `handoffs`: a map from source epoch to `{nextEpoch, cert}`.
- `members`: registration records with flags `ignored`, `resigned`, and
  next-epoch keys. These flags are read only when a committee forms.
- `launched`: set once by `finish_publish`. It gates genesis only.
- `reconfigHold`, `paused`: config flags written by governance.

Invariant expected after genesis: `hashiEpoch <= pending.epoch <= suiEpoch`.
Hashi epochs are a subsequence of Sui epochs and can skip values.

### 2.2 Actions

**SuiEpochAdvance** (environment): `suiEpoch' = suiEpoch + 1`.

**StartReconfig** (anyone, `core/reconfig.move:85`). Preconditions:
`!reconfigHold`, `pending = None`, genesis implies `launched`, no committee
exists for `suiEpoch`, and `hashiEpoch = 0 \/ hashiEpoch # suiEpoch`. The
action forms committee `C` from active Sui validators that are registered, not
ignored, not resigned, and have keys set. It sets `committees[suiEpoch] = C`
and `pending = {suiEpoch, None}`. `C` must be non-empty.

**DKG / KeyRotation** (offchain, section 6). The pending committee runs DKG if
`mpcKey` is empty and key rotation otherwise. Each member that finishes holds
an output: its shares and the group key.

**SubmitCommitteeHandoff(e, cert)** (rotation only, `reconfig.move:178`).
Preconditions: `pending.epoch = e = suiEpoch`, `mpcKey` non-empty, `cert` is
signed by 2/3 of the **current** committee over
`CommitteeTransitionRequest{committees[e]}`, and no handoff cert is stored yet
on `pending`. Effect: `pending.handoffCert = cert`.

**EndReconfig(key, cert)** (`reconfig.move:109`). Preconditions:
`pending.epoch = n = suiEpoch` where `n = cert.epoch`, `cert` is signed by 2/3
of the **pending** committee over `ReconfigCompletionMessage{n, key}`. If
`mpcKey` is empty it is set to `key`. Otherwise a handoff cert must be present
and `key = mpcKey`. Effects: `hashiEpoch' = n`, `pending' = None`, the presig
allocator resets to 0, and the handoff is stored at `handoffs[oldEpoch]`.
Nodes submit the handoff and `end_reconfig` in one Sui transaction.

**AbortReconfig(e)** (anyone, no certificate, `committee_set.move:526`).
Preconditions: `pending.epoch = e` and `e # suiEpoch`. Effects:
`pending' = None` and `committees[e]` is removed. `hashiEpoch`, the current
committee and `mpcKey` are unchanged. At genesis Hashi returns to its
pre-genesis state.

Completion requires `pending.epoch = suiEpoch`. Abort requires
`pending.epoch # suiEpoch`. The two are therefore never both enabled. An
aborted epoch number is never reused, because `suiEpoch` has passed it.

**Registration and membership** (`validator.move`): register, set next-epoch
BLS key (with proof of possession bound to the current Sui epoch), set
encryption key, set TLS key, resign, withdraw resignation, remove inactive
member. None of these alter the current or pending committee.

### 2.3 Node reconfiguration driver (`mpc/service.rs:213-325, 1798-2118`)

- A node submits `start_reconfig` on a Sui epoch change, on an observed abort,
  and at startup. It does not submit while `reconfigHold` is set.
- When the node sees `suiEpoch > pending.epoch`, it submits `abort_reconfig`
  and then a fresh `start_reconfig`.
- The node runs the MPC protocol while its target is pending and inside the
  window. Once it has an output it loops on `end_reconfig`. It treats
  `EReconfigAlreadyCompleted` as success and `ENotReconfiguring`,
  `EReconfigWindowClosed`, `EWrongReconfigEpoch` as "target dead". It panics on
  any other Move abort, which is a crash and restart.

## 3. Certificates

A certificate is a BLS aggregate over
`intent || hashi_id || epoch || bcs(message)` with a signer bitmap.
Verification (`committee.move:191-273`) requires `cert.epoch = committee.epoch`
and signer weight `>= ceil(totalWeight * 6667 / 10000)`.

- BTC operations verify against the **current** committee
  (`hashi.move:136`). A certificate therefore stops verifying once
  `end_reconfig` advances the epoch. An aborted reconfiguration leaves it valid.
- The intent provides domain separation between message types. The epoch
  provides replay protection across committees.
- For modelling, a certificate for message `m` at epoch `e` exists iff the set
  of members of `committees[e]` that signed `m` has weight at or above the
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
| `StandardWithdrawalRequest{wid, utxos, ts, seq}` | (guardian) | committee known to the Guardian |

## 4. Gating

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
| confirm_withdrawal | yes | **no** | CONFIRMATION |
| archive_*, cleanup_spent_utxos | no | no | none |
| reconfig, governance, registration | no | no | as in section 2 |

"Reconfiguring blocks" also blocks before genesis, since no current committee
exists.

## 5. UTXO pool

`UtxoPool` (`btc/utxo_pool.move`) has two maps. `utxo_records` maps a UTXO id
to `{utxo, producedBy, spentBy, spentEpoch}`. `spent_utxos` holds tombstones.

States of a UTXO id:

| State | Encoding |
|---|---|
| Absent | in neither map |
| Available-confirmed | record, `producedBy = None`, `spentBy = None` |
| Available-pending | record, `producedBy = Some(W)`, `spentBy = None` (unconfirmed change, selectable) |
| Locked | record, `spentBy = Some(W)` |
| MarkedSpent | Locked and `spentEpoch = Some(e)` |
| Spent | tombstone only (permanent) |

Transitions: insert-active (deposit confirm), insert-pending (change at
commit), confirm-pending (withdrawal confirm), lock (commit), mark-spent
(withdrawal confirm), cleanup (anyone). No transition unlocks a UTXO. Both
insert paths require the id to be Absent.

## 6. Deposits

### 6.1 Request states

`Requested -> Approved(e, t) -> Confirmed`, with `Deleted` reachable from
`Requested` and `Approved` after expiry (1 day after creation).

### 6.2 Actions

1. **SendDeposit** (user, Bitcoin): create a Bitcoin output to the derived
   deposit address for Sui recipient `r`.
2. **Deposit(utxo)** (anyone, `btc/deposit.move:85`): requires unpaused,
   `amount >= max(min, 546)`, and the UTXO id not in the pool. Several requests
   may name the same UTXO id. The `Utxo` value is user-supplied and may be
   false.
3. **ApproveDeposit(req, cert)** (`deposit.move:132`): requires unpaused, not
   reconfiguring, UTXO id not in the pool, no stored cert from the current
   epoch, and a current-committee cert over `{requestId, utxo}`. Effect: store
   cert and `approvedAt = now`.
   - Honest signer checks (`deposits.rs:95-246`): the request matches chain
     state, the UTXO id is not in the pool or tombstones, the Bitcoin output
     has `>= threshold` confirmations, is unspent at the Bitcoin Core tip, and
     has the stated amount and script. Optional sanctions screening.
4. **ConfirmDeposit(req)** (anyone, `deposit.move:197`): requires unpaused,
   not reconfiguring, UTXO id not in the pool, stored cert re-verifies against
   the **current** committee, and `approvedAt + delay <= now` (default 10
   min). Expiry is not checked. Effect: mint `amount` to `r` if the
   derivation path is set, insert the UTXO as Available-confirmed, move the
   request to `processed`.
5. **DeleteExpiredDeposit(req)** (anyone): requires `now > created + 1 day`.
6. After a reconfiguration the leader re-approves deposits that carry an
   old-epoch cert. That restarts the delay.

The node does not re-check Bitcoin between approval and confirm.

## 7. Withdrawals

### 7.1 Request states

`Requested -> Approved(e) -> Committed(W) -> Archived`, with `Cancelled`
reachable from `Requested` and `Approved`.

### 7.2 WithdrawalTransaction states

`Signing -> MpcComplete -> FullySigned -> Confirmed -> Archived`. `W` holds
the input list, outputs, change outputs, a `SigningBatch` (one slot per input,
each `Pending(presigIndex)` or `Signed(sig)`, plus the batch epoch), random
bytes, and guardian signatures.

### 7.3 Actions

1. **RequestWithdrawal(amount, addr)** (`btc/withdraw.move:105`): requires
   unpaused and `amount >= max(min, 547)`. Escrows `amount` hBTC.
2. **CancelWithdrawal(req)** (`withdraw.move:150`): sender only, after a
   1-hour cooldown from creation, only while not committed. Not gated by pause
   or reconfiguration. Returns the escrow.
3. **ApproveRequest(req, cert)** (`withdraw.move:186`): requires unpaused, not
   reconfiguring, not committed, and the stored cert absent or from an older
   epoch. Honest signers check that the request exists and run optional
   screening. They make no Bitcoin, pool or limiter checks.
4. **CommitWithdrawalTx(requests, inputs, outputs, txid, cert)**
   (`withdraw.move:208`): requires unpaused, not reconfiguring, a
   current-committee cert, every input present in the pool and not Locked,
   every request Approved (any epoch) and not Committed, `sum(in) >=
   sum(out)`, an even fee split, fee per request within the worst-case cap,
   and output `i` equal to `amount_i - fee_i` to request `i`'s address.
   Trailing outputs are change and are not validated on chain. Effects:
   allocate `|inputs|` presig indices, lock inputs, burn escrowed hBTC, insert
   change as Available-pending, create `W`.
   - Honest signer checks (`withdrawals.rs:591-855`) add: change goes to the
     root deposit address, ancestor depth `< 25`, fee within
     `[1 sat/vB, 3 x own estimate]`, `inputs - change <= limiter max
     capacity`, and txid matches the rebuilt transaction.
   - The leader commits only when no unsigned `W` exists. Move does not
     enforce this, so concurrent leaders can create several unsigned `W`.
5. **SignInputs** (offchain MPC, section 8) then
   **CommitInputSignatures(W, indices, sigs, cert)**: requires unpaused, not
   reconfiguring, `W` not fully signed. Pending slots become Signed; Signed
   slots are unchanged. The batch epoch is not checked on chain.
6. **ReallocatePresigs(W)** (anyone, no cert): requires unpaused, not
   reconfiguring, `W.batch.epoch # hashiEpoch`. Assigns fresh indices to the
   Pending slots, sets the batch epoch, redraws randomness.
7. **GuardianSign** (section 9) then **FinalizeWithdrawal(W, gsigs, cert)**:
   requires unpaused, not reconfiguring, all slots Signed, `W` not fully
   signed. Honest signers re-check their local limiter
   (`validate_consume(seq, ts, amount)`), and verify all MPC and guardian
   signatures and the txid.
8. **Broadcast** (any leader): rebuild the signed transaction from chain state
   and send it. Repeats while the transaction is not found.
9. **ConfirmWithdrawal(W, cert)**: requires unpaused (not reconfiguring is
   **not** required), `W` fully signed and not confirmed. Honest signers check
   `>= threshold` Bitcoin confirmations. Effects: mark inputs MarkedSpent,
   promote change to Available-confirmed.
10. **Archive / Cleanup** (anyone): move confirmed `W` and its requests to
    history; turn MarkedSpent records into tombstones.

### 7.4 Batching and change chaining

The leader takes approved requests oldest first, skips any above the limiter
maximum, and stops at the first request that does not fit its local
limiter's current capacity. Coin selection takes inputs largest first from
both confirmed and pending UTXOs. A withdrawal can therefore spend unconfirmed
change of an earlier withdrawal. If the parent never confirms, the child
cannot confirm either. No path exists to cancel or replace a committed `W`.

## 8. MPC: key generation, presignatures, signing

### 8.1 Thresholds

`W` is total committee weight after a knapsack weight reduction. `f =
max(1, W * maxFaultyBps / 10000)`, `t = W - 2f`, requiring `t > f`
(`mpc_except_signing.rs:6636-6705`). Dealer certificates need `t + f` of
reduced weight. Nonce certificates need `W` (AVSS) or `W - f` (AVID).
Completion and handoff certificates need 2/3 of unreduced weight.

### 8.2 DKG and rotation

1. Each dealer persists one dealing, then sends encrypted shares to all
   parties. A rotation dealer deals one message per previous share index it
   holds.
2. A receiver rejects a second, different message from the same dealer. It
   signs `{dealer, hash}` only if its own shares verify (and, for rotation,
   match the previous commitments).
3. The dealer posts its certificate to an onchain append-only log (TOB) for
   `(epoch, protocol)`. First submission per dealer wins. Move does not verify
   the certificate; nodes verify it offchain and skip invalid ones.
4. Every party reads the log in order. DKG takes the first prefix of valid
   dealers whose weight reaches `t`. Rotation takes the first
   `previousThreshold` share indices. Because the log order and the validity
   check are deterministic, all honest parties derive the same key. Rotation
   additionally requires the new key to equal the old key.
5. A party with bad shares from a selected dealer sends complaints to that
   certificate's signers. The default `complaint_response_policy` answers no
   complaints (`config.rs:253-262`).
6. The party signs `ReconfigCompletionMessage{epoch, key}` and gathers 2/3.
   For rotation it also gathers the outgoing committee's handoff signatures.
   Outgoing members sign a handoff for whatever committee is pending.

### 8.3 Presignatures

- Per epoch, presignatures come in batches. Batch `k` is formed from AVID
  nonce dealings in the TOB, a dealer set fixed by a time window, and a seal
  (`submit_presig_dealer_set`) carrying onchain randomness. A node uses batch
  `k` only if the seal digest equals its own dealer-set digest.
- `presigAllocator` is a counter on `Hashi`. `commit_withdrawal_tx` allocates
  `[c, c + n)` and stores `Pending(i)` in each input slot, tagged with the
  current epoch. `end_reconfig` resets the counter to 0. `abort_reconfig` does
  not.
- After an epoch change, Pending slots keep indices from the old epoch.
  `reallocate_presigs` gives them indices from the new epoch.

### 8.4 Signing and nonce safety

A node signs input `j` of `W` with presig index `i` only if
`W.batch.epoch = hashiEpoch` in its view. It rebuilds the transaction and
checks the txid. The presig slot is take-once per process. Partial signatures
are cached in memory per `(wid, input)`; a changed request is refused.

**Critical safety property:** for each `(epoch, presigIndex)`, at most one
message is ever signed. Signing two messages with one nonce leaks the key.

The argument relies on: unique allocation within an epoch; the onchain epoch
tag and the offchain epoch check; take-once slots; and, after restart,
re-signing the same message for still-Pending slots. Nothing on disk binds an
index to the message it was signed for, so the restart case depends on the
message being a deterministic function of chain state and node config.

## 9. Guardian

### 9.1 Lifecycle

`None -> OperatorInitialized -> ProvisionerInitialized -> Activated`. Each step
requires its predecessor. Only process death leaves `Activated`. A single
mutex makes every RPC handler atomic.

**OperatorActivate** requires: own heartbeat fresh, every other session's last
heartbeat at least `Q = 10 min` old, and a derived state hash equal to the
operator's pin. The derived state comes from S3: the latest committee update
(or genesis record) and the limiter post-state with maximum `seq` from the two
newest hour directories.

### 9.2 Heartbeat fence

Heartbeats run each minute. A session refuses to start a write whose deadline
reaches `lastHeartbeat + Q - skew` and panics instead. Releasing a signature
requires a successful S3 write. Model: `CanWrite(s) => now < hb[s] + Q - skew`
and `Activate(s')` requires `\A s # s' : now >= hb[s] + Q`.

### 9.3 UpdateCommitteeChain

Applies stored handoffs in order. A target epoch at or below the current one is
a no-op. Each handoff cert must verify against the Guardian's current
committee. The Guardian logs the update to S3, then installs it. The proxy
forwards only handoffs that are stored on chain; the enclave itself does not
check this.

### 9.4 StandardWithdrawal{wid, utxos, ts, seq, cert}

1. Require `Activated`.
2. Verify the cert against the Guardian's current committee at its epoch.
3. Require `ts <= now + 300 s` and `now - ts <= 1800 s`.
4. Limiter: require `seq = nextSeq`, `ts >= lastTs`, and `cap = min(max,
   tokens + (ts - lastTs) * rate) >= amount` where `amount = inputs - change`.
   Set `tokens = cap - amount`, `lastTs = ts`, `nextSeq = nextSeq + 1`.
5. Sign every input. Write the withdraw record to S3. Return signatures only
   after the write succeeds; a write failure crashes the process.

The proxy returns the logged response for a wid that is already signed,
whatever `seq` the request carries. The enclave has no wid dedup.

### 9.5 Local limiter mirror on nodes

Each node seeds a copy from `GetGuardianInfo`. It advances only when the node
sees a `W` become fully signed on chain, using the node's own `nextSeq` and the
finalize checkpoint time. Every 15 s it reconciles with the Guardian and snaps
to it on a stall or drift.

## 10. Governance

- Proposals: created and voted by current committee members. Execution needs
  `sum(weight of voters in the current committee) >= threshold`. Votes persist
  across epochs and are re-weighted against the committee at execution time.
  Expiry is 7 days.
- `EmergencyPause`: pause threshold 5%, unpause threshold 2/3.
- `UpdateConfig` can set `paused`, `reconfig_hold`, thresholds, delays.
- `IgnoreMember`: excluded from the next committee formed.
- Pause and hold do not block reconfiguration completion or abort.

## 11. Properties to check

### Safety

1. **Supply conservation.** `hBTCSupply = sum(amount of pool records with
   spentBy = None) - sum(amount of confirmed deposits with no recipient)`.
   Escrowed hBTC counts in supply.
2. **Backing.** Every Available pool record corresponds to an unspent Bitcoin
   output controlled by Hashi (given an honest supermajority). Stronger:
   `hBTCSupply <= value of Hashi-controlled Bitcoin UTXOs`.
3. **No double mint.** A Bitcoin output is minted at most once.
4. **No double spend.** A UTXO is locked by at most one `W`. Two different
   fully signed transactions never spend the same input.
5. **Request integrity.** A withdrawal request is committed at most once and
   is never both cancelled and committed. Its user output equals
   `amount - feeShare` to the requested address.
6. **Nonce safety.** At most one message per `(epoch, presigIndex)` is signed.
7. **Key continuity.** `mpcKey` never changes after genesis. All honest
   members of a completed committee hold shares of `mpcKey`.
8. **Reconfiguration exclusivity.** Completion and abort never both succeed
   for one pending epoch. Epoch numbers are never reused.
9. **Guardian committee monotonicity.** The Guardian's committee epoch only
   increases, and it only adopts committees whose reconfiguration completed on
   chain.
10. **Rate limit.** Total guardian-signed outflow in any window is bounded by
    `max + rate * (window + 300 s)`.
11. **Single active Guardian.** At most one Guardian session can release
    signatures at any time.
12. **Pause.** No mint and no new guardian signature result from a committee
    step that started after a pause executed. (Needs care: confirm and
    broadcast continue.)

### Liveness (under fairness and an honest, live 2/3)

1. Every confirmed, valid deposit is eventually minted or its request expires.
2. Every approved withdrawal request that fits the limiter is eventually
   committed, unless cancelled.
3. Every committed `W` eventually becomes FullySigned and Confirmed.
4. Every pending reconfiguration either completes or is aborted, and Hashi
   eventually reaches `suiEpoch`.
5. The local limiter mirror and the Guardian limiter eventually agree.

## 12. Points the code exploration flagged

These are candidate model targets, not confirmed bugs.

1. **Stale-epoch presig use is blocked only offchain.** `commit_input_signatures`
   does not compare `batch.epoch` with `hashiEpoch`. After a reset, index `i`
   in epoch `e+1` collides numerically with a stale `Pending(i)` from epoch
   `e`.
2. **Nonce reuse across restart.** No persisted `(epoch, index) -> message`
   binding. The sighash depends on node-local config (guardian key, master
   `G`, leaf construction).
3. **`reallocate_presigs` takes no certificate.** Anyone can call it once per
   `W` per epoch, which changes the presig indices and randomness while
   signing is in progress.
4. **Guardian follows any handoff signed by its current committee.** After an
   abort, the outgoing committee may have signed handoffs to two different
   targets. Only the proxy's onchain check prevents adoption of the aborted
   one, and the Guardian cannot move backwards.
5. **Guardian wid dedup lives only in the proxy and is not atomic.** Two
   requests for one wid at `seq` `n` and `n+1` can both be signed, which
   debits the limiter twice.
6. **Limiter divergence.** The node mirror advances with a different timestamp
   from the Guardian, and the follower limiter check comes only at finalize,
   after the Guardian has already consumed tokens. A leader change can present
   a consumed `seq`.
7. **One unsigned `W` at a time is offchain only.** Concurrent leaders can
   commit several. The signer handles the oldest first, which can block on a
   `seq` mismatch.
8. **Burn before signing, and no cancel path.** A `W` whose signing or
   broadcast never completes leaves the user's hBTC burned and the inputs
   locked. Chained children are stranded with it.
9. **Change outputs are not validated on chain.** A wrong `txid` creates pool
   records with no Bitcoin output (relies on honest 2/3).
10. **Withdrawal approvals from old epochs are accepted at commit.**
11. **Deposits are not re-checked on Bitcoin between approve and confirm.** A
    reorg within the delay is not detected.
12. **`confirm_withdrawal` is not reconfig-gated** and verifies against the
    outgoing committee during a reconfiguration.
13. **Complaint responses are off by default.** A bad dealer can deny output to
    up to `f` of honest weight, which may keep the completion certificate
    below 2/3 for an entire Sui epoch.
14. **Dealer certs are not verified on chain.** Any registered member can fill
    its own first-wins slot, even if it is not in the committee.
15. **Child-before-parent confirmation is accepted on chain.** Only the
    committee's Bitcoin check prevents it.
16. **Governance votes persist across epochs** and are re-weighted at
    execution time.

## 13. Proposed model decomposition

A single spec with all of the above will not be tractable. Proposed modules,
each with its own invariants and a small configuration:

1. **`Reconfig`**: Sui epoch, start/end/abort/handoff, committee formation from
   a fixed validator set with registration flags, Byzantine signers as a
   subset. Checks properties 7, 8 and reconfiguration liveness.
2. **`Bridge`**: deposits, withdrawals, UTXO pool, treasury, a Bitcoin ledger
   with bounded reorgs, abstract committee certificates (honest-check
   predicates per message), pause, and epoch changes as an abstract event that
   invalidates certificates. Checks properties 1-5, 12.
3. **`Presig`**: allocator, `SigningBatch`, reallocation, node signing with
   epoch checks, crash and restart, epoch change. Checks property 6 and probes
   flagged points 1-3.
4. **`Guardian`**: enclave lifecycle, committee chain, limiter, proxy replay,
   heartbeat fence with an abstract clock, node limiter mirrors, concurrent
   leaders. Checks properties 9-11 and probes flagged points 4-7.

Each module abstracts the others into nondeterministic environment actions.
Amounts and time use small integer domains.
