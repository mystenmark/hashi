---------------------------- MODULE BridgeLimiter ----------------------------
(***************************************************************************)
(* Bridge composed with GuardianLimiter. The two share withdrawal ids and  *)
(* synchronise on three steps:                                             *)
(*                                                                         *)
(* - commit_input_signatures makes the withdrawal ready for the Guardian;  *)
(* - an enclave step that logs a record is the Guardian signature;         *)
(* - finalize_withdrawal needs both the Bridge preconditions and a quorum  *)
(*   of follower mirrors that accept (seq, ts, amount).                    *)
(*                                                                         *)
(* The limiter amount of a withdrawal is fixed per id (LAmt). A commit     *)
(* must batch requests totalling LAmt[w], which is inputs minus change.    *)
(* Honest commit signers also require LAmt[w] <= the mirror's max          *)
(* (check_commitment_outflow, withdrawals.rs:781-786).                     *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    DepOuts, DepAmt, DepUser, DepReqIds, Reqs, ReqAmt, Wids, MaxFee,
    MaxEpoch, HonestCerts, AllowRecovery, EnvFaults, LeaderGuard,
    Nodes, LAmt, Max, Rate, MaxTime, Past, Future, TsSkew, Quorum, Slack,
    MaxSnaps, SnapBehind, RotateTo

VARIABLES
    epoch, reconfiguring, paused, pool, tomb, supply, userBal, depReq, wreq,
    wtx, utxo, mempool, finalTx, mpcDone, gsig, donated, inserts, lockHist,
    now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies, ready, final,
    mirror, seen, snaps, gMax

B == INSTANCE Bridge
L == INSTANCE GuardianLimiter WITH Amt <- LAmt

bVars == <<epoch, reconfiguring, paused, pool, tomb, supply, userBal, depReq,
           wreq, wtx, utxo, mempool, finalTx, mpcDone, gsig, donated,
           inserts, lockHist>>
lVars == <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies, ready,
           final, mirror, seen, snaps, gMax>>
vars == <<bVars, lVars>>

Init == B!Init /\ L!Init

Commit(w, Q, I, fee, ch) ==
    /\ B!ReqTotal(Q) = LAmt[w]
    /\ HonestCerts => LAmt[w] <= gMax
    /\ B!CommitWithdrawal(w, Q, I, fee, ch)
    /\ UNCHANGED lVars

MpcRecorded(w) == B!CommitInputSignatures(w) /\ L!MpcComplete(w)

\* A logged record is the Guardian's signature; a refusal changes nothing in
\* Bridge.
EnclaveStep(r) ==
    /\ L!Enclave(r)
    /\ gsig' = IF log' # log THEN gsig \cup {r.wid} ELSE gsig
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   depReq, wreq, wtx, utxo, mempool, finalTx, mpcDone,
                   donated, inserts, lockHist>>

FinalizeStep(r) == L!Finalize(r) /\ B!FinalizeWithdrawal(r.wid)

LimiterOnly ==
    \/ L!Tick \/ L!Rotate
    \/ \E n \in Nodes, w \in Wids : L!Request(n, w)
    \/ \E r \in proxyIn : L!Proxy(r)
    \/ \E r \in replies : L!DropReply(r)
    \/ \E n \in Nodes : L!Observe(n) \/ L!Reconcile(n) \/ L!Restart(n)

Next ==
    \/ (B!CoreOpNext \/ B!EpochNext) /\ UNCHANGED lVars
    \/ \E w \in Wids, Q \in SUBSET Reqs, I \in SUBSET B!PoolIds,
          fee \in 0..MaxFee, ch \in BOOLEAN : Commit(w, Q, I, fee, ch)
    \/ \E w \in Wids : MpcRecorded(w)
    \/ \E r \in enclaveQ : EnclaveStep(r)
    \/ \E r \in replies : FinalizeStep(r)
    \/ LimiterOnly /\ UNCHANGED bVars

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

SupplyInv == B!SupplyInv
BalanceInv == B!BalanceInv
NoDoubleInsert == B!NoDoubleInsert
SingleLock == B!SingleLock
DepositSound == B!DepositSound
RecordSound == B!RecordSound
Backing == B!Backing
NoDoubleSpend == B!NoDoubleSpend
ConfirmSound == B!ConfirmSound
NoDoubleConsume == L!NoDoubleConsume
SeqRateBound == L!SeqRateBound

\* Bridge's Guardian signatures are exactly the enclave's logged records.
GsigLogged == gsig = {r.wid : r \in log}

\* The limiter's ready set is Bridge's MPC-recorded, unfinalized withdrawals.
\* With GsigLogged, GuardianLimiterSeq's ReadyConsumed becomes Bridge's
\* GuardianSigns.
ReadyIsMpcRec ==
    \A w \in Wids : (w \in ready) <=> (wtx[w].st = "signing" /\ wtx[w].mpcRec)

\* A finalized withdrawal was logged by the Guardian.
FinalizedLogged ==
    \A w \in Wids : wtx[w].st \in {"full", "conf"} => L!HasLog(w)

\* R11 with R4: every withdrawal still awaiting the Guardian fits the current
\* session's max, so it can be signed once the bucket refills.
SignableByGuardian ==
    \A w \in Wids : (wtx[w].st = "signing" /\ w \notin gsig) => LAmt[w] <= gMax

Stuck == \E w \in Wids : wtx[w].st = "signing" /\ w \notin gsig /\ LAmt[w] > gMax

\* Without a later session that raises max, a stuck withdrawal stays stuck.
StuckIsPermanent == [](Stuck => []Stuck)

\* While one withdrawal is stuck, no other is committed (R4).
StuckBlocksCommits ==
    [][Stuck => \A v \in Wids : wtx[v].st = "none" => wtx'[v].st = "none"]_vars

\* Coverage probes: each should be violated.
NeverFinalized == \A w \in Wids : wtx[w].st \notin {"full", "conf"}
NeverBothFinalized == \E w \in Wids : wtx[w].st \notin {"full", "conf"}

=============================================================================
