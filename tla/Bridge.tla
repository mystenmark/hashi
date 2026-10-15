------------------------------- MODULE Bridge -------------------------------
(***************************************************************************)
(* Deposits, withdrawals, the UTXO pool, and hBTC supply against a         *)
(* Bitcoin ledger (PROTOCOL.md 5, 6, 7).                                   *)
(*                                                                         *)
(* Bitcoin has two levels. A transaction is in the mempool or final        *)
(* (confirmed to the threshold). Final transactions are never reorged.     *)
(* Mempool transactions can be evicted. A transaction mines only when its  *)
(* inputs are final and unspent.                                           *)
(*                                                                         *)
(* Certificates are abstract. With HonestCerts, a certificate exists only  *)
(* when the honest-signer checks for that message pass. Without it, any    *)
(* certificate exists, which checks properties that hold on chain alone.   *)
(*                                                                         *)
(* MPC signing and Guardian signing are offchain flags without pause or    *)
(* reconfiguration gates (PROTOCOL.md 4.2). Anyone holding both sets of    *)
(* signatures can broadcast.                                               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    DepOuts,        \* Bitcoin deposit outputs users may create
    DepAmt,         \* DepOuts -> amount
    DepUser,        \* DepOuts -> TRUE if derived for a user recipient
    DepReqIds,      \* deposit requests: <<output, claimed amount, claimed user>>
    Reqs,           \* withdrawal request ids
    ReqAmt,         \* Reqs -> amount
    Wids,           \* withdrawal transaction ids
    MaxFee,         \* max miner fee per request
    MaxEpoch,       \* committee epochs are 0..MaxEpoch
    HonestCerts,    \* certificates require honest-signer checks
    AllowRecovery,  \* the MPC key alone may spend Hashi outputs (60-day leaf)
    EnvFaults,      \* pause, reconfiguration, and mempool eviction may occur
    LeaderGuard     \* commits require no W awaiting signatures (honest leader)

None == "none"
ChangeId(w) == <<w, 0>>
UserOutId(w, q) == <<w, q>>
PoolIds == DepOuts \cup {ChangeId(w) : w \in Wids}
DepTx(o) == <<"dep", o>>
WTx(w) == <<"w", w>>
RecTx(id) == <<"rec", id>>

\* Sum of f[x] over x in S, for a function f whose domain includes S.
RECURSIVE SumOver(_, _)
SumOver(S, f) ==
    IF S = {} THEN 0
    ELSE LET x == CHOOSE y \in S : TRUE IN f[x] + SumOver(S \ {x}, f)

VARIABLES
    \* Sui
    epoch, reconfiguring, paused,
    pool,       \* PoolIds -> [st, amt, prod]; st \in {absent, avail, locked, marked}
    tomb,       \* spent tombstones
    supply,     \* hBTC supply (includes escrow)
    userBal,    \* hBTC held by users outside escrow
    depReq,     \* DepReqIds -> [st, ep, delay, expired]
    wreq,       \* Reqs -> st \in {none, req, appr, comm, canc}
    wtx,        \* Wids -> [st, ins, reqs, fee, chg, chgHashi, mpcRec]
    \* Bitcoin
    utxo,       \* final unspent outputs: set of [id, amt, hashi]
    mempool,    \* txids broadcast and not final
    finalTx,    \* txids final
    \* Offchain
    mpcDone,    \* Wids whose MPC signatures exist
    gsig,       \* Wids whose Guardian signatures were released
    \* Ghost
    donated,    \* total of confirmed deposits with no recipient
    inserts,    \* PoolIds -> number of pool insertions ever
    lockHist    \* set of <<id, w>> lock events

suiVars == <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
             depReq, wreq, wtx>>
btcVars == <<utxo, mempool, finalTx>>
offVars == <<mpcDone, gsig>>
ghostVars == <<donated, inserts, lockHist>>
vars == <<suiVars, btcVars, offVars, ghostVars>>

NoRec == [st |-> "absent", amt |-> 0, prod |-> None]
NoW == [st |-> "none", ins |-> {}, reqs |-> {}, fee |-> 0, chg |-> 0,
        chgHashi |-> TRUE, mpcRec |-> FALSE]
NoDep == [st |-> "absent", ep |-> 0, delay |-> FALSE, expired |-> FALSE]

Init ==
    /\ epoch = 0 /\ reconfiguring = FALSE /\ paused = FALSE
    /\ pool = [id \in PoolIds |-> NoRec]
    /\ tomb = {}
    /\ supply = 0 /\ userBal = 0
    /\ depReq = [r \in DepReqIds |-> NoDep]
    /\ wreq = [q \in Reqs |-> "none"]
    /\ wtx = [w \in Wids |-> NoW]
    /\ utxo = {} /\ mempool = {} /\ finalTx = {}
    /\ mpcDone = {} /\ gsig = {}
    /\ donated = 0
    /\ inserts = [id \in PoolIds |-> 0]
    /\ lockHist = {}

-----------------------------------------------------------------------------
(* Bitcoin transactions *)

UtxoIds == {u.id : u \in utxo}

TxIns(t) ==
    CASE t[1] = "dep" -> {}
      [] t[1] = "w"   -> wtx[t[2]].ins
      [] t[1] = "rec" -> {t[2]}

TxOuts(t) ==
    CASE t[1] = "dep" ->
            {[id |-> t[2], amt |-> DepAmt[t[2]], hashi |-> TRUE]}
      [] t[1] = "w" ->
            LET x == wtx[t[2]]
            IN {[id |-> UserOutId(t[2], q), amt |-> ReqAmt[q] - x.fee,
                 hashi |-> FALSE] : q \in x.reqs}
               \cup (IF x.chg > 0
                     THEN {[id |-> ChangeId(t[2]), amt |-> x.chg,
                            hashi |-> x.chgHashi]}
                     ELSE {})
      [] t[1] = "rec" ->
            \* The amount leaves Hashi; it does not matter where it goes.
            {[id |-> <<"rec", t[2]>>, amt |-> 0, hashi |-> FALSE]}

MempoolOutIds == UNION {{o.id : o \in TxOuts(t)} : t \in mempool}

\* A transaction can enter the mempool when its inputs exist and no mempool
\* transaction spends them.
CanBroadcast(t) ==
    /\ t \notin mempool /\ t \notin finalTx
    /\ TxIns(t) \subseteq (UtxoIds \cup MempoolOutIds)
    /\ \A t2 \in mempool : TxIns(t) \cap TxIns(t2) = {}

Broadcast(t) ==
    /\ CanBroadcast(t)
    /\ mempool' = mempool \cup {t}
    /\ UNCHANGED <<suiVars, utxo, finalTx, offVars, ghostVars>>

Mine(t) ==
    /\ t \in mempool
    /\ TxIns(t) \subseteq UtxoIds
    /\ utxo' = {u \in utxo : u.id \notin TxIns(t)} \cup TxOuts(t)
    /\ mempool' = mempool \ {t}
    /\ finalTx' = finalTx \cup {t}
    /\ UNCHANGED <<suiVars, offVars, ghostVars>>

Evict(t) ==
    /\ EnvFaults
    /\ t \in mempool
    /\ mempool' = mempool \ {t}
    /\ UNCHANGED <<suiVars, utxo, finalTx, offVars, ghostVars>>

SendDeposit(o) == Broadcast(DepTx(o))

\* The 60-day recovery leaf: the MPC key alone spends a final Hashi output.
RecoverySpend(id) ==
    /\ AllowRecovery
    /\ \E u \in utxo : u.id = id /\ u.hashi
    /\ Broadcast(RecTx(id))

-----------------------------------------------------------------------------
(* Governance and epochs *)

Pause ==
    /\ EnvFaults
    /\ ~paused /\ paused' = TRUE
    /\ UNCHANGED <<epoch, reconfiguring, pool, tomb, supply, userBal, depReq,
                   wreq, wtx, btcVars, offVars, ghostVars>>

Unpause ==
    /\ paused /\ paused' = FALSE
    /\ UNCHANGED <<epoch, reconfiguring, pool, tomb, supply, userBal, depReq,
                   wreq, wtx, btcVars, offVars, ghostVars>>

StartReconfig ==
    /\ EnvFaults
    /\ ~reconfiguring /\ epoch < MaxEpoch
    /\ reconfiguring' = TRUE
    /\ UNCHANGED <<epoch, paused, pool, tomb, supply, userBal, depReq, wreq,
                   wtx, btcVars, offVars, ghostVars>>

EndReconfig ==
    /\ reconfiguring
    /\ reconfiguring' = FALSE /\ epoch' = epoch + 1
    /\ UNCHANGED <<paused, pool, tomb, supply, userBal, depReq, wreq, wtx,
                   btcVars, offVars, ghostVars>>

AbortReconfig ==
    /\ reconfiguring
    /\ reconfiguring' = FALSE
    /\ UNCHANGED <<epoch, paused, pool, tomb, supply, userBal, depReq, wreq,
                   wtx, btcVars, offVars, ghostVars>>

-----------------------------------------------------------------------------
(* Deposits *)

InPool(id) == pool[id].st # "absent" \/ id \in tomb

\* deposit(): anyone may claim any amount and recipient for an output id.
RequestDeposit(r) ==
    LET o == r[1] IN
    /\ ~paused
    /\ depReq[r].st \in {"absent", "deleted"}
    /\ ~InPool(o)
    /\ depReq' = [depReq EXCEPT ![r] = [NoDep EXCEPT !.st = "req"]]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   wreq, wtx, btcVars, offVars, ghostVars>>

\* Honest signers: the output is final and unspent, and amount and script match.
HonestDepositOk(r) ==
    LET o == r[1] IN
    /\ o \in UtxoIds
    /\ r[2] = DepAmt[o]
    /\ r[3] = DepUser[o]

ApproveDeposit(r) ==
    LET o == r[1] IN
    /\ ~paused /\ ~reconfiguring
    /\ depReq[r].st \in {"req", "appr"}
    /\ depReq[r].st = "appr" => depReq[r].ep # epoch
    /\ ~InPool(o)
    /\ HonestCerts => HonestDepositOk(r)
    /\ depReq' = [depReq EXCEPT ![r] = [@ EXCEPT !.st = "appr", !.ep = epoch,
                                                  !.delay = FALSE]]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   wreq, wtx, btcVars, offVars, ghostVars>>

DelayElapses(r) ==
    /\ depReq[r].st = "appr" /\ ~depReq[r].delay
    /\ depReq' = [depReq EXCEPT ![r].delay = TRUE]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   wreq, wtx, btcVars, offVars, ghostVars>>

Expire(r) ==
    /\ depReq[r].st \in {"req", "appr"} /\ ~depReq[r].expired
    /\ depReq' = [depReq EXCEPT ![r].expired = TRUE]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   wreq, wtx, btcVars, offVars, ghostVars>>

DeleteExpired(r) ==
    /\ depReq[r].st \in {"req", "appr"} /\ depReq[r].expired
    /\ depReq' = [depReq EXCEPT ![r] = [NoDep EXCEPT !.st = "deleted"]]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   wreq, wtx, btcVars, offVars, ghostVars>>

\* confirm_deposit: the stored cert must be from the current epoch.
ConfirmDeposit(r) ==
    LET o == r[1]
        a == r[2]
    IN
    /\ ~paused /\ ~reconfiguring
    /\ depReq[r].st = "appr" /\ depReq[r].ep = epoch /\ depReq[r].delay
    /\ ~InPool(o)
    /\ pool' = [pool EXCEPT ![o] = [st |-> "avail", amt |-> a, prod |-> None]]
    /\ inserts' = [inserts EXCEPT ![o] = @ + 1]
    /\ IF r[3]
       THEN /\ supply' = supply + a /\ userBal' = userBal + a
            /\ UNCHANGED donated
       ELSE /\ donated' = donated + a
            /\ UNCHANGED <<supply, userBal>>
    /\ depReq' = [depReq EXCEPT ![r].st = "done"]
    /\ UNCHANGED <<epoch, reconfiguring, paused, tomb, wreq, wtx, btcVars,
                   offVars, lockHist>>

-----------------------------------------------------------------------------
(* Withdrawals *)

RequestWithdrawal(q) ==
    /\ ~paused
    /\ wreq[q] = "none"
    /\ userBal >= ReqAmt[q]
    /\ wreq' = [wreq EXCEPT ![q] = "req"]
    /\ userBal' = userBal - ReqAmt[q]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, depReq,
                   wtx, btcVars, offVars, ghostVars>>

CancelWithdrawal(q) ==
    /\ wreq[q] \in {"req", "appr"}
    /\ wreq' = [wreq EXCEPT ![q] = "canc"]
    /\ userBal' = userBal + ReqAmt[q]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, depReq,
                   wtx, btcVars, offVars, ghostVars>>

ApproveRequest(q) ==
    /\ ~paused /\ ~reconfiguring
    /\ wreq[q] = "req"
    /\ wreq' = [wreq EXCEPT ![q] = "appr"]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   depReq, wtx, btcVars, offVars, ghostVars>>

ReqTotal(Q) == SumOver(Q, ReqAmt)
PoolTotal(I) == SumOver(I, [id \in I |-> pool[id].amt])

\* commit_withdrawal_tx. Honest signers require change to a Hashi address.
CommitWithdrawal(w, Q, I, fee, chgHashi) ==
    LET chg == PoolTotal(I) - ReqTotal(Q) IN
    /\ ~paused /\ ~reconfiguring
    /\ wtx[w].st = "none"
    /\ LeaderGuard => \A v \in Wids : wtx[v].st # "signing"
    /\ Q # {} /\ I # {}
    /\ \A q \in Q : wreq[q] = "appr" /\ ReqAmt[q] > fee
    /\ \A id \in I : pool[id].st = "avail"
    /\ PoolTotal(I) >= ReqTotal(Q)
    /\ HonestCerts => chgHashi
    /\ chg > 0 => ~InPool(ChangeId(w))
    /\ wtx' = [wtx EXCEPT ![w] = [st |-> "signing", ins |-> I, reqs |-> Q,
                                  fee |-> fee, chg |-> chg,
                                  chgHashi |-> chgHashi, mpcRec |-> FALSE]]
    /\ wreq' = [q \in Reqs |-> IF q \in Q THEN "comm" ELSE wreq[q]]
    /\ supply' = supply - ReqTotal(Q)
    /\ pool' = [id \in PoolIds |->
                  IF id \in I THEN [pool[id] EXCEPT !.st = "locked"]
                  ELSE IF id = ChangeId(w) /\ chg > 0
                       THEN [st |-> "avail", amt |-> chg, prod |-> w]
                       ELSE pool[id]]
    /\ inserts' = IF chg > 0 THEN [inserts EXCEPT ![ChangeId(w)] = @ + 1]
                  ELSE inserts
    /\ lockHist' = lockHist \cup {<<id, w>> : id \in I}
    /\ UNCHANGED <<epoch, reconfiguring, paused, tomb, userBal, depReq,
                   btcVars, offVars, donated>>

\* Offchain MPC signing. Followers check no pause or reconfiguration.
MpcSign(w) ==
    /\ wtx[w].st # "none" /\ w \notin mpcDone
    /\ mpcDone' = mpcDone \cup {w}
    /\ UNCHANGED <<suiVars, btcVars, gsig, ghostVars>>

\* The Guardian signs a committed W. Limiter refusal is the action not firing.
GuardianSign(w) ==
    /\ wtx[w].st # "none" /\ w \notin gsig
    /\ gsig' = gsig \cup {w}
    /\ UNCHANGED <<suiVars, btcVars, mpcDone, ghostVars>>

CommitInputSignatures(w) ==
    /\ ~paused /\ ~reconfiguring
    /\ wtx[w].st = "signing" /\ w \in mpcDone /\ ~wtx[w].mpcRec
    /\ wtx' = [wtx EXCEPT ![w].mpcRec = TRUE]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   depReq, wreq, btcVars, offVars, ghostVars>>

FinalizeWithdrawal(w) ==
    /\ ~paused /\ ~reconfiguring
    /\ wtx[w].st = "signing" /\ wtx[w].mpcRec /\ w \in gsig
    /\ wtx' = [wtx EXCEPT ![w].st = "full"]
    /\ UNCHANGED <<epoch, reconfiguring, paused, pool, tomb, supply, userBal,
                   depReq, wreq, btcVars, offVars, ghostVars>>

\* Anyone holding MPC and Guardian signatures can broadcast.
BroadcastWithdrawal(w) ==
    /\ w \in mpcDone /\ w \in gsig
    /\ Broadcast(WTx(w))

\* confirm_withdrawal. Honest signers require the transaction to be final.
ConfirmWithdrawal(w) ==
    /\ ~paused
    /\ wtx[w].st = "full"
    /\ HonestCerts => WTx(w) \in finalTx
    /\ wtx' = [wtx EXCEPT ![w].st = "conf"]
    /\ pool' = [id \in PoolIds |->
                  IF id \in wtx[w].ins THEN [pool[id] EXCEPT !.st = "marked"]
                  ELSE IF id = ChangeId(w) /\ pool[id].st # "absent"
                       THEN [pool[id] EXCEPT !.prod = None]
                       ELSE pool[id]]
    /\ UNCHANGED <<epoch, reconfiguring, paused, tomb, supply, userBal,
                   depReq, wreq, btcVars, offVars, ghostVars>>

CleanupSpent(id) ==
    /\ pool[id].st = "marked"
    /\ pool' = [pool EXCEPT ![id] = NoRec]
    /\ tomb' = tomb \cup {id}
    /\ UNCHANGED <<epoch, reconfiguring, paused, supply, userBal, depReq,
                   wreq, wtx, btcVars, offVars, ghostVars>>

-----------------------------------------------------------------------------

EpochNext == StartReconfig \/ EndReconfig \/ AbortReconfig

\* Actions a composed model may synchronise with the Guardian limiter.
LimiterCoupled ==
    \/ \E w \in Wids, Q \in SUBSET Reqs, I \in SUBSET PoolIds,
          fee \in 0..MaxFee, ch \in BOOLEAN :
          CommitWithdrawal(w, Q, I, fee, ch)
    \/ \E w \in Wids : CommitInputSignatures(w) \/ FinalizeWithdrawal(w)

\* Actions other than epoch changes, Guardian signing, and LimiterCoupled.
CoreOpNext ==
    \/ \E o \in DepOuts : SendDeposit(o)
    \/ \E t \in mempool : Mine(t) \/ Evict(t)
    \/ \E id \in PoolIds : RecoverySpend(id) \/ CleanupSpent(id)
    \/ Pause \/ Unpause
    \/ \E r \in DepReqIds :
          \/ RequestDeposit(r) \/ ApproveDeposit(r) \/ DelayElapses(r)
          \/ Expire(r) \/ DeleteExpired(r) \/ ConfirmDeposit(r)
    \/ \E q \in Reqs :
          RequestWithdrawal(q) \/ CancelWithdrawal(q) \/ ApproveRequest(q)
    \/ \E w \in Wids :
          MpcSign(w) \/ BroadcastWithdrawal(w) \/ ConfirmWithdrawal(w)

\* Actions other than epoch changes and Guardian signing.
OpNext == CoreOpNext \/ LimiterCoupled

Next == EpochNext \/ OpNext \/ \E w \in Wids : GuardianSign(w)

Spec == Init /\ [][Next]_vars

Commit == \E w \in Wids, Q \in SUBSET Reqs, I \in SUBSET PoolIds,
              fee \in 0..MaxFee, ch \in BOOLEAN :
              CommitWithdrawal(w, Q, I, fee, ch)

\* Honest parties and the Bitcoin network act eventually. Adversarial and
\* user actions (recovery, eviction, pause, cancel, expiry) are not fair.
OpFairness ==
    /\ WF_vars(Unpause)
    /\ \A o \in DepOuts : SF_vars(Mine(DepTx(o)))
    /\ \A r \in DepReqIds :
          /\ WF_vars(ApproveDeposit(r)) /\ WF_vars(DelayElapses(r))
          /\ WF_vars(ConfirmDeposit(r))
    /\ \A q \in Reqs : WF_vars(ApproveRequest(q))
    /\ WF_vars(Commit)
    /\ \A w \in Wids :
          /\ WF_vars(MpcSign(w))
          /\ WF_vars(CommitInputSignatures(w)) /\ WF_vars(FinalizeWithdrawal(w))
          /\ SF_vars(BroadcastWithdrawal(w)) /\ SF_vars(Mine(WTx(w)))
          /\ WF_vars(ConfirmWithdrawal(w))

Fairness ==
    /\ OpFairness /\ WF_vars(EndReconfig)
    /\ \A w \in Wids : WF_vars(GuardianSign(w))

LiveSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties. Numbers refer to PROTOCOL.md section 11. *)

AvailTotal == PoolTotal({id \in PoolIds : pool[id].st = "avail"})
Escrow == ReqTotal({q \in Reqs : wreq[q] \in {"req", "appr"}})

\* 1. Supply.
SupplyInv == supply + donated = AvailTotal

\* Escrow is part of supply.
BalanceInv == userBal + Escrow = supply

\* 2. No double mint: a pool id is inserted at most once.
NoDoubleInsert == \A id \in PoolIds : inserts[id] <= 1

\* 3. Single lock.
SingleLock == \A a, b \in lockHist : a[1] = b[1] => a[2] = b[2]

\* 9. Deposit soundness.
DepositSound ==
    \A r \in DepReqIds :
        depReq[r].st = "done" =>
            /\ DepTx(r[1]) \in finalTx
            /\ r[2] = DepAmt[r[1]]
            /\ r[3] = DepUser[r[1]]

\* 10. Record soundness.
RecordSound ==
    \A id \in PoolIds :
        /\ (pool[id].st = "avail" /\ pool[id].prod = None) =>
               \E u \in utxo : u.id = id /\ u.amt = pool[id].amt /\ u.hashi
        /\ (pool[id].st = "avail" /\ pool[id].prod # None) =>
               LET w == pool[id].prod
               IN wtx[w].st # "none" /\ id = ChangeId(w)
                  /\ wtx[w].chg = pool[id].amt

HashiFinal ==
    LET H == {u \in utxo : u.hashi} IN SumOver(H, [u \in H |-> u.amt])
Owed ==
    LET O == {w \in Wids : wtx[w].st # "none" /\ WTx(w) \notin finalTx}
    IN SumOver(O, [w \in O |-> ReqTotal(wtx[w].reqs)])

\* 11. Backing.
Backing == HashiFinal >= supply + Owed

\* 12. No double spend among transactions signed by MPC and Guardian.
NoDoubleSpend ==
    \A w1, w2 \in mpcDone \cap gsig :
        w1 # w2 => wtx[w1].ins \cap wtx[w2].ins = {}

\* Liveness 3: every committed W is eventually confirmed on Sui.
WithdrawalCompletes ==
    \A w \in Wids : (wtx[w].st # "none") ~> (wtx[w].st = "conf")

\* Liveness 2: every approved request is eventually committed or cancelled.
RequestServed ==
    \A q \in Reqs : (wreq[q] = "appr") ~> (wreq[q] \in {"comm", "canc"})

\* Liveness 1: a true deposit claim whose output is final is eventually
\* confirmed, unless the output entered the pool another way.
DepositCompletes ==
    \A r \in DepReqIds :
        (r[2] = DepAmt[r[1]] /\ r[3] = DepUser[r[1]]) =>
            ((depReq[r].st = "req" /\ DepTx(r[1]) \in finalTx)
                ~> (depReq[r].st \in {"done", "deleted"} \/ InPool(r[1])))

\* R2 probe: no withdrawal transaction enters the mempool while paused.
PausedNoWithdrawalBroadcast ==
    [][paused /\ paused' =>
         \A w \in Wids : WTx(w) \in mempool' => WTx(w) \in mempool]_vars

\* 13. Withdrawal confirmation soundness.
ConfirmSound ==
    \A w \in Wids : wtx[w].st = "conf" => WTx(w) \in finalTx

=============================================================================
