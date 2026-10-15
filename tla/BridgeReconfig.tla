--------------------------- MODULE BridgeReconfig ---------------------------
(***************************************************************************)
(* Bridge composed with Reconfig. Reconfig drives the Hashi epoch and the  *)
(* pending reconfiguration that Bridge reads; Bridge's own epoch actions   *)
(* are dropped.                                                            *)
(*                                                                         *)
(* Coupling:                                                               *)
(* - Bridge's epoch is Reconfig's hashi, and reconfiguring is pend # None. *)
(* - The Guardian verifies a withdrawal-request cert only against its own  *)
(*   committee, and nodes sign that cert at the current Hashi epoch        *)
(*   (standard_withdrawal.rs:37-44, withdrawals.rs:1210-1214). The         *)
(*   Guardian therefore signs only when it is active and gEpoch = hashi.   *)
(* - Byzantine members may drive Guardian signing while paused or          *)
(*   reconfiguring. An honest leader requests only when neither holds      *)
(*   (withdrawal_transactions.rs:288-291), so only that case is fair.      *)
(*                                                                         *)
(* MPC signing across an epoch change is one flag: Signed slots survive    *)
(* reallocate_presigs, and the new committee signs the rest                *)
(* (mpc_signing.move:159-183). Presig.tla covers nonce safety.             *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    DepOuts, DepAmt, DepUser, DepReqIds, Reqs, ReqAmt, Wids, MaxFee,
    MaxEpoch, HonestCerts, AllowRecovery, EnvFaults, LeaderGuard,
    Nodes, MaxSui, MaxAttempts, TransientFailures, HoldEnabled, MpcMayFail,
    ProxyGate, RestartsEnabled, NoCommitteeFails

VARIABLES
    paused, pool, tomb, supply, userBal, depReq, wreq, wtx,
    utxo, mempool, finalTx, mpcDone, gsig, donated, inserts, lockHist,
    sui, hashi, pend, pendH, canComplete, done, aborted, stored, hold,
    signedH, view, attempts, panicked, gEpoch, gActive, gate,
    signEp,     \* ghost: Wids -> Hashi epoch of the Guardian signature
    commitEp    \* ghost: Wids -> Hashi epoch of the commit

B == INSTANCE Bridge WITH epoch <- hashi, reconfiguring <- (pend # -1)
R == INSTANCE Reconfig

bVars == <<paused, pool, tomb, supply, userBal, depReq, wreq, wtx,
           utxo, mempool, finalTx, mpcDone, gsig, donated, inserts, lockHist>>
rVars == <<sui, hashi, pend, pendH, canComplete, done, aborted, stored, hold,
           signedH, view, attempts, panicked, gEpoch, gActive, gate>>
ghost == <<signEp, commitEp>>
vars == <<bVars, rVars, ghost>>

Init ==
    /\ R!Init /\ B!Init
    /\ signEp = [w \in Wids |-> -1]
    /\ commitEp = [w \in Wids |-> -1]

BridgeStep ==
    \* rVars first: Bridge's UNCHANGED reconfiguring reads pend'.
    /\ UNCHANGED <<rVars, signEp>> /\ B!OpNext
    /\ commitEp' = [w \in Wids |->
                      IF wtx[w].st = "none" /\ wtx'[w].st # "none"
                      THEN hashi ELSE commitEp[w]]

GSign(w) ==
    /\ UNCHANGED <<rVars, commitEp>>
    /\ gActive /\ gEpoch = hashi
    /\ B!GuardianSign(w)
    /\ signEp' = [signEp EXCEPT ![w] = hashi]

HonestGSign(w) == ~paused /\ pend = -1 /\ GSign(w)

ReconfigStep == R!Next /\ UNCHANGED <<bVars, ghost>>

Next == BridgeStep \/ (\E w \in Wids : GSign(w)) \/ ReconfigStep

Spec == Init /\ [][Next]_vars

\* An honest leader retries a Guardian request every checkpoint
\* (guardian.rs:90-104), so it is strongly fair.
Fairness ==
    /\ B!OpFairness /\ R!Fairness
    /\ \A w \in Wids : SF_vars(HonestGSign(w))

LiveSpec == Spec /\ Fairness

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
PendingWindow == R!PendingWindow
CompleteXorAbort == R!CompleteXorAbort
NoEpochReuse == R!NoEpochReuse
HandoffChain == R!HandoffChain
NoPanic == R!NoPanic
GuardianCompleted == R!GuardianCompleted
GuardianNotAhead == R!GuardianNotAhead

\* The Guardian signs only for a completed committee's epoch.
GuardianSignsCompleted == \A w \in Wids : signEp[w] # -1 => signEp[w] \in done

WithdrawalCompletes == B!WithdrawalCompletes
RequestServed == B!RequestServed
DepositCompletes == B!DepositCompletes
HashiCatchesUp == R!HashiCatchesUp
GuardianCatchesUp == R!GuardianCatchesUp

\* Coverage probes: each should be violated.
NeverSignedAfterEpochChange ==
    \A w \in Wids : signEp[w] # -1 => signEp[w] = commitEp[w]
NeverConfirmedAfterEpochChange ==
    \A w \in Wids : wtx[w].st = "conf" => commitEp[w] = hashi
NeverDepositAfterEpochChange ==
    \A r \in DepReqIds : depReq[r].st = "done" => depReq[r].ep = 0

=============================================================================
