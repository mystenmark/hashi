------------------------------ MODULE Reconfig ------------------------------
(***************************************************************************)
(* Hashi reconfiguration after genesis, the node driver, and the Guardian  *)
(* committee chain (PROTOCOL.md 2, 9.3).                                   *)
(*                                                                         *)
(* Chain: start, end (with handoff), standalone handoff, and abort against *)
(* an advancing Sui epoch. Committees are identified by their epoch.       *)
(*                                                                         *)
(* Nodes act on snapshots of the chain that lag it and never lead it. The  *)
(* driver follows mpc/service.rs: abort a pending target whose window      *)
(* closed, start a replacement when Hashi lags Sui, and submit handoff and *)
(* end_reconfig in one transaction, classifying aborts. An abort the       *)
(* driver does not classify sets `panicked`.                               *)
(*                                                                         *)
(* MPC is abstract: when a committee forms, the environment decides        *)
(* whether it can produce a completion certificate in its window.          *)
(*                                                                         *)
(* Guardian: the leader pushes stored handoffs once per Hashi epoch        *)
(* (leader/guardian.rs). Anyone holding a signed handoff can also send it  *)
(* through the proxy, which admits only handoffs the chain stores.         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Nodes,
    MaxSui,             \* Sui epochs are 0..MaxSui
    MaxAttempts,        \* start_reconfig attempts per trigger
    TransientFailures,  \* a start_reconfig submission may fail transiently
    HoldEnabled,        \* governance may set and clear reconfig_hold
    MpcMayFail,         \* a formed committee may be unable to complete
    ProxyGate,          \* the proxy admits only stored handoffs
    RestartsEnabled,    \* nodes may restart, clearing leader state
    NoCommitteeFails    \* a reply with no committee clears the gate (F9 fix)

None == -1

VARIABLES
    \* Chain
    sui,            \* Sui epoch
    hashi,          \* Hashi epoch
    pend,           \* pending target epoch or None
    pendH,          \* a handoff cert is stored on the pending change
    canComplete,    \* the pending committee can gather a completion cert
    done,           \* completed epochs
    aborted,        \* aborted target epochs
    stored,         \* stored handoffs <<from, to>>
    hold,           \* reconfig_hold
    \* Off chain
    signedH,        \* handoff certs signed by the outgoing committee
    view,           \* per node chain snapshot
    attempts,       \* per node start_reconfig attempts since last trigger
    panicked,       \* ghost: some honest node hit an unclassified abort
    \* Guardian
    gEpoch,         \* Guardian committee epoch
    gActive,        \* Guardian answers GetGuardianInfo with a committee
    gate            \* per node: Hashi epoch it last reconciled as leader, or None

chainVars == <<sui, hashi, pend, pendH, canComplete, done, aborted, stored, hold>>
guardVars == <<gEpoch, gActive, gate>>
vars == <<chainVars, signedH, view, attempts, panicked, guardVars>>

Snapshot == [sui |-> sui, hashi |-> hashi, pend |-> pend, pendH |-> pendH,
             hold |-> hold]

Init ==
    /\ sui = 0 /\ hashi = 0 /\ pend = None /\ pendH = FALSE
    /\ canComplete = FALSE
    /\ done = {0} /\ aborted = {} /\ stored = {}
    /\ hold = FALSE
    /\ signedH = {}
    /\ view = [n \in Nodes |-> Snapshot]
    /\ attempts = [n \in Nodes |-> 0]
    /\ panicked = FALSE
    /\ gEpoch = 0 /\ gActive = TRUE /\ gate = [n \in Nodes |-> None]

-----------------------------------------------------------------------------
(* Environment *)

SuiAdvance ==
    /\ sui < MaxSui
    /\ sui' = sui + 1
    /\ UNCHANGED <<hashi, pend, pendH, canComplete, done, aborted, stored, hold,
                   signedH, view, attempts, panicked, guardVars>>

SetHold(b) ==
    /\ HoldEnabled /\ hold # b
    /\ hold' = b
    /\ UNCHANGED <<sui, hashi, pend, pendH, canComplete, done, aborted, stored,
                   signedH, view, attempts, panicked, guardVars>>

\* Honest outgoing members sign a handoff to the committee pending on chain.
SignHandoff ==
    /\ pend # None
    /\ <<hashi, pend>> \notin signedH
    /\ signedH' = signedH \cup {<<hashi, pend>>}
    /\ UNCHANGED <<chainVars, view, attempts, panicked, guardVars>>

\* Anyone holding a valid handoff cert can submit it on its own.
SubmitHandoffAlone(f, t) ==
    /\ <<f, t>> \in signedH
    /\ pend = t /\ sui = t /\ hashi = f /\ ~pendH
    /\ pendH' = TRUE
    /\ UNCHANGED <<sui, hashi, pend, canComplete, done, aborted, stored, hold,
                   signedH, view, attempts, panicked, guardVars>>

-----------------------------------------------------------------------------
(* Node driver *)

\* The view catches up. A Sui epoch change or an observed abort is a new
\* start_reconfig trigger, which resets the attempt budget.
Sync(n) ==
    /\ view[n] # Snapshot
    /\ view' = [view EXCEPT ![n] = Snapshot]
    /\ attempts' = [attempts EXCEPT ![n] =
          IF sui # view[n].sui \/ (view[n].pend # None /\ view[n].pend \in aborted)
          THEN 0 ELSE @]
    /\ UNCHANGED <<chainVars, signedH, panicked, guardVars>>

\* Abort a pending target whose window closed in the node's view. An abort
\* the chain refuses as still current would mean the view led the chain.
NodeAbort(n) ==
    LET p == view[n].pend IN
    /\ p # None /\ view[n].sui > p
    /\ IF pend = p /\ sui # p
       THEN /\ pend' = None /\ pendH' = FALSE
            /\ aborted' = aborted \cup {p}
            /\ UNCHANGED panicked
       ELSE /\ panicked' = (panicked \/ (pend = p /\ sui = p))
            /\ UNCHANGED <<pend, pendH, aborted>>
    /\ UNCHANGED <<sui, hashi, canComplete, done, stored, hold, signedH, view,
                   attempts, guardVars>>

\* start_reconfig when the view shows Hashi lagging Sui with nothing pending.
\* The chain forms the committee for its own Sui epoch.
NodeStart(n) ==
    LET v == view[n] IN
    /\ v.pend = None /\ v.hashi < v.sui /\ ~v.hold
    /\ attempts[n] < MaxAttempts
    /\ \/ /\ pend = None /\ ~hold /\ sui \notin done
          /\ pend' = sui /\ pendH' = FALSE
          /\ canComplete' \in (IF MpcMayFail THEN BOOLEAN ELSE {TRUE})
          /\ UNCHANGED attempts
       \/ /\ (pend # None \/ hold \/ sui \in done \/ TransientFailures)
          /\ attempts' = [attempts EXCEPT ![n] = @ + 1]
          /\ UNCHANGED <<pend, pendH, canComplete>>
    /\ UNCHANGED <<sui, hashi, done, aborted, stored, hold, signedH, view,
                   panicked, guardVars>>

\* Handoff and end_reconfig in one transaction. The handoff cert was signed
\* at the node's view of the Hashi epoch. Classification follows
\* classify_reconfig_execution_error and submit_end_reconfig.
NodeEnd(n) ==
    LET v == view[n]
        p == v.pend
        f == v.hashi
    IN
    /\ p # None /\ v.sui = p
    /\ canComplete
    /\ <<f, p>> \in signedH
    /\ IF pend = p /\ sui = p
       THEN IF hashi = f
            THEN \* Completes. If a handoff is already stored the node
                 \* retries without its own, which also completes.
                 /\ hashi' = p /\ pend' = None /\ pendH' = FALSE
                 /\ done' = done \cup {p}
                 /\ stored' = stored \cup {<<f, p>>}
                 /\ UNCHANGED panicked
            ELSE \* The handoff cert epoch differs from the current committee:
                 \* an unnamed assert in committee::verify.
                 /\ panicked' = TRUE
                 /\ UNCHANGED <<hashi, pend, pendH, done, stored>>
       ELSE \* EReconfigAlreadyCompleted, or the target is dead.
            /\ UNCHANGED <<hashi, pend, pendH, done, stored, panicked>>
    /\ UNCHANGED <<sui, canComplete, aborted, hold, signedH, view, attempts,
                   guardVars>>

-----------------------------------------------------------------------------
(* Guardian *)

GuardianDown ==
    /\ gActive /\ gActive' = FALSE
    /\ UNCHANGED <<chainVars, signedH, view, attempts, panicked, gEpoch, gate>>

\* Activation recovers the committee from the latest committee-update record.
GuardianUp ==
    /\ ~gActive /\ gActive' = TRUE
    /\ UNCHANGED <<chainVars, signedH, view, attempts, panicked, gEpoch, gate>>

RECURSIVE ChainEnd(_)
ChainEnd(e) == IF \E h \in stored : h[1] = e
               THEN ChainEnd((CHOOSE h \in stored : h[1] = e)[2])
               ELSE e

\* A node reconciles once per Hashi epoch while it is leader; leadership
\* rotates, so any node may. With no committee reported (not activated) the
\* call returns Ok and the node keeps its gate set, unless NoCommitteeFails
\* treats that reply as a failure.
LeaderReconcile(n) ==
    /\ gate[n] # hashi
    /\ NoCommitteeFails => gActive
    /\ gate' = [gate EXCEPT ![n] = hashi]
    /\ gEpoch' = IF gActive THEN ChainEnd(gEpoch) ELSE gEpoch
    /\ UNCHANGED <<chainVars, signedH, view, attempts, panicked, gActive>>

\* Anyone holding a signed handoff sends it through the proxy. The enclave
\* accepts a cert from its current committee to a later epoch.
PushHandoff(f, t) ==
    /\ gActive
    /\ <<f, t>> \in signedH
    /\ ProxyGate => <<f, t>> \in stored
    /\ f = gEpoch /\ t > gEpoch
    /\ gEpoch' = t
    /\ UNCHANGED <<chainVars, signedH, view, attempts, panicked, gActive, gate>>

\* A restart clears in-memory leader state. Not fair: restarts are faults.
NodeRestart(n) ==
    /\ RestartsEnabled
    /\ gate[n] # None
    /\ gate' = [gate EXCEPT ![n] = None]
    /\ UNCHANGED <<chainVars, signedH, view, attempts, panicked, gEpoch, gActive>>

-----------------------------------------------------------------------------

Next ==
    \/ SuiAdvance \/ SetHold(TRUE) \/ SetHold(FALSE) \/ SignHandoff
    \/ \E h \in signedH : SubmitHandoffAlone(h[1], h[2]) \/ PushHandoff(h[1], h[2])
    \/ \E n \in Nodes : Sync(n) \/ NodeAbort(n) \/ NodeStart(n) \/ NodeEnd(n)
    \/ GuardianDown \/ GuardianUp
    \/ \E n \in Nodes : LeaderReconcile(n) \/ NodeRestart(n)

Spec == Init /\ [][Next]_vars

\* Honest nodes and the Guardian operator act eventually; governance clears
\* a hold eventually. Sui keeps advancing until MaxSui. A leader retries a
\* failed reconcile every tick, so reconcile is strongly fair.
Fairness ==
    /\ WF_vars(SuiAdvance) /\ WF_vars(SetHold(FALSE)) /\ WF_vars(SignHandoff)
    /\ WF_vars(GuardianUp)
    /\ \A n \in Nodes :
          WF_vars(Sync(n)) /\ WF_vars(NodeAbort(n))
          /\ WF_vars(NodeStart(n)) /\ WF_vars(NodeEnd(n))
          /\ SF_vars(LeaderReconcile(n))

LiveSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ sui \in 0..MaxSui /\ hashi \in 0..MaxSui
    /\ pend \in {None} \cup (0..MaxSui)
    /\ done \subseteq 0..MaxSui /\ aborted \subseteq 0..MaxSui

\* Safety 6.
HashiMonotone == [][hashi' >= hashi]_vars
PendingWindow == pend # None => hashi < pend /\ pend <= sui
CompleteXorAbort == done \cap aborted = {}
NoEpochReuse == pend # None => pend \notin (done \cup aborted)

\* Safety 7: stored handoffs form a chain over completed epochs.
HandoffChain ==
    /\ \A h \in stored : h[1] \in done /\ h[2] \in done /\ h[1] < h[2]
    /\ \A h1, h2 \in stored : h1[1] = h2[1] => h1 = h2

\* The driver never hits an abort it does not classify.
NoPanic == ~panicked

\* Safety 16.
GuardianCompleted == gEpoch \in done
GuardianNotAhead == gEpoch <= hashi

\* Liveness 5 and 6.
HashiCatchesUp == <>[](hashi = sui)
GuardianCatchesUp == <>[](gEpoch = hashi)

=============================================================================
