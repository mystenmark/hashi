-------------------------- MODULE GuardianLimiterSeq --------------------------
(***************************************************************************)
(* GuardianLimiter with time and tokens removed, for liveness checking.    *)
(*                                                                         *)
(* A mirror is its next seq; a request is [from, wid, seq]. The enclave     *)
(* accepts exactly the request at its seq; a refusal for timestamp or      *)
(* capacity is a separate step that is not fair. Observing a finalize may  *)
(* or may not advance a mirror, since the concrete apply can fail on       *)
(* timestamp or capacity. Finalize needs Quorum mirrors at the request's   *)
(* seq.                                                                    *)
(*                                                                         *)
(* MC_GuardianLimiterRefine checks that GuardianLimiter (with the stall    *)
(* reconcile) refines this module. The liveness result carries over when   *)
(* capacity and timestamp checks do not block the concrete steps that are  *)
(* fair here.                                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Nodes, Wids, Quorum, MaxSnaps

VARIABLES
    gSeq,       \* enclave next seq
    log,        \* durable records [wid, seq]
    proxyIn, enclaveQ, replies,  \* sets of [from, wid, seq]
    ready,      \* MPC-complete, not finalized
    done,       \* finalized wids
    mseq,       \* per node: mirror next seq
    seen,       \* per node: finalizes applied or skipped
    snaps

vars == <<gSeq, log, proxyIn, enclaveQ, replies, ready, done, mseq, seen, snaps>>

HasLog(w) == \E r \in log : r.wid = w
Finalizable(r) == Cardinality({m \in Nodes : mseq[m] = r.seq}) >= Quorum
Outstanding(n, w) ==
    \E r \in proxyIn \cup enclaveQ \cup replies : r.from = n /\ r.wid = w

Init ==
    /\ gSeq = 0 /\ log = {}
    /\ proxyIn = {} /\ enclaveQ = {} /\ replies = {}
    /\ ready = {} /\ done = {}
    /\ mseq = [n \in Nodes |-> 0] /\ seen = [n \in Nodes |-> 0]
    /\ snaps = 0

MpcComplete(w) ==
    /\ w \notin ready /\ w \notin done
    /\ ready' = ready \cup {w}
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, replies, done, mseq, seen, snaps>>

Request(n, w) ==
    /\ w \in ready /\ ~Outstanding(n, w)
    /\ proxyIn' = proxyIn \cup {[from |-> n, wid |-> w, seq |-> mseq[n]]}
    /\ UNCHANGED <<gSeq, log, enclaveQ, replies, ready, done, mseq, seen, snaps>>

Proxy(r) ==
    /\ r \in proxyIn
    /\ proxyIn' = proxyIn \ {r}
    /\ IF HasLog(r.wid)
       THEN replies' = replies \cup {r} /\ UNCHANGED enclaveQ
       ELSE enclaveQ' = enclaveQ \cup {r} /\ UNCHANGED replies
    /\ UNCHANGED <<gSeq, log, ready, done, mseq, seen, snaps>>

\* The enclave signs the request at its seq and drops any other.
Enclave(r) ==
    /\ r \in enclaveQ
    /\ enclaveQ' = enclaveQ \ {r}
    /\ IF r.seq = gSeq
       THEN /\ gSeq' = gSeq + 1
            /\ log' = log \cup {[wid |-> r.wid, seq |-> r.seq]}
            /\ replies' = replies \cup {r}
       ELSE UNCHANGED <<gSeq, log, replies>>
    /\ UNCHANGED <<proxyIn, ready, done, mseq, seen, snaps>>

\* Refusal on timestamp or capacity.
EnclaveRefuse(r) ==
    /\ r \in enclaveQ
    /\ enclaveQ' = enclaveQ \ {r}
    /\ UNCHANGED <<gSeq, log, proxyIn, replies, ready, done, mseq, seen, snaps>>

Finalize(r) ==
    /\ r \in replies /\ r.wid \in ready
    /\ Finalizable(r)
    /\ ready' = ready \ {r.wid}
    /\ done' = done \cup {r.wid}
    /\ replies' = {x \in replies : x.wid # r.wid}
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, mseq, seen, snaps>>

DropReply(r) ==
    /\ r \in replies
    /\ replies' = replies \ {r}
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, ready, done, mseq, seen, snaps>>

Observe(n) ==
    /\ seen[n] < Cardinality(done)
    /\ seen' = [seen EXCEPT ![n] = @ + 1]
    /\ mseq' \in {mseq, [mseq EXCEPT ![n] = @ + 1]}
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, replies, ready, done, snaps>>

Reconcile(n) ==
    /\ snaps < MaxSnaps
    /\ snaps' = snaps + 1
    /\ mseq' = [mseq EXCEPT ![n] = gSeq]
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, replies, ready, done, seen>>

Restart(n) ==
    /\ snaps < MaxSnaps
    /\ snaps' = snaps + 1
    /\ mseq' = [mseq EXCEPT ![n] = gSeq]
    /\ seen' = [seen EXCEPT ![n] = Cardinality(done)]
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, replies, ready, done>>

\* The stall reconcile (guardian_limiter.rs LimiterStallTracker).
StallSnap(n) ==
    /\ mseq[n] # gSeq
    /\ mseq' = [mseq EXCEPT ![n] = gSeq]
    /\ UNCHANGED <<gSeq, log, proxyIn, enclaveQ, replies, ready, done, seen, snaps>>

Next ==
    \/ \E w \in Wids : MpcComplete(w)
    \/ \E n \in Nodes, w \in Wids : Request(n, w)
    \/ \E r \in proxyIn : Proxy(r)
    \/ \E r \in enclaveQ : Enclave(r) \/ EnclaveRefuse(r)
    \/ \E r \in replies : Finalize(r) \/ DropReply(r)
    \/ \E n \in Nodes : Observe(n) \/ Reconcile(n) \/ Restart(n) \/ StallSnap(n)

Spec == Init /\ [][Next]_vars

\* Refusals, snaps, and restarts are not fair; drops are fair only for a
\* reply that cannot be finalized. Fairness is per withdrawal, so no
\* withdrawal's requests are starved by another's.
Fairness ==
    /\ \A w \in Wids : WF_vars(MpcComplete(w))
    /\ \A n \in Nodes, w \in Wids : WF_vars(Request(n, w))
    /\ \A w \in Wids : WF_vars(\E r \in proxyIn : r.wid = w /\ Proxy(r))
    \* The enclave answers every request, and refusals on timestamp or capacity
    \* do not recur forever (strong fairness on acceptance).
    \* This assumes each amount fits max (else F12) and the bucket refills.
    /\ \A w \in Wids : WF_vars(\E r \in enclaveQ : r.wid = w /\ Enclave(r))
    /\ \A w \in Wids :
          SF_vars(\E r \in enclaveQ : r.wid = w /\ r.seq = gSeq /\ Enclave(r))
    /\ \A w \in Wids : SF_vars(\E r \in replies : r.wid = w /\ Finalize(r))
    \* A leader whose finalize fails retries from scratch on a later checkpoint
    \* (finalize_fully_signed_withdrawal re-reads its mirror's seq each time).
    /\ \A w \in Wids :
          WF_vars(\E r \in replies : r.wid = w /\ ~Finalizable(r) /\ DropReply(r))
    /\ \A n \in Nodes : WF_vars(Observe(n)) /\ WF_vars(StallSnap(n))

LiveSpec == Spec /\ Fairness

\* Every withdrawal the Guardian consumed is eventually finalized.
ConsumedFinalized == \A w \in Wids : HasLog(w) ~> (w \in done)

\* Guarantee to Bridge: a withdrawal ready for the Guardian (MPC complete)
\* is eventually logged, which is its Guardian signature.
ReadyConsumed == \A w \in Wids : (w \in ready) ~> HasLog(w)

\* Coverage probe: a withdrawal consumed at two seqs. Should fail.
NoDoubleConsume == \A r1, r2 \in log : r1.wid = r2.wid => r1 = r2
=============================================================================
