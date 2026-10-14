------------------------------ MODULE MC_Bridge ------------------------------
EXTENDS Bridge
CONSTANTS d1, d2, q1, q2, w1, w2
MCDepOuts == {d1, d2}
MCDepAmt == (d1 :> 2) @@ (d2 :> 1)
MCDepUser == (d1 :> TRUE) @@ (d2 :> FALSE)
\* True claims for both outputs plus one false amount claim for d1.
MCDepReqIds == {<<d1, 2, TRUE>>, <<d2, 1, FALSE>>, <<d1, 1, TRUE>>}
MCReqs == {q1, q2}
MCReqAmt == (q1 :> 1) @@ (q2 :> 1)
MCWids == {w1, w2}

\* Coverage probes: each should be violated, which shows the state is reachable.
NeverConfirmed == \A w \in Wids : wtx[w].st # "conf"
NeverChained == \A w \in Wids : \A v \in Wids : ChangeId(v) \notin wtx[w].ins
NeverChildFirst ==
    ~\E w, v \in Wids :
        /\ ChangeId(v) \in wtx[w].ins
        /\ wtx[w].st = "conf" /\ wtx[v].st # "conf"
NeverBothWithdrawn == \E q \in Reqs : wreq[q] # "comm"
=============================================================================
