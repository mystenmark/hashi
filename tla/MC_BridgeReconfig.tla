--------------------------- MODULE MC_BridgeReconfig -------------------------
EXTENDS BridgeReconfig, TLC
CONSTANTS d1, q1, q2, w1, w2
MCDepOuts == {d1}
MCDepAmt == d1 :> 2
MCDepUser == d1 :> TRUE
MCDepReqIds == {<<d1, 2, TRUE>>}
MCReqs1 == {q1}
MCReqs2 == {q1, q2}
MCReqAmt == (q1 :> 1) @@ (q2 :> 1)
MCWids1 == {w1}
MCWids2 == {w1, w2}

\* End to end: a submitted request is paid on Bitcoin and confirmed on Sui,
\* unless the user cancels it.
PaidConfirmed(q) == \E w \in Wids : q \in wtx[w].reqs /\ wtx[w].st = "conf"
RequestPaid ==
    \A q \in Reqs : (wreq[q] = "req") ~> (wreq[q] = "canc" \/ PaidConfirmed(q))
=============================================================================
