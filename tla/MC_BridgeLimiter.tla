---------------------------- MODULE MC_BridgeLimiter --------------------------
EXTENDS BridgeLimiter, TLC
CONSTANTS d1, q1, q2, q3, w1, w2
MCDepOuts == {d1}
MCDepAmt == d1 :> 3
MCDepUser == d1 :> TRUE
MCDepReqIds == {<<d1, 3, TRUE>>}
MCReqs == {q1, q2, q3}
MCReqAmt == (q1 :> 1) @@ (q2 :> 1) @@ (q3 :> 1)
MCWids == {w1, w2}
\* w1 batches two requests; w2 carries one.
MCLAmt == (w1 :> 2) @@ (w2 :> 1)
=============================================================================
