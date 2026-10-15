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
=============================================================================
