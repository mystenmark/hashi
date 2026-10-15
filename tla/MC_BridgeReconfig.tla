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

\* End to end for deposits, as in MC_Bridge: the user refiles a true claim,
\* and approval, the delay, and confirmation win the race with expiry
\* infinitely often. Re-approval after a completed reconfiguration is
\* ApproveDeposit on a request approved in an older epoch.
TrueClaim(r) == r[2] = DepAmt[r[1]] /\ r[3] = DepUser[r[1]]
DepositLiveSpec ==
    /\ LiveSpec
    /\ \A r \in DepReqIds : TrueClaim(r) =>
          /\ WF_vars(BridgeStep /\ B!RequestDeposit(r))
          /\ SF_vars(BridgeStep /\ B!ApproveDeposit(r))
          /\ SF_vars(BridgeStep /\ B!DelayElapses(r))
          /\ SF_vars(BridgeStep /\ B!ConfirmDeposit(r))
DepositMinted ==
    \A o \in DepOuts :
        (B!DepTx(o) \in finalTx /\ \E r \in DepReqIds : TrueClaim(r) /\ r[1] = o)
            ~> B!InPool(o)
=============================================================================
