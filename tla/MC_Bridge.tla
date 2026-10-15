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
\* Fee variant: unequal amounts so a fee of 1 per request is possible.
MCDepAmtFee == (d1 :> 3) @@ (d2 :> 1)
MCDepReqIdsFee == {<<d1, 3, TRUE>>, <<d2, 1, FALSE>>, <<d1, 1, TRUE>>}
MCReqAmtFee == (q1 :> 2) @@ (q2 :> 1)

\* Coverage probes: each should be violated, which shows the state is reachable.
NeverConfirmed == \A w \in Wids : wtx[w].st # "conf"
NeverChained == \A w \in Wids : \A v \in Wids : ChangeId(v) \notin wtx[w].ins
NeverChildFirst ==
    ~\E w, v \in Wids :
        /\ ChangeId(v) \in wtx[w].ins
        /\ wtx[w].st = "conf" /\ wtx[v].st # "conf"
\* End to end: a submitted withdrawal request is eventually paid by a final
\* Bitcoin transaction and recorded as confirmed on Sui, unless the user
\* cancels it first.
Paid(q) == \E w \in Wids : q \in wtx[w].reqs /\ WTx(w) \in finalTx
PaidConfirmed(q) == \E w \in Wids : q \in wtx[w].reqs /\ wtx[w].st = "conf"
RequestPaid ==
    \A q \in Reqs : (wreq[q] = "req") ~> (wreq[q] = "canc" \/ PaidConfirmed(q))

\* Bridge without fairness on GuardianSign. The Guardian's behaviour comes
\* instead from GuardianSigns, which GuardianLimiterSeq (ReadyConsumed) and
\* BridgeLimiter (ReadyIsMpcRec, GsigLogged) establish.
LiveSpecNoGuardian == Spec /\ OpFairness /\ WF_vars(EndReconfig)
GuardianSigns ==
    \A w \in Wids : (wtx[w].st = "signing" /\ wtx[w].mpcRec) ~> (w \in gsig)
RequestPaidIfGuardianSigns == GuardianSigns => RequestPaid

\* End to end for deposits. A user whose output is final keeps a true claim
\* filed: after expiry or deletion they file it again. Approval, the delay,
\* and confirmation are strongly fair per claim, so expiry cannot win every
\* race (the 24 h expiry is far longer than approval plus the 10 min delay).
TrueClaim(r) == r[2] = DepAmt[r[1]] /\ r[3] = DepUser[r[1]]
DepositFairness ==
    /\ OpFairness /\ WF_vars(EndReconfig)
    /\ \A r \in DepReqIds : TrueClaim(r) =>
          /\ WF_vars(RequestDeposit(r))
          /\ SF_vars(ApproveDeposit(r)) /\ SF_vars(DelayElapses(r))
          /\ SF_vars(ConfirmDeposit(r))
DepositLiveSpec == Spec /\ DepositFairness /\ \A w \in Wids : WF_vars(GuardianSign(w))

\* A final deposit output with a true claim is eventually in the pool, and its
\* hBTC minted (SupplyInv ties the two).
DepositMinted ==
    \A o \in DepOuts :
        (DepTx(o) \in finalTx /\ \E r \in DepReqIds : TrueClaim(r) /\ r[1] = o)
            ~> InPool(o)

NeverBothWithdrawn == \E q \in Reqs : wreq[q] # "comm"
=============================================================================
