------------------------- MODULE MC_GuardianLimiter -------------------------
EXTENDS GuardianLimiter, TLC
AmtOne == [w \in Wids |-> 1]
AmtTwo == [w \in Wids |-> 2]
Symm == Permutations(Nodes) \cup Permutations(Wids)

\* A Byzantine member asks the proxy for any ready wid at any seq, with no
\* mirror check (F2 direct path). Honest signers check only ts.
MaxByzSeq == 3
ByzRequest(w) ==
    /\ w \in ready
    /\ \E s \in 0..MaxByzSeq, ts \in TsRange :
         proxyIn' = proxyIn \cup {[from |-> "byz", wid |-> w, seq |-> s, ts |-> ts]}
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, enclaveQ, replies, ready,
                   final, mirror, seen, snaps, gMax>>

ByzSpec == Init /\ [][Next \/ \E w \in Wids : ByzRequest(w)]_vars

\* Three records for one wid.
AtMostTwoConsumes == \A w \in Wids : Cardinality({r \in log : r.wid = w}) <= 2

\* The stall reconcile: once a mirror's seq stays off the Guardian's, the
\* node snaps to it (guardian_limiter.rs LimiterStallTracker). It is outside
\* the MaxSnaps budget, which bounds only adversarial snaps and restarts.
\* Liveness is checked on GuardianLimiterSeq (see MC_GuardianLimiterRefine).
StallSnap(n) ==
    /\ mirror[n].seq # gSeq
    /\ mirror' = [mirror EXCEPT ![n] = GState]
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies,
                   ready, final, seen, snaps, gMax>>

=============================================================================
