---------------------- MODULE MC_GuardianLimiterRefine ----------------------
(* GuardianLimiter with the stall reconcile refines GuardianLimiterSeq.    *)
EXTENDS MC_GuardianLimiter

Strip(S) == {[from |-> r.from, wid |-> r.wid, seq |-> r.seq] : r \in S}

A == INSTANCE GuardianLimiterSeq WITH
        log <- {[wid |-> r.wid, seq |-> r.seq] : r \in log},
        proxyIn <- Strip(proxyIn),
        enclaveQ <- Strip(enclaveQ),
        replies <- Strip(replies),
        done <- FinalSet,
        mseq <- [n \in Nodes |-> mirror[n].seq]

FullSpec == Init /\ [][Next \/ \E n \in Nodes : StallSnap(n)]_vars

Refines == A!Spec

\* Mutant: the abstract finalize needs one more mirror than the concrete
\* one. The check should fail, which shows it detects a wrong mapping.
AMut == INSTANCE GuardianLimiterSeq WITH
        Quorum <- Quorum + 1,
        log <- {[wid |-> r.wid, seq |-> r.seq] : r \in log},
        proxyIn <- Strip(proxyIn),
        enclaveQ <- Strip(enclaveQ),
        replies <- Strip(replies),
        done <- FinalSet,
        mseq <- [n \in Nodes |-> mirror[n].seq]
RefinesMutant == AMut!Spec
=============================================================================
