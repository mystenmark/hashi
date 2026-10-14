----------------------------- MODULE DkgOutputs -----------------------------
(***************************************************************************)
(* Which honest members obtain a DKG output, and whether the committee can *)
(* then gather a completion certificate (PROTOCOL.md 8.1, 8.2).            *)
(*                                                                         *)
(* Dealers post certificates to the TOB in an order the adversary picks.   *)
(* A certificate needs signatures from weight >= t + f; honest receivers   *)
(* sign only if their own shares verify, and Byzantine receivers always    *)
(* sign. A Byzantine dealer may send bad shares to a set of honest         *)
(* members that do not sign. Parties take the first dealers whose weight   *)
(* reaches t. A party with bad shares from a selected dealer obtains an    *)
(* output only if complaints are answered.                                 *)
(*                                                                         *)
(* Every member has weight 1, which matches reduced weights of one unit.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Members,
    Byz,            \* Byzantine members
    MaxFaultyBps,   \* mpc_max_faulty_in_basis_points
    ComplaintsOn    \* honest members answer complaints

ASSUME Byz \subseteq Members

W == Cardinality(Members)
F == LET x == (W * MaxFaultyBps) \div 10000 IN IF x < 1 THEN 1 ELSE x
T == W - 2 * F
DealerQ == T + F
\* ceil(W * 6667 / 10000)
CompletionQ == (W * 6667 + 9999) \div 10000
Honest == Members \ Byz

ASSUME T > F

VARIABLES
    sel,    \* set of [dealer, hurt] for the TOB prefix selected so far
    posted  \* dealers in the prefix

vars == <<sel, posted>>

Init == sel = {} /\ posted = {}

\* The adversary orders the TOB, so any T dealers can form the prefix. Order
\* within the prefix does not affect outputs.
Deal(d) ==
    /\ Cardinality(posted) < T
    /\ d \notin posted
    /\ \E hurt \in (IF d \in Byz THEN SUBSET Honest ELSE {{}}) :
         /\ Cardinality(Members \ hurt) >= DealerQ
         /\ sel' = sel \cup {[dealer |-> d, hurt |-> hurt]}
         /\ posted' = posted \cup {d}

Next == \E d \in Members : Deal(d)

Spec == Init /\ [][Next]_vars

Symm == Permutations(Honest) \cup Permutations(Byz)

-----------------------------------------------------------------------------

PrefixDone == Cardinality(posted) = T

Hurt == UNION {s.hurt : s \in sel}

Holders == IF ComplaintsOn THEN Honest ELSE Honest \ Hurt

\* Once the prefix is fixed, honest holders plus Byzantine members reach the
\* completion threshold.
CanComplete ==
    PrefixDone => Cardinality(Holders) + Cardinality(Byz) >= CompletionQ

\* Byzantine members may withhold completion signatures, so liveness needs
\* honest holders alone to reach the completion threshold.
HonestCanComplete ==
    PrefixDone => Cardinality(Holders) >= CompletionQ

\* After completion, honest holders alone can reach the signing threshold.
HoldersReachT ==
    (PrefixDone /\ Cardinality(Holders) + Cardinality(Byz) >= CompletionQ)
        => Cardinality(Holders) >= T

=============================================================================
