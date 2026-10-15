----------------------------- MODULE DkgRotation -----------------------------
(***************************************************************************)
(* A rotation whose Byzantine dealers are not in the new committee         *)
(* (PROTOCOL.md 8.2; R10 with F1). Governance excluded them with           *)
(* IgnoreMember, so they deal from the old committee but cannot withhold   *)
(* completion signatures.                                                  *)
(*                                                                         *)
(* Receivers are the new committee, with unit weights. A dealer            *)
(* certificate needs new-committee weight >= t + f; honest receivers sign  *)
(* only if their shares verify, and Byzantine receivers always sign. A     *)
(* Byzantine dealer may give bad shares to honest receivers that then do   *)
(* not sign. Parties take the first PrevT dealers, in an order Sui fixes   *)
(* and the Byzantine dealers race for. A receiver with bad shares from a   *)
(* selected dealer obtains no output unless complaints are answered.       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    NewMembers,
    NewByz,         \* Byzantine members of the new committee
    OldHonest,      \* honest dealers of the old committee
    OldByz,         \* Byzantine dealers of the old committee, not in NewMembers
    PrevT,          \* dealers selected: the old committee's threshold
    MaxFaultyBps,
    ComplaintsOn

ASSUME NewByz \subseteq NewMembers /\ OldByz \cap NewMembers = {}

W == Cardinality(NewMembers)
F == LET x == (W * MaxFaultyBps) \div 10000 IN IF x < 1 THEN 1 ELSE x
T == W - 2 * F
DealerQ == T + F
CompletionQ == (W * 6667 + 9999) \div 10000
Honest == NewMembers \ NewByz
Dealers == OldHonest \cup OldByz

ASSUME T > F

VARIABLES sel, posted

vars == <<sel, posted>>

Init == sel = {} /\ posted = {}

Deal(d) ==
    /\ Cardinality(posted) < PrevT
    /\ d \notin posted
    /\ \E hurt \in (IF d \in OldByz THEN SUBSET Honest ELSE {{}}) :
         /\ Cardinality(NewMembers \ hurt) >= DealerQ
         /\ sel' = sel \cup {[dealer |-> d, hurt |-> hurt]}
         /\ posted' = posted \cup {d}

Next == \E d \in Dealers : Deal(d)

Spec == Init /\ [][Next]_vars

Symm == Permutations(OldHonest) \cup Permutations(OldByz)

-----------------------------------------------------------------------------

PrefixDone == Cardinality(posted) = PrevT
Hurt == UNION {s.hurt : s \in sel}
Holders == IF ComplaintsOn THEN Honest ELSE Honest \ Hurt

\* Honest holders alone reach the completion threshold, so the rotation that
\* removes the Byzantine dealers completes.
HonestCanComplete == PrefixDone => Cardinality(Holders) >= CompletionQ

\* Coverage probe: some Byzantine dealer is selected. Should fail.
NoByzSelected == \A s \in sel : s.dealer \notin OldByz
=============================================================================
