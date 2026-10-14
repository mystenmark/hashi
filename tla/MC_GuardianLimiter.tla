------------------------- MODULE MC_GuardianLimiter -------------------------
EXTENDS GuardianLimiter, TLC
AmtOne == [w \in Wids |-> 1]
AmtTwo == [w \in Wids |-> 2]
Symm == Permutations(Nodes) \cup Permutations(Wids)
=============================================================================
