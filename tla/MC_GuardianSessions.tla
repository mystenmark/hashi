------------------------- MODULE MC_GuardianSessions -------------------------
EXTENDS GuardianSessions, TLC
CONSTANTS a, b, c
\* Wall offsets. b activates second, so b is the reader; "ahead k" means
\* b's clock is k minutes ahead of a's.
OffEq == (a :> 100) @@ (b :> 100)
OffAhead1 == (a :> 100) @@ (b :> 101)
OffAhead2 == (a :> 100) @@ (b :> 102)
\* a's clock is over an hour ahead of b's: a's heartbeats fall outside b's
\* three-hour scan.
OffWriterAhead == (a :> 230) @@ (b :> 100)
\* Three sessions: a's clock is over an hour ahead; b and c agree.
OffRollback == (a :> 230) @@ (b :> 100) @@ (c :> 100)
=============================================================================
