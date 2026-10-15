--------------------------- MODULE GuardianSessions ---------------------------
(***************************************************************************)
(* Guardian enclave sessions, the heartbeat write fence, and activation    *)
(* (PROTOCOL.md 9.1, 9.2; safety 19).                                      *)
(*                                                                         *)
(* Time is real time in minutes. Each session's wall clock is real time    *)
(* plus a fixed offset. Monotonic time is real time (README assumption 2). *)
(*                                                                         *)
(* A session heartbeats from OperatorInit until it dies. The host may      *)
(* delay or drop heartbeats. Every write is serialized and gated by the    *)
(* fence: start only if now + Attempt < lastHB + Q - Budget, where lastHB  *)
(* is the monotonic start of the last confirmed heartbeat                  *)
(* (log_writer.rs:72-101). A write not confirmed by start + Attempt makes  *)
(* the enclave panic; the PUT may still become durable up to LateDur after *)
(* that deadline (README assumption 4). The code instead retries the same  *)
(* key while an attempt fits before the fence; a retry rewrites the same   *)
(* object, so treating the first timeout as fatal loses no records.        *)
(*                                                                         *)
(* Activation scans heartbeats in the previous, current, and next hour of  *)
(* its wall clock and requires every other session's newest heartbeat to   *)
(* be at least Q old, and its own at most Fresh old                        *)
(* (heartbeat_checks.rs:92-221). Limiter recovery reads the newest         *)
(* non-empty withdraw hour and the hour before it, and takes the highest   *)
(* next seq (limiter_recovery.rs:48-110). Activation is atomic here.       *)
(*                                                                         *)
(* Heartbeats are abstracted to the first and last wall times, with one    *)
(* heartbeat assumed at every wall minute in between. Session First is     *)
(* active at time 0; the others start uninitialised.                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Sessions,
    First,      \* the session already active at time 0
    Off,        \* Sessions -> wall-clock offset
    Q,          \* quiet period (10)
    Budget,     \* reader clock-skew budget (1)
    Attempt,    \* per-attempt write timeout (5)
    Fresh,      \* own-heartbeat freshness at activation (3)
    HourLen,    \* minutes per S3 hour directory (60)
    LateDur,    \* a timed-out PUT may become durable this long after its deadline
    MaxTime,
    MaxSeq

None == -1
NoPend == [seq |-> None, start |-> None, wall |-> None]

VARIABLES
    t,
    mode,       \* none, standby, active, dead
    hbFirst,    \* wall time of the first heartbeat, or None
    hbLast,     \* wall time of the last heartbeat, or None
    nseq,       \* the session's limiter next seq
    pend,       \* in-flight withdraw write [seq, start, wall], or NoPend
    recs,       \* durable withdraw records [s, seq, wall, dur]
    actAt,      \* ghost: activation time, or None
    recov       \* ghost: [got, truth] next seq at activation

vars == <<t, mode, hbFirst, hbLast, nseq, pend, recs, actAt, recov>>

Wall(s) == t + Off[s]
Hour(w) == w \div HourLen
Max(S) == CHOOSE x \in S : \A y \in S : y <= x
MinOf(a, b) == IF a < b THEN a ELSE b
MaxOf(a, b) == IF a > b THEN a ELSE b

\* Monotonic start of the last heartbeat, in real time.
HbMono(s) == hbLast[s] - Off[s]

FenceOpen(s) == hbLast[s] # None /\ t + Attempt < HbMono(s) + Q - Budget

Init ==
    /\ t = 0
    /\ mode = [s \in Sessions |-> IF s = First THEN "active" ELSE "none"]
    /\ hbFirst = [s \in Sessions |-> IF s = First THEN Off[s] ELSE None]
    /\ hbLast = hbFirst
    /\ nseq = [s \in Sessions |-> 0]
    /\ pend = [s \in Sessions |-> NoPend]
    /\ recs = {}
    /\ actAt = [s \in Sessions |-> IF s = First THEN 0 ELSE None]
    /\ recov = [s \in Sessions |-> [got |-> 0, truth |-> 0]]

Tick ==
    /\ t < MaxTime
    /\ t' = t + 1
    /\ UNCHANGED <<mode, hbFirst, hbLast, nseq, pend, recs, actAt, recov>>

OperatorInit(s) ==
    /\ mode[s] = "none"
    /\ mode' = [mode EXCEPT ![s] = "standby"]
    /\ UNCHANGED <<t, hbFirst, hbLast, nseq, pend, recs, actAt, recov>>

\* At most one heartbeat per minute. The first heartbeat has no fence.
Heartbeat(s) ==
    /\ mode[s] \in {"standby", "active"}
    /\ pend[s] = NoPend
    /\ hbLast[s] # Wall(s)
    /\ hbLast[s] # None => FenceOpen(s)
    /\ hbFirst' = [hbFirst EXCEPT ![s] = IF @ = None THEN Wall(s) ELSE @]
    /\ hbLast' = [hbLast EXCEPT ![s] = Wall(s)]
    /\ UNCHANGED <<t, mode, nseq, pend, recs, actAt, recov>>

StartWrite(s) ==
    /\ mode[s] = "active"
    /\ pend[s] = NoPend
    /\ FenceOpen(s)
    /\ nseq[s] < MaxSeq
    /\ pend' = [pend EXCEPT ![s] = [seq |-> nseq[s], start |-> t, wall |-> Wall(s)]]
    /\ UNCHANGED <<t, mode, hbFirst, hbLast, nseq, recs, actAt, recov>>

\* The PUT becomes durable. Before the deadline the enclave confirms it and
\* advances its seq; after the deadline the enclave has already panicked.
Durable(s) ==
    /\ pend[s] # NoPend
    /\ t <= pend[s].start + Attempt + LateDur
    /\ recs' = recs \cup {[s |-> s, seq |-> pend[s].seq, wall |-> pend[s].wall,
                           dur |-> t]}
    /\ pend' = [pend EXCEPT ![s] = NoPend]
    /\ IF mode[s] = "active" /\ t <= pend[s].start + Attempt
       THEN nseq' = [nseq EXCEPT ![s] = @ + 1]
       ELSE UNCHANGED nseq
    /\ UNCHANGED <<t, mode, hbFirst, hbLast, actAt, recov>>

\* The attempt deadline passes unconfirmed: panic. The PUT may still land.
Timeout(s) ==
    /\ pend[s] # NoPend /\ mode[s] # "dead"
    /\ t > pend[s].start + Attempt
    /\ mode' = [mode EXCEPT ![s] = "dead"]
    /\ UNCHANGED <<t, hbFirst, hbLast, nseq, pend, recs, actAt, recov>>

\* A PUT that can no longer land is gone.
Lost(s) ==
    /\ pend[s] # NoPend
    /\ t > pend[s].start + Attempt + LateDur
    /\ pend' = [pend EXCEPT ![s] = NoPend]
    /\ UNCHANGED <<t, mode, hbFirst, hbLast, nseq, recs, actAt, recov>>

Kill(s) ==
    /\ mode[s] \in {"standby", "active"}
    /\ mode' = [mode EXCEPT ![s] = "dead"]
    /\ UNCHANGED <<t, hbFirst, hbLast, nseq, pend, recs, actAt, recov>>

\* Newest heartbeat of s2 within the activator's three-hour window.
NewestInWindow(s2, w) ==
    LET lo == (Hour(w) - 1) * HourLen
        hi == (Hour(w) + 2) * HourLen - 1
        top == MinOf(hbLast[s2], hi)
    IN IF hbFirst[s2] = None \/ top < MaxOf(hbFirst[s2], lo) THEN None ELSE top

RecoveredSeq ==
    IF recs = {} THEN 0
    ELSE LET hn == Max({Hour(r.wall) : r \in recs})
             R == {r \in recs : Hour(r.wall) \in {hn - 1, hn}}
         IN Max({r.seq : r \in R}) + 1

TrueSeq == IF recs = {} THEN 0 ELSE Max({r.seq : r \in recs}) + 1

Activate(s) ==
    /\ mode[s] = "standby"
    /\ hbLast[s] # None
    /\ Wall(s) - hbLast[s] <= Fresh
    /\ \A s2 \in Sessions \ {s} :
          LET h == NewestInWindow(s2, Wall(s)) IN h = None \/ Wall(s) - h >= Q
    /\ mode' = [mode EXCEPT ![s] = "active"]
    /\ nseq' = [nseq EXCEPT ![s] = RecoveredSeq]
    /\ actAt' = [actAt EXCEPT ![s] = t]
    /\ recov' = [recov EXCEPT ![s] = [got |-> RecoveredSeq, truth |-> TrueSeq]]
    /\ UNCHANGED <<t, hbFirst, hbLast, pend, recs>>

Next ==
    \/ Tick
    \/ \E s \in Sessions :
          \/ OperatorInit(s) \/ Heartbeat(s) \/ StartWrite(s) \/ Durable(s)
          \/ Timeout(s) \/ Lost(s) \/ Kill(s) \/ Activate(s)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties: safety 19 *)

UniqueSeq == \A r1, r2 \in recs : r1.seq = r2.seq => r1 = r2

RecoveryExact == \A s \in Sessions : recov[s].got = recov[s].truth

\* No record from an earlier-activated session becomes durable after a later
\* session activated.
NoLateRecord ==
    \A r \in recs, s \in Sessions :
        (/\ s # r.s /\ actAt[s] # None
         /\ actAt[r.s] # None /\ actAt[r.s] < actAt[s])
            => r.dur <= actAt[s]

\* Two active sessions never both have an open fence.
OneWriter ==
    \A s1, s2 \in Sessions :
        (s1 # s2 /\ mode[s1] = "active" /\ mode[s2] = "active")
            => ~(FenceOpen(s1) /\ FenceOpen(s2))

\* Coverage probe: a handover with records from two sessions. Should fail.
NeverHandover == ~\E r1, r2 \in recs : r1.s # r2.s

=============================================================================
