--------------------------- MODULE GuardianLimiter ---------------------------
(***************************************************************************)
(* Guardian withdrawal signing path with one active enclave session        *)
(* (PROTOCOL.md 7.3 steps 7-9, 9.4, 9.5).                                  *)
(*                                                                         *)
(* Leaders send StandardWithdrawal requests through the proxy. The proxy   *)
(* replays a logged wid; otherwise it forwards to the enclave. Lookup and  *)
(* forward are separate steps. The enclave checks the timestamp window and *)
(* consumes limiter tokens, then logs the record, which is the release     *)
(* point. Leaders then gather a finalize certificate, for which followers  *)
(* check their local limiter mirrors. Mirrors advance when a node observes *)
(* a finalize on chain, and can be seeded or snapped from the Guardian.    *)
(*                                                                         *)
(* Time is one integer clock shared by the enclave and nodes.              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Nodes,      \* committee nodes; any of them may act as leader
    Wids,       \* withdrawal transaction ids
    Amt,        \* Wids -> amount (inputs - change)
    Max,        \* limiter capacity
    Rate,       \* limiter refill per time unit
    MaxTime,    \* clock runs 0..MaxTime
    Past,       \* enclave accepts ts >= now - Past
    Future,     \* enclave accepts ts <= now + Future
    TsSkew,     \* leaders pick ts within TsSkew of now
    Quorum,     \* number of nodes whose mirrors must accept a finalize
    Slack,      \* slack in the real-time rate bound being checked
    MaxSnaps,   \* bound on Reconcile plus Restart steps, to keep TLC finite
    SnapBehind, \* Reconcile may snap a mirror that is behind the Guardian
    RotateTo    \* max capacity of a later session; Max disables rotation

ASSUME Quorum <= Cardinality(Nodes)

VARIABLES
    now,
    gSeq, gTok, gLast,  \* enclave limiter
    log,                \* durable withdraw records
    proxyIn,            \* requests waiting for proxy lookup
    enclaveQ,           \* requests forwarded to the enclave
    replies,            \* requests whose guardian signatures a leader holds
    ready,              \* wids that are MPC-complete and not finalized
    final,              \* sequence of finalized [wid, ts] in chain order
    mirror,             \* per node: [seq, tok, last]
    seen,               \* per node: prefix of final the mirror has applied
    snaps,              \* Reconcile plus Restart steps taken
    gMax                \* the session's max capacity, adopted by all mirrors

vars == <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies, ready,
          final, mirror, seen, snaps, gMax>>

Min(a, b) == IF a < b THEN a ELSE b
Cap(m, ts) == Min(gMax, m.tok + (ts - m.last) * Rate)
Valid(m, s, ts, a) == s = m.seq /\ ts >= m.last /\ Cap(m, ts) >= a
GState == [seq |-> gSeq, tok |-> gTok, last |-> gLast]

FinalSet == {final[i].wid : i \in 1..Len(final)}
HasLog(w) == \E r \in log : r.wid = w
Outstanding(n, w) ==
    \E r \in proxyIn \cup enclaveQ \cup replies : r.from = n /\ r.wid = w

RECURSIVE SumAmt(_)
SumAmt(S) == IF S = {} THEN 0
             ELSE LET r == CHOOSE x \in S : TRUE IN r.amt + SumAmt(S \ {r})

TypeOK ==
    /\ now \in 0..MaxTime
    /\ gSeq \in Nat /\ gTok \in 0..gMax /\ gLast \in Nat
    /\ ready \subseteq Wids
    /\ \A n \in Nodes : seen[n] \in 0..Len(final)

Init ==
    /\ now = 0
    /\ gSeq = 0 /\ gTok = Max /\ gLast = 0
    /\ log = {}
    /\ proxyIn = {} /\ enclaveQ = {} /\ replies = {}
    /\ ready = {}
    /\ final = <<>>
    /\ mirror = [n \in Nodes |-> [seq |-> 0, tok |-> Max, last |-> 0]]
    /\ seen = [n \in Nodes |-> 0]
    /\ snaps = 0
    /\ gMax = Max

-----------------------------------------------------------------------------

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies, ready,
                   final, mirror, seen, snaps, gMax>>

\* Environment: a withdrawal's MPC signatures are all committed on chain.
MpcComplete(w) ==
    /\ w \notin ready /\ w \notin FinalSet
    /\ ready' = ready \cup {w}
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies,
                   final, mirror, seen, snaps, gMax>>

TsRange == {t \in 0..(MaxTime + TsSkew) : now <= t + TsSkew /\ t <= now + TsSkew}

\* A leader checks its own mirror, gathers the guardian-request certificate
\* (honest signers check only the timestamp), and calls the proxy.
Request(n, w) ==
    /\ w \in ready
    /\ ~Outstanding(n, w)
    /\ \E ts \in TsRange :
         /\ Valid(mirror[n], mirror[n].seq, ts, Amt[w])
         /\ proxyIn' = proxyIn \cup
              {[from |-> n, wid |-> w, seq |-> mirror[n].seq, ts |-> ts]}
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, enclaveQ, replies, ready,
                   final, mirror, seen, snaps, gMax>>

\* Proxy lookup. A hit replays the logged signatures; a miss forwards.
Proxy(r) ==
    /\ r \in proxyIn
    /\ proxyIn' = proxyIn \ {r}
    /\ IF HasLog(r.wid)
       THEN /\ replies' = replies \cup {r}
            /\ UNCHANGED enclaveQ
       ELSE /\ enclaveQ' = enclaveQ \cup {r}
            /\ UNCHANGED replies
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, ready, final, mirror, seen,
                   snaps, gMax>>

\* Enclave handling: timestamp window, consume, sign, log (release point).
\* A rejected request is dropped; the leader may retry.
Enclave(r) ==
    /\ r \in enclaveQ
    /\ enclaveQ' = enclaveQ \ {r}
    /\ IF /\ r.ts + Past >= now
          /\ r.ts <= now + Future
          /\ Valid(GState, r.seq, r.ts, Amt[r.wid])
       THEN /\ gSeq' = gSeq + 1
            /\ gTok' = Cap(GState, r.ts) - Amt[r.wid]
            /\ gLast' = r.ts
            /\ log' = log \cup {[wid |-> r.wid, seq |-> r.seq, ts |-> r.ts,
                                 amt |-> Amt[r.wid], at |-> now]}
            /\ replies' = replies \cup {r}
       ELSE UNCHANGED <<gSeq, gTok, gLast, log, replies>>
    /\ UNCHANGED <<now, proxyIn, ready, final, mirror, seen, snaps, gMax>>

\* A leader that holds guardian signatures gathers the finalize certificate.
\* Each follower checks validate_consume(seq, ts, amount) on its own mirror.
Finalize(r) ==
    /\ r \in replies
    /\ r.wid \in ready
    /\ Cardinality({m \in Nodes : Valid(mirror[m], r.seq, r.ts, Amt[r.wid])})
          >= Quorum
    /\ ready' = ready \ {r.wid}
    /\ final' = Append(final, [wid |-> r.wid, ts |-> now])
    /\ replies' = {x \in replies : x.wid # r.wid}
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, mirror,
                   seen, snaps, gMax>>

\* A leader gives up on a reply it cannot finalize, and may request again.
DropReply(r) ==
    /\ r \in replies
    /\ replies' = replies \ {r}
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, ready,
                   final, mirror, seen, snaps, gMax>>

\* A node observes the next finalize and applies it with its own next_seq and
\* the finalize checkpoint time. On error the mirror is left unchanged.
Observe(n) ==
    /\ seen[n] < Len(final)
    /\ LET f == final[seen[n] + 1]
           m == mirror[n]
       IN mirror' = [mirror EXCEPT ![n] =
              IF f.ts >= m.last /\ Cap(m, f.ts) >= Amt[f.wid]
              THEN [seq |-> m.seq + 1, tok |-> Cap(m, f.ts) - Amt[f.wid],
                    last |-> f.ts]
              ELSE m]
    /\ seen' = [seen EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies,
                   ready, final, snaps, gMax>>

\* Periodic reconcile snaps the mirror to the Guardian. The code snaps at
\* once when ahead or when only tokens differ, and after about 5 minutes
\* when behind. SnapBehind allows the behind case at any time.
Reconcile(n) ==
    /\ snaps < MaxSnaps
    /\ snaps' = snaps + 1
    /\ mirror[n] # GState
    /\ \/ mirror[n].seq >= gSeq
       \/ SnapBehind
    /\ mirror' = [mirror EXCEPT ![n] = GState]
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies,
                   ready, final, seen, gMax>>

\* A restart seeds the mirror from GetGuardianInfo at the current chain point.
Restart(n) ==
    /\ snaps < MaxSnaps
    /\ snaps' = snaps + 1
    /\ mirror' = [mirror EXCEPT ![n] = GState]
    /\ seen' = [seen EXCEPT ![n] = Len(final)]
    /\ UNCHANGED <<now, gSeq, gTok, gLast, log, proxyIn, enclaveQ, replies,
                   ready, final, gMax>>

\* An operator rotation starts a session with max RotateTo. Activation
\* recovers seq and tokens from the log and caps tokens to the new max;
\* nodes adopt the new config on their next reconcile tick
\* (limiter_recovery.rs:44-85, guardian_limiter.rs:157-166).
Rotate ==
    /\ gMax = Max /\ RotateTo # Max
    /\ gMax' = RotateTo
    /\ gTok' = Min(gTok, RotateTo)
    /\ mirror' = [n \in Nodes |-> [mirror[n] EXCEPT !.tok = Min(@, RotateTo)]]
    /\ UNCHANGED <<now, gSeq, gLast, log, proxyIn, enclaveQ, replies, ready,
                   final, seen, snaps>>

Next ==
    \/ Tick
    \/ \E w \in Wids : MpcComplete(w)
    \/ \E n \in Nodes, w \in Wids : Request(n, w)
    \/ \E r \in proxyIn : Proxy(r)
    \/ \E r \in enclaveQ : Enclave(r)
    \/ \E r \in replies : Finalize(r) \/ DropReply(r)
    \/ \E n \in Nodes : Observe(n) \/ Reconcile(n) \/ Restart(n)
    \/ Rotate

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

\* Flagged point 5: a wid is consumed at most once.
NoDoubleConsume ==
    \A r1, r2 \in log : r1.wid = r2.wid => r1 = r2

\* The bucket arithmetic over consecutive records (safety 18, first part).
SeqRateBound ==
    \A r1, r2 \in log :
        r1.seq <= r2.seq =>
            SumAmt({r \in log : r.seq >= r1.seq /\ r.seq <= r2.seq})
                <= Max + Rate * (r2.ts - r1.ts)

\* Outflow released during enclave time [a, b] (safety 18, second part).
RealTimeRateBound ==
    \A a \in 0..MaxTime : \A b \in a..MaxTime :
        SumAmt({r \in log : r.at >= a /\ r.at <= b}) <= Max + Rate * (b - a + Slack)

=============================================================================
