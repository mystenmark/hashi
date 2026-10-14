------------------------------- MODULE Presig -------------------------------
(***************************************************************************)
(* Presignature allocation and threshold-signing nonce safety.             *)
(*                                                                         *)
(* Chain side: the presig allocator, per-withdrawal SigningBatch slots,    *)
(* reallocation, and epoch changes (PROTOCOL.md 7.3, 8.3).                 *)
(* Node side: each honest node signs from a lagging view of the chain,     *)
(* tracks which presignatures it has taken, and can crash and restart      *)
(* (PROTOCOL.md 8.4, 8.5).                                                 *)
(*                                                                         *)
(* A presignature is identified by <<node, epoch, position>>. A node maps  *)
(* a global index to a local position through map[n][e]. The request a   *)
(* node signs is <<wid, input, randomness, epoch, index>>; the sighash is *)
(* fixed by <<wid, input>> and the seal randomness by the epoch.           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,            \* honest committee nodes
    Wids,             \* withdrawal transaction ids
    MaxInputs,        \* max inputs per withdrawal
    MaxEpoch,         \* epochs are 0..MaxEpoch
    MaxIndex,         \* presig indices per epoch are 0..MaxIndex-1
    MaxRand,          \* bound on fresh randomness draws
    CheckEpochTag,    \* honest signers require slot tag = view epoch
    AllowCodeChange   \* a restart may change the index-to-position map

Epochs == 0..MaxEpoch
Index == 0..(MaxIndex - 1)
Perms == {f \in [Index -> Index] : \A a, b \in Index : a # b => f[a] # f[b]}
Identity == [i \in Index |-> i]
NoReq == <<>>
Reused == <<"reused">>
None == [k |-> 0, slots |-> <<>>, tag |-> 0, rand |-> 0]

PresigId == Nodes \X Epochs \X Index
Request == Wids \X (1..MaxInputs) \X (1..MaxRand) \X Epochs \X Index

VARIABLES
    epoch,          \* hashiEpoch
    alloc,          \* presig allocator cursor
    reconfiguring,  \* a reconfiguration is pending
    txns,           \* Wids -> Txn \cup {None}
    randCtr,        \* last randomness drawn
    view,           \* per node: snapshot [epoch, alloc, txns]
    taken,          \* per node: presig ids taken in this process
    map,            \* per node: Epochs -> index-to-position permutation
    sigs            \* ghost: per presig id, NoReq, the first request, or Reused

chainVars == <<epoch, alloc, reconfiguring, txns, randCtr>>
nodeVars == <<view, taken, map>>
vars == <<chainVars, nodeVars, sigs>>

Snapshot == [epoch |-> epoch, alloc |-> alloc, txns |-> txns]

TypeOK ==
    /\ epoch \in Epochs
    /\ alloc \in 0..MaxIndex
    /\ reconfiguring \in BOOLEAN
    /\ randCtr \in 0..MaxRand
    /\ \A w \in Wids : txns[w] = None \/ txns[w].tag \in Epochs
    /\ \A n \in Nodes : view[n].epoch \in Epochs
    /\ \A n \in Nodes : taken[n] \subseteq PresigId
    /\ \A n \in Nodes : map[n] \in [Epochs -> Perms]
    /\ sigs \in [PresigId -> Request \cup {NoReq, Reused}]

Init ==
    /\ epoch = 0
    /\ alloc = 0
    /\ reconfiguring = FALSE
    /\ txns = [w \in Wids |-> None]
    /\ randCtr = 0
    /\ view = [n \in Nodes |-> [epoch |-> 0, alloc |-> 0,
                                txns |-> [w \in Wids |-> None]]]
    /\ taken = [n \in Nodes |-> {}]
    /\ map = [n \in Nodes |-> [e \in Epochs |-> Identity]]
    /\ sigs = [p \in PresigId |-> NoReq]

-----------------------------------------------------------------------------
(* Chain actions *)

\* commit_withdrawal_tx: allocate k consecutive indices tagged with epoch.
Commit(w, k) ==
    /\ ~reconfiguring
    /\ txns[w] = None
    /\ alloc + k <= MaxIndex
    /\ randCtr < MaxRand
    /\ txns' = [txns EXCEPT ![w] =
                  [k |-> k,
                   slots |-> [j \in 1..k |-> [st |-> "P", idx |-> alloc + j - 1]],
                   tag |-> epoch,
                   rand |-> randCtr + 1]]
    /\ alloc' = alloc + k
    /\ randCtr' = randCtr + 1
    /\ UNCHANGED <<epoch, reconfiguring, nodeVars, sigs>>

\* commit_input_signatures: Move checks neither the tag nor the signature.
RecordSig(w, j) ==
    /\ ~reconfiguring
    /\ txns[w] # None
    /\ j \in 1..txns[w].k
    /\ txns[w].slots[j].st = "P"
    /\ txns' = [txns EXCEPT ![w].slots[j].st = "S"]
    /\ UNCHANGED <<epoch, alloc, reconfiguring, randCtr, nodeVars, sigs>>

PendingSlots(t) == {j \in 1..t.k : t.slots[j].st = "P"}

\* reallocate_presigs: give stale Pending slots indices in the current epoch,
\* in slot order. Randomness is redrawn only when some slot is Pending.
Reallocate(w) ==
    /\ ~reconfiguring
    /\ txns[w] # None
    /\ txns[w].tag # epoch
    /\ LET t == txns[w]
           P == PendingSlots(t)
           n == Cardinality(P)
       IN /\ alloc + n <= MaxIndex
          /\ n > 0 => randCtr < MaxRand
          /\ txns' = [txns EXCEPT ![w] =
                [t EXCEPT
                   !.slots = [j \in 1..t.k |->
                       IF j \in P
                       THEN [st |-> "P",
                             idx |-> alloc + Cardinality({q \in P : q < j})]
                       ELSE t.slots[j]],
                   !.tag = epoch,
                   !.rand = IF n > 0 THEN randCtr + 1 ELSE t.rand]]
          /\ alloc' = alloc + n
          /\ randCtr' = IF n > 0 THEN randCtr + 1 ELSE randCtr
    /\ UNCHANGED <<epoch, reconfiguring, nodeVars, sigs>>

StartReconfig ==
    /\ ~reconfiguring
    /\ epoch < MaxEpoch
    /\ reconfiguring' = TRUE
    /\ UNCHANGED <<epoch, alloc, txns, randCtr, nodeVars, sigs>>

\* end_reconfig resets the allocator.
EndReconfig ==
    /\ reconfiguring
    /\ epoch' = epoch + 1
    /\ alloc' = 0
    /\ reconfiguring' = FALSE
    /\ UNCHANGED <<txns, randCtr, nodeVars, sigs>>

\* abort_reconfig leaves the epoch and allocator unchanged.
AbortReconfig ==
    /\ reconfiguring
    /\ reconfiguring' = FALSE
    /\ UNCHANGED <<epoch, alloc, txns, randCtr, nodeVars, sigs>>

-----------------------------------------------------------------------------
(* Node actions *)

\* The node's view catches up to the chain. The signing manager follows the
\* view epoch, so the pool used for signing is always that of view[n].epoch.
Sync(n) ==
    /\ view[n] # Snapshot
    /\ view' = [view EXCEPT ![n] = Snapshot]
    /\ UNCHANGED <<chainVars, taken, map, sigs>>

\* A follower signs input j of w when asked. Any member can ask at any time.
Sign(n, w, j) ==
    LET v == view[n]
        t == v.txns[w]
    IN /\ t # None
       /\ j \in 1..t.k
       /\ t.slots[j].st = "P"
       /\ CheckEpochTag => t.tag = v.epoch
       /\ LET e == v.epoch
              i == t.slots[j].idx
              p == <<n, e, map[n][e][i]>>
          IN /\ p \notin taken[n]
             /\ taken' = [taken EXCEPT ![n] = @ \cup {p}]
             /\ LET r == <<w, j, t.rand, e, i>>
                IN sigs' = [sigs EXCEPT ![p] =
                              IF @ \in {NoReq, r} THEN r ELSE Reused]
       /\ UNCHANGED <<chainVars, view, map>>

PendingWithTag(v, i) ==
    \E w \in Wids :
        /\ v.txns[w] # None
        /\ v.txns[w].tag = v.epoch
        /\ \E j \in PendingSlots(v.txns[w]) : v.txns[w].slots[j].idx = i

\* Recovery disables every allocated index that is not still Pending with the
\* current tag (service.rs:956-976). A code change may alter the map.
Restart(n) ==
    LET v == view[n]
        e == v.epoch
    IN \E q \in (IF AllowCodeChange THEN Perms ELSE {map[n][e]}) :
         /\ map' = [map EXCEPT ![n][e] = q]
         /\ taken' = [taken EXCEPT ![n] =
               {<<n, e, q[i]>> : i \in {x \in Index :
                                         x < v.alloc /\ ~PendingWithTag(v, x)}}]
         /\ UNCHANGED <<chainVars, view, sigs>>

-----------------------------------------------------------------------------

Next ==
    \/ \E w \in Wids, k \in 1..MaxInputs : Commit(w, k)
    \/ \E w \in Wids, j \in 1..MaxInputs : RecordSig(w, j)
    \/ \E w \in Wids : Reallocate(w)
    \/ StartReconfig \/ EndReconfig \/ AbortReconfig
    \/ \E n \in Nodes : Sync(n) \/ Restart(n)
    \/ \E n \in Nodes, w \in Wids, j \in 1..MaxInputs : Sign(n, w, j)

Spec == Init /\ [][Next]_vars

Symm == Permutations(Nodes) \cup Permutations(Wids)

-----------------------------------------------------------------------------
(* Properties *)

\* PROTOCOL.md safety 15: one request per underlying presignature.
NonceSafety ==
    \A p \in PresigId : sigs[p] # Reused

PendingPairs ==
    {<<w, j>> \in Wids \X (1..MaxInputs) :
        txns[w] # None /\ j \in PendingSlots(txns[w])}

\* Two Pending slots with the same tag have different indices.
UniquePendingIndex ==
    \A a, b \in PendingPairs :
        (a # b /\ txns[a[1]].tag = txns[b[1]].tag)
            => txns[a[1]].slots[a[2]].idx # txns[b[1]].slots[b[2]].idx

\* Every current-epoch Pending index is below the allocator.
PendingBelowAlloc ==
    \A a \in PendingPairs :
        txns[a[1]].tag = epoch => txns[a[1]].slots[a[2]].idx < alloc

TagNotAhead ==
    \A w \in Wids : txns[w] # None => txns[w].tag <= epoch

ViewNotAhead ==
    \A n \in Nodes : view[n].epoch <= epoch

=============================================================================
