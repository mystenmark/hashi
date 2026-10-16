------------------------------ MODULE MpcSigning ------------------------------
(***************************************************************************)
(* Liveness of MPC input signing (PROTOCOL.md 8.3, 8.4).                   *)
(*                                                                         *)
(* commit_withdrawal_tx allocates presig indices [alloc, alloc + n) tagged *)
(* with the epoch. Batches are generated in order, on demand. A node       *)
(* installs batch k only after batch k - 1 (set_next_batch,                *)
(* signing.rs:428-470). A node may skip batch k for node-local reasons     *)
(* (lost round state, failed retrieval; mpc_except_signing.rs:3825-3990);  *)
(* it then discards the batch (service.rs:831-837) and, by contiguity,     *)
(* can sign nothing at or after batch k while its process runs. A restart  *)
(* rebuilds from the first batch with a pending index (service.rs:1038),   *)
(* which this model leaves out. A seal (2/3, first wins) is signed by      *)
(* nodes that skipped no earlier batch: a node signs before its own skip   *)
(* check (service.rs:813, 831). Byzantine nodes refuse. An input is signed *)
(* when T honest nodes that installed its batch sign. An epoch change      *)
(* resets the allocator, batches, and seals; the leader reallocates stale  *)
(* slots.                                                                  *)
(*                                                                         *)
(* Every member has weight 1.                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Nodes, Byz,
    T,          \* signing threshold (reduced t)
    SealQ,      \* seal certificate weight
    BatchSize,
    MaxBatch,   \* batches per epoch the model generates
    Wids,
    Inputs,     \* Wids -> number of inputs
    MaxEpoch,
    MayStick,   \* honest nodes that may skip a batch
    PerBatch,   \* at most this many skippers per batch
    FaultEpochs \* epochs in which skips occur

Honest == Nodes \ Byz

VARIABLES
    epoch,
    alloc,
    slots,      \* Wids -> sequence of [idx, tag, signed], or <<>> before commit
    done,       \* Wids whose input signatures are recorded on chain
    ngen,       \* batches generated this epoch
    skip,       \* batch -> honest nodes that skipped it
    sealed,     \* batches sealed this epoch
    inst        \* per node: batches installed this epoch

vars == <<epoch, alloc, slots, done, ngen, skip, sealed, inst>>

Batches == 0..(MaxBatch - 1)
BatchOf(i) == i \div BatchSize
\* Honest nodes that sign batch k's seal: those that skipped no earlier batch.
\* A node signs the seal before its skip check (service.rs:813, 831), so its
\* own skip of batch k does not remove it; a node that skipped an earlier
\* batch keeps retrying that batch and never reaches k.
SealSigners(k) == Honest \ UNION {skip[x] : x \in 0..(k - 1)}
\* Nodes able to sign in batch k: installed it.
Able(k) == {n \in Honest : inst[n] > k}

Init ==
    /\ epoch = 0 /\ alloc = 0
    /\ slots = [w \in Wids |-> <<>>]
    /\ done = {}
    /\ ngen = 0
    /\ skip = [k \in Batches |-> {}]
    /\ sealed = {}
    /\ inst = [n \in Nodes |-> 0]

Commit(w) ==
    /\ slots[w] = <<>>
    /\ alloc + Inputs[w] <= MaxBatch * BatchSize
    /\ slots' = [slots EXCEPT ![w] =
                   [j \in 1..Inputs[w] |-> [idx |-> alloc + j - 1, tag |-> epoch,
                                            signed |-> FALSE]]]
    /\ alloc' = alloc + Inputs[w]
    /\ UNCHANGED <<epoch, done, ngen, skip, sealed, inst>>

\* Nonce generation for the next batch; some honest nodes may skip it.
Generate ==
    /\ ngen < MaxBatch
    /\ \E S \in SUBSET (IF epoch \in FaultEpochs THEN MayStick ELSE {}) :
         /\ Cardinality(S) <= PerBatch
         /\ skip' = [skip EXCEPT ![ngen] = S]
    /\ ngen' = ngen + 1
    /\ UNCHANGED <<epoch, alloc, slots, done, sealed, inst>>

\* Nodes that built batch k sign its seal; Byzantine nodes refuse.
Seal(k) ==
    /\ k < ngen /\ k \notin sealed
    /\ Cardinality(SealSigners(k)) >= SealQ
    /\ sealed' = sealed \cup {k}
    /\ UNCHANGED <<epoch, alloc, slots, done, ngen, skip, inst>>

\* A node installs the next batch unless it skipped it.
Install(n) ==
    /\ n \in Honest
    /\ inst[n] < ngen
    /\ n \notin skip[inst[n]]
    /\ inst' = [inst EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<epoch, alloc, slots, done, ngen, skip, sealed>>

Sign(w, j) ==
    /\ j \in DOMAIN slots[w]
    /\ LET s == slots[w][j] IN
         /\ ~s.signed /\ s.tag = epoch
         /\ BatchOf(s.idx) \in sealed
         /\ Cardinality(Able(BatchOf(s.idx))) >= T
    /\ slots' = [slots EXCEPT ![w][j].signed = TRUE]
    /\ UNCHANGED <<epoch, alloc, done, ngen, skip, sealed, inst>>

RecordSigs(w) ==
    /\ slots[w] # <<>> /\ w \notin done
    /\ \A j \in DOMAIN slots[w] : slots[w][j].signed
    /\ done' = done \cup {w}
    /\ UNCHANGED <<epoch, alloc, slots, ngen, skip, sealed, inst>>

\* reallocate_presigs moves unsigned stale slots to fresh indices.
Reallocate(w) ==
    /\ w \notin done
    /\ \E j \in DOMAIN slots[w] : ~slots[w][j].signed /\ slots[w][j].tag # epoch
    /\ LET U == {j \in DOMAIN slots[w] : ~slots[w][j].signed}
           n == Cardinality(U)
           rank(j) == Cardinality({x \in U : x < j})
       IN /\ alloc + n <= MaxBatch * BatchSize
          /\ slots' = [slots EXCEPT ![w] =
                [j \in DOMAIN slots[w] |->
                    IF j \in U THEN [idx |-> alloc + rank(j), tag |-> epoch,
                                     signed |-> FALSE]
                    ELSE slots[w][j]]]
          /\ alloc' = alloc + n
    /\ UNCHANGED <<epoch, done, ngen, skip, sealed, inst>>

\* A completed reconfiguration: end_reconfig resets the allocator.
EpochChange ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ alloc' = 0 /\ ngen' = 0 /\ sealed' = {}
    /\ skip' = [k \in Batches |-> {}]
    /\ inst' = [n \in Nodes |-> 0]
    /\ UNCHANGED <<slots, done>>

Next ==
    \/ \E w \in Wids : Commit(w) \/ RecordSigs(w) \/ Reallocate(w)
    \/ Generate
    \/ \E k \in Batches : Seal(k)
    \/ \E n \in Nodes : Install(n)
    \/ \E w \in Wids, j \in 1..5 : Sign(w, j)
    \/ EpochChange

Spec == Init /\ [][Next]_vars

\* Generation, sealing, installing, signing, recording, and reallocation
\* happen eventually. Epoch changes are not forced.
Fairness ==
    /\ WF_vars(Generate)
    /\ \A k \in Batches : WF_vars(Seal(k))
    /\ \A n \in Nodes : WF_vars(Install(n))
    /\ \A w \in Wids, j \in 1..5 : WF_vars(Sign(w, j))
    /\ \A w \in Wids : WF_vars(RecordSigs(w)) /\ WF_vars(Reallocate(w))

LiveSpec == Spec /\ Fairness

\* With a later epoch change forced, for comparison.
LiveSpecEpoch == LiveSpec /\ WF_vars(EpochChange)

Committed(w) == slots[w] # <<>>

\* Every committed withdrawal gets all its input signatures recorded.
SigningCompletes == \A w \in Wids : Committed(w) ~> (w \in done)

\* Coverage probe: some withdrawal gets signed. Should fail.
NeverSigned == done = {}
=============================================================================
