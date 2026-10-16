----------------------------- MODULE MC_MpcSigning -----------------------------
EXTENDS MpcSigning, TLC
CONSTANTS h1, h2, h3, h4, h5, h6, b1, w1, w2
MCNodes == {h1, h2, h3, h4, h5, h6, b1}
MCWids == {w1, w2}
MCInputs == (w1 :> 2) @@ (w2 :> 2)
\* Three inputs in batches of 1, so they reach batches 0, 1, and 2.
MCInputsSpread == (w1 :> 1) @@ (w2 :> 2)
=============================================================================
