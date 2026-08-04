# vigil

A *C. elegans* neural-substrate simulator in pure Rust, built as a scientific
**instrument with stated epistemic bounds** — not as an argument for a
conclusion.

```
vigil claims       what this instrument may and may not conclude
vigil substrate    connectome + full cleaning report
vigil dynamics     parameter provenance + calibrated stimulation sweep
vigil metrics      PCI / Φ, with the null model stated
vigil validate     every validation gate (exits non-zero when data is absent)
vigil anchor       real-EEG sleep anchor across all subject-nights
vigil transfer     state round-trip + Benettin Lyapunov  [SIM only]
vigil lesion       clamped-node experiments with bootstrap CIs
vigil manifest     reproducibility manifest (checksums, seeds, provenance)
```

## The contract

Every quantity vigil prints is tagged:

- **[SIM]** — a property of *this deterministic simulation*.
- **[BIO]** — an independently established biological fact, with a citation.
- **[UNFITTED]** — a free parameter not constrained by any data available here.

And one rule governs the rest:

> **A biological claim requires reference data. If the data is absent, the claim
> is reported `UNVALIDATED` — never as a pass.**

Run `vigil validate` with no reference data and it exits **non-zero**, having
licensed nothing:

```
  [UNVALIDATED] model reproduces observed whole-brain co-activity structure
  [UNVALIDATED] model reproduces published ablation / optogenetic outcomes
  [   FAIL    ] model reproduces the tap-withdrawal reflex (held-out behaviour)
  [UNVALIDATED] LZc instrument recovers wake > slow-wave-sleep on real human EEG

  0 passed, 1 failed, 3 unvalidated (of 4 gates)

  NO BIOLOGICAL CLAIM IS LICENSED BY THIS RUN.
```

**vigil does not measure consciousness, identity, death, or mind preservation.**
It measures correlates of conscious *level* and dynamical properties of one model
whose synaptic parameters are unfitted. See [`FINDINGS.md`](FINDINGS.md) for what
it *does* support, and
[`docs/FINDINGS_v0.1_WITHDRAWN.md`](docs/FINDINGS_v0.1_WITHDRAWN.md) for the
conclusions that were withdrawn, and why.

## Architecture

Rebuilt from a 2,722-line `main.rs` into a library with a thin CLI.

```
src/
  lib.rs                  crate root; the epistemic contract, pinned by tests
  connectome/
    neuron_names.rs       the canonical 300, generated from the source data
    classify.rs           EXPLICIT node typing; an unknown name is a hard error
    load.rs               safe loader; symmetrizes gap junctions, reports cleaning
  dynamics/
    params.rs             every parameter carries a Provenance tag
    transmitter.rs        transmitter identity + a NAMED, swappable sign policy
    rng.rs                SplitMix64 + Box–Muller normals
    mod.rs                Sim, allocation-free RK4, Euler–Maruyama noise
  metrics/
    lz.rs                 Lempel-Ziv complexity family
    pci.rs                perturbational complexity + noise-null calibration
    phi.rs                integrated information (whole-minus-sum), capped at 12
    lyapunov.rs           Benettin renormalized largest exponent
    distance.rs           FULL state distance (v ⊕ s), not voltage-only
    stats.rs              bootstrap CIs, permutation tests, effect sizes
  edf/
    mod.rs                bounds-checked EDF/EDF+ reader
    anchor.rs             multi-subject sleep anchor with paired statistics
  persist/
    hash.rs               SHA-256 (NIST vectors), replacing FNV-1a
    mod.rs                versioned, COMPLETE snapshots; refuses foreign restores
  experiments/
    stimulation.rs        amplitude calibration (was hard-coded)
    lesion.rs             clamped-node experiments, multi-seed
    transfer.rs           round-trip + sensitivity  [SIM only]
    manifest.rs           reproducibility manifest
  validation/
    mod.rs                the harness: Pass / Fail / Unvalidated
    recording.rs          gate vs real Ca²⁺ imaging
    perturbation.rs       gate vs published ablation / optogenetics
    behaviour.rs          gate vs held-out behaviour (tap-withdrawal)
```

**Zero third-party dependencies.** The numerics, SHA-256, EDF parsing and
statistics are all in-crate and unit-tested against published vectors, so the
whole substrate is auditable end to end.

## Supplying reference data

The validation gates are real and runnable; vigil simply ships **no fabricated
data** for them. Templates and sourcing notes are in `data/reference/`.

```sh
vigil validate \
  --recording      data/reference/recording.csv \
  --perturbations  data/reference/perturbations.csv \
  --sleep-dir      data
```

- **Recordings** — whole-brain Ca²⁺ imaging (Kato et al. 2015; Nichols et al.
  2017; Nguyen et al. 2016), as CSV: header of neuron names, rows of ΔF/F.
- **Perturbations** — published ablation/optogenetic outcomes, as
  `ablated|neurons, readout, effect(-1|0|1), citation`.
- **EEG** — ≥ 5 subject-nights of Sleep-EDF (Kemp et al. 2000).

## Build

```sh
cargo test --release     # 82 gates
cargo run  --release -- claims
```

Requires Rust 1.75+. CI builds on Linux and macOS, pins the connectome checksum,
and **fails if a forbidden conclusion reappears in the output**.

## Known limits

Single-compartment neurons; no receptor modelling, no neuromodulation, no
plasticity, no body/environment loop, and **unfitted synaptic polarity** — which
is why the model fails the behavioural gate. The connectome is not the nervous
system (cf. Bentley et al. 2016). Determinism is same-machine only.

These are listed in full in [`FINDINGS.md`](FINDINGS.md). None of them is patched
over.

## License

MIT OR Apache-2.0.
