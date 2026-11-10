# 5GC Authorization Testing Pipeline

Automated pipeline that turns a catalog of 5G Core (5GC) resource-ownership
authorization cases into executable, reproducible test scenarios against a
live 5G Core lab, and produces auditable evidence for each run. The primary
target is free5GC, but the lab itself is reached through a pluggable adapter
layer, so a second core implementation can be tested with the same pipeline.

This is a **research/test instrument**, not production software: it is built
for reproducibility and evidence collection in a controlled lab, not for
hardening, scaling, or defending a real deployment.

## Why this exists

Hand-writing one attack script per Service-Based Interface endpoint does not
scale and makes it easy for an attack's stated hypothesis to drift apart from
its actual HTTP implementation. This pipeline instead:

1. Parses a catalog of authorization cases (one case = one endpoint + one
   resource-ownership hypothesis) into structured data.
2. Enriches each case deterministically from 3GPP rules and OpenAPI specs,
   optionally with model assistance for the parts that cannot be derived
   mechanically (e.g. a plausible JSON payload).
3. Forces a **human review gate** before anything is treated as ground truth
   — enrichment output is never trusted blindly.
4. Executes the approved scenario generically against the lab (no per-case
   code) and classifies the result with a deterministic verdict oracle.
5. Compares the measured runtime result against what the specification
   itself says should happen, and writes an auditable report per run.

The design principle that runs through the codebase: no branch of the code is
keyed on a specific case identifier. Everything is dispatched on structural
properties of the scenario (resource type, HTTP method, target service) so
that adding a new case to the catalog requires no new code for a service
3GPP already publishes as OpenAPI.

## Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│  STAGE A — Spec Enrichment        (stage_a/stage_a.py)       │
│                                                                │
│  input catalog ──► enrich ──► review file (approved: false)  │
│                                        │                      │
│                              human review + approval          │
│                                        ▼                      │
│                              --finalize ──► scenarios/        │
└──────────────────────────────────┬────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE B — Scenario Execution     (stage_b/stage_b.py)        │
│                                                                │
│  for each scenario: resolve identifiers, build the request,  │
│  fire it as the attacker, collect before/after evidence,     │
│  classify the result, restore lab state                      │
└──────────────────────────────────┬────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│  STAGE C — Specification-vs-Runtime Analysis                  │
│                      (stage_c/stage_c.py, offline)            │
│                                                                │
│  compares Stage B's measured verdict against what the        │
│  specification itself says should happen for that case        │
└─────────────────────────────────────────────────────────────┘
```

Each stage is an independent CLI entry point and can be re-run separately.
Stage A never touches the live lab; Stage C never touches the live lab either
— it only reads what Stage B already wrote.

## Directory layout

```
stage_a/      spec enrichment: parsing, deterministic rules, review-file I/O
stage_b/      scenario execution against the live lab, including the
              per-core adapter layer (stage_b/adapters/)
stage_c/      offline comparison of the runtime result against the spec
shared/       code shared across stages (OpenAPI handling, schema
              validation, model client, reporting)
scripts/      standalone maintenance/utility scripts
configs/      lab manifest(s) and the resource-provisioning catalog
input/        source catalogs of authorization cases
```

A run's working data (review files, finalized scenarios, results) lives
under a `runs/<name>/` directory, not included here.

## Usage

```bash
python3 -m pip install -r requirements.txt   # see the parent project
```

1. **Enrich the catalog** (deterministic rules only, or with model
   assistance for payload/assertion drafting):

   ```bash
   python3 stage_a/stage_a.py --profiles input/authorization_profiles.json
   ```

   This writes one `review/<case_id>_review.yaml` per case, each with
   `approved: false`. A human reviews every flagged field and the drafted
   request, then flips `approved: true`.

2. **Finalize the approved cases** into immutable scenarios:

   ```bash
   python3 stage_a/stage_a.py --finalize
   ```

3. **Run the scenarios against a live lab**:

   ```bash
   python3 stage_b/stage_b.py
   ```

   Requires the target lab to already be up and reachable per the selected
   lab manifest (`configs/lab.yaml`). Each scenario's resolved request,
   verdict, and evidence are written under `results/<run_id>/`, alongside a
   refreshed `results/SUMMARY.md`.

4. **Compare the runtime result against the specification**:

   ```bash
   python3 stage_c/stage_c.py
   ```

   This produces `results/<run_id>/stage_c_analysis.{md,json}` per scenario
   and refreshes `SUMMARY.md` with the comparison outcome.

All three CLIs accept `--help` for their full option list, including
directory overrides to run an isolated catalog/batch without touching an
existing run.
