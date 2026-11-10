# 5G SBI Specification Analysis

This workspace builds deterministic 3GPP TS context packs for selected 5G SBI
endpoints, then prepares separate LLM prompts for expected resource binding and
existing protection analysis. The output feeds the authorization-testing
pipeline as a catalog of annotated endpoints.

## Tracked Files

`scripts/build_endpoint_list.py`

Selects and enriches OpenAPI operations from exact seeds or generic resource
identifier/category filters.

`scripts/build_ts_context_packs.py`

Retrieves the relevant 3GPP TS text and builds deterministic per-endpoint
context packs from it.

`scripts/build_binding_protection_prompts.py`

Builds expected-binding and existing-protection prompt files from the context
packs. It does not call a model.

`scripts/run_jsonl_prompts.py`

Runs a prompt file through an external model command and records per-line
failures.

`scripts/run_openai_json_agent.py`

Model adapter for one prompt, with JSON schema validation of its output.

`scripts/build_authorization_profiles.py`

Deterministically joins endpoint/OpenAPI metadata with the two semantic model
outputs into the canonical `authorization_profiles.json` catalog, consumed by
the authorization-testing pipeline.

`output/identifiers_categorization.json`

Resource-identifier categories used by generic endpoint selection and endpoint
metadata enrichment.

`5GC_APIs-Rel-17/bundled/`

Bundled Rel-17 OpenAPI specifications used to build endpoint metadata.

## Dependencies

```bash
python3 -m pip install -r requirements.txt
```

Model-reading scripts expect an API key via an exported environment variable
or a local `.env` file. Never commit API keys.

## Usage

The pipeline runs in stages; each step reads the previous step's output.

1. **Select the endpoints to analyze.**

   ```bash
   python3 scripts/build_endpoint_list.py --output output/seed_endpoint_list.json
   ```

2. **Build the 3GPP TS context packs** for those endpoints (fetches/indexes the
   relevant spec text, then assembles one context pack per endpoint).

   ```bash
   python3 scripts/build_ts_context_packs.py ensure-ts-corpus
   python3 scripts/build_ts_context_packs.py index-ts-sections
   python3 scripts/build_ts_context_packs.py build-operation-context-packs
   ```

3. **Build the two prompt files** (expected binding, existing protection) from
   the context packs — no model call happens here.

   ```bash
   python3 scripts/build_binding_protection_prompts.py expected-binding
   python3 scripts/build_binding_protection_prompts.py existing-protection
   ```

4. **Run each prompt file through a model**, once per analysis type. The
   model command is pluggable; `run_openai_json_agent.py` is one adapter.

   ```bash
   python3 scripts/run_jsonl_prompts.py \
     --input <expected-binding-prompts.jsonl> \
     --output-dir <model-output-dir> \
     --model-command "python3 scripts/run_openai_json_agent.py --schema expected_binding"

   python3 scripts/run_jsonl_prompts.py \
     --input <existing-protection-prompts.jsonl> \
     --output-dir <model-output-dir> \
     --model-command "python3 scripts/run_openai_json_agent.py --schema existing_protection"
   ```

5. **Assemble the final catalog**, joining deterministic endpoint metadata
   with both model outputs.

   ```bash
   python3 scripts/build_authorization_profiles.py \
     --endpoints output/seed_endpoint_list.json \
     --context-packs <operation-context-packs.jsonl> \
     --expected-binding <expected-binding-outputs.jsonl> \
     --existing-protection <existing-protection-outputs.jsonl> \
     --output output/authorization_profiles.json
   ```

The resulting `authorization_profiles.json` is the catalog consumed by the
authorization-testing pipeline. Each script also accepts `--help` for its
full option list.

## Known Limitations

- 3GPP TS documents are not laid out consistently across services; section
  numbering for the relevant procedures varies by specification.
- Legacy binary document formats need an external conversion step and are not
  always available in a clean, directly parseable form.
- Deterministic context selection has been manually checked on a seed set of
  endpoints but has not been validated as an oracle across the full catalog.
