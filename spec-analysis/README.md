# 5G SBI Specification Analysis

This workspace builds deterministic 3GPP TS context packs for selected 5G SBI
endpoints, then prepares separate LLM prompts for expected resource binding and
existing protection analysis.

## Tracked Files

`scripts/build_endpoint_list.py`

Selects and enriches OpenAPI operations from exact seeds or generic resource
identifier/category filters.

`scripts/build_ts_context_packs.py`

Provides three local commands:

- `ensure-ts-corpus`: downloads and extracts only missing endpoint-associated TS files;
- `index-ts-sections`: indexes numbered sections from local extracted TS text;
- `build-operation-context-packs`: retrieves deterministic endpoint context packs.

`scripts/build_binding_protection_prompts.py`

Builds expected-binding and existing-protection prompt JSONL from the context
packs. It does not call a model.

`scripts/run_jsonl_prompts.py`

Runs prompt JSONL through an external command and records per-line failures.

`scripts/run_openai_json_agent.py`

OpenAI adapter for one prompt read from stdin, with JSON schema validation.

`scripts/build_authorization_profiles.py`

Deterministically joins endpoint/OpenAPI metadata with the two semantic LLM
outputs and writes the canonical `authorization_profiles.json` consumed by
`PartB_EndpointTest/5gc-security-tester/stage_a.py`.

`ground_truth/`

Manual context-selection ground truth for the validated seed endpoints.

`output/identifiers_categorization.json`

Resource-identifier categories used by generic endpoint selection and endpoint
metadata enrichment.


`5GC_APIs-Rel-17/bundled/`

Bundled Rel-17 OpenAPI specifications used to build endpoint metadata.

## Workflow

```bash
python3 -m pip install -r requirements.txt

python3 scripts/build_endpoint_list.py \
  --default-p1-seeds \
  --output output/seed_endpoint_list.json

python3 scripts/build_ts_context_packs.py ensure-ts-corpus
python3 scripts/build_ts_context_packs.py index-ts-sections
python3 scripts/build_ts_context_packs.py build-operation-context-packs

python3 scripts/build_binding_protection_prompts.py expected-binding
python3 scripts/build_binding_protection_prompts.py existing-protection
```

### Legacy Word Documents and Corpus Quality

TS 29.512 is source-locked to V17.11.0 (`29512-hb0.zip`) so its procedure
text matches the V17.11.0 OpenAPI bundled in this workspace. The official
Rel-17 archive contains a legacy binary `.doc`, not `.docx`. The pipeline
converts it with `antiword`; if that converter is unavailable or fails, it can
fall back to the official ETSI V17.11.0 PDF using `pdftotext -layout`.

Install the external converters on Debian/Ubuntu with:

```bash
sudo apt-get install antiword poppler-utils
```

`ensure-ts-corpus` auto-detects both commands. Non-standard installations can
be supplied explicitly:

```bash
python3 scripts/build_ts_context_packs.py ensure-ts-corpus \
  --antiword-command /path/to/antiword \
  --antiword-home /path/to/antiword-maps \
  --pdftotext-command /path/to/pdftotext
```

The old binary-as-Latin-1 fallback is intentionally not supported. Extraction
must pass a quality gate before the corpus is written or indexed. The gate
checks maximum and excessive line lengths, text-to-binary size ratio, `1
Scope`, and source-specific required sections. Provenance, source hash,
converter, version, and quality metrics are written beside the extracted text
as `TS29512.source.json` and summarized in `ts_manifest.json`.

Use `run_jsonl_prompts.py` with a model command to execute either prompt file.
The runner prints the selected range and output paths, then logs `RUN`, `OK`,
`ERROR`, or `SKIP` with elapsed time for every endpoint and a final summary.

Immutable endpoint metadata, context packs, and prompts stay in the shared
`seed_endpoints/` directory. Only model-dependent artifacts are grouped by
model:

```text
output/agent_pipeline/seed_endpoints/
├── 01_ts_section_index.jsonl
├── 02_operation_context_packs.jsonl
├── 03_expected_binding_prompts.jsonl
├── 04_existing_protection_prompts.jsonl
└── model_outputs/
    ├── gpt-5.5/
    │   ├── 03_expected_binding_outputs.jsonl
    │   ├── 03_expected_binding_outputs.jsonl.errors.jsonl
    │   ├── 04_existing_protection_outputs.jsonl
    │   ├── 04_existing_protection_outputs.jsonl.errors.jsonl
    │   └── 05_authorization_profiles.json
    └── other-model/
        └── ...
```

Example: run expected-binding analysis for one endpoint:

```bash
python3 scripts/run_jsonl_prompts.py \
  --input output/agent_pipeline/seed_endpoints/03_expected_binding_prompts.jsonl \
  --output-dir output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5 \
  --limit 1 \
  --model-command "python3 scripts/run_openai_json_agent.py --model gpt-5.5 --schema expected_binding"
```

Remove `--limit 1` to process the complete prompt file. For existing protection,
use the `04_existing_protection_prompts.jsonl` input and the
`existing_protection` schema.

Run both agents, then build the Part B input:

```bash
python3 scripts/run_jsonl_prompts.py \
  --input output/agent_pipeline/seed_endpoints/03_expected_binding_prompts.jsonl \
  --output-dir output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5 \
  --resume \
  --model-command "python3 scripts/run_openai_json_agent.py --model gpt-5.5 --schema expected_binding"

python3 scripts/run_jsonl_prompts.py \
  --input output/agent_pipeline/seed_endpoints/04_existing_protection_prompts.jsonl \
  --output-dir output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5 \
  --resume \
  --model-command "python3 scripts/run_openai_json_agent.py --model gpt-5.5 --schema existing_protection"

python3 scripts/build_authorization_profiles.py \
  --endpoints output/seed_endpoint_list.json \
  --context-packs output/agent_pipeline/seed_endpoints/02_operation_context_packs.jsonl \
  --expected-binding output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5/03_expected_binding_outputs.jsonl \
  --existing-protection output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5/04_existing_protection_outputs.jsonl \
  --output output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5/05_authorization_profiles.json
```

After validating a model-specific catalog, it can be promoted explicitly to
the stable integration path:

```bash
cp output/agent_pipeline/seed_endpoints/model_outputs/gpt-5.5/05_authorization_profiles.json \
  output/authorization_profiles.json
```

The assembler is strict by default: every selected endpoint must have exactly
one output from each agent, duplicate/unknown endpoint IDs are rejected, enum
values are validated, every cited `context_id` must exist in that endpoint's
context pack, and the LLM's resource identifiers must include a path identifier
from the deterministic endpoint metadata. `--allow-incomplete`
can be used for exploratory partial runs; it emits only endpoints for which
both outputs exist.

The responsibility boundary is intentional:

- deterministic endpoint list/OpenAPI metadata supplies service, method, path,
  `operationId`, and OAuth scopes;
- the expected-binding agent supplies requester NF types, resource identifiers,
  relation type/statement, and binding strength;
- the existing-protection agent supplies resource-binding coverage, mechanism,
  applicability conditions, and associated failure codes/causes;
- the assembler conservatively uses the lower confidence of the two agents and
  merges their evidence references.

Agent JSONL files remain the auditable, detailed analysis artifacts. The
assembled catalog is a compact integration format, not a replacement for them.
Outputs produced with the older agent schema (`requester`,
`resource_instance_identifiers`, or `resource_instance_authorization`) must be
regenerated before using this assembler.

The OpenAI adapter reads `OPENAI_API_KEY` from an exported environment variable
or from `.env` in the current directory or this workspace. Exported variables
take precedence. A different file can be selected with `--env-file PATH`.
Never commit API keys.

## Known Limitations

- TS service-operation layouts are not fully consistent. Many specifications
  place relevant procedures in clause `5.x`, while TS 29.512 uses `4.2.x` for
  its main service operations.
- Legacy `.doc` and PDF conversion depends on external `antiword` and
  `pdftotext` executables. The corpus build fails explicitly when neither
  conversion path is available.
- Text conversion preserves paragraph content but can still flatten table
  structure even when it passes the quality gate.
- Text embedded in figures is not extracted. Figures often contain strong
  method-and-path signals, but introducing OCR without validation could corrupt
  paths, braces, underscores, and operation names.
- Deterministic context selection has been manually checked on the current seed
  set but still requires broader validation before being used as an oracle.

## Future Work

- Compare antiword output with a LibreOffice conversion and the official ETSI
  PDF to quantify paragraph and table coverage.
- Evaluate an optional OCR fallback for figures, with provenance and confidence
  metadata and manual accuracy measurements.
- Add a corpus-quality report distinguishing legacy `.doc`, `.docx`, and
  potentially OCR-derived text.
- Manually validate the new PCF context packs and expand the ground-truth set
  before using them as an analysis oracle.

### TODO: Hierarchical Procedure-Context Expansion

An HTTP endpoint can be used by procedures located in different branches of a
TS service-operations hierarchy. Selecting only the best-scoring procedure leaf
can therefore miss valid, condition-specific behavior. Literal endpoint paths
are also frequently present only in figures, while the surrounding text refers
to a resource or service operation by name.

Implement a high-recall hierarchical strategy:

1. Always include the endpoint's resource parent with its method/operation
   children as the authoritative API contract context.
2. When the procedure-to-endpoint mapping is uncertain or spans multiple
   branches, include the smallest common service-operations ancestor and its
   descendants, provided it fits a configurable prompt token budget. Evaluate
   an initial budget in the 20k-25k token range rather than hard-coding it.
3. Ask the agents to identify every applicable leaf procedure and emit separate
   conditional binding/protection rules with the exact source section and
   applicability condition. Text from the parent must not be treated as if
   every descendant applied to the endpoint.
4. Deterministically verify that emitted section IDs exist in the supplied
   context, cited text is an exact excerpt, and rejected ground-truth sections
   are reported during validation.
5. If the common ancestor exceeds the token budget, fall back to a coarse-to-
   fine retrieval stage over section titles, resource/operation names, method,
   schema fields, captions, and validated figure/OCR metadata.

For example, `Nudm_UECM PATCH
/{ueId}/registrations/amf-3gpp-access` is used by procedures in two different
branches:

```text
5.3.2 Service Operations
├── 5.3.2.4 Deregistration
│   └── 5.3.2.4.2 AMF deregistration for 3GPP access
└── 5.3.2.6 Update
    └── 5.3.2.6.2 Update a parameter in the AMF registration for 3GPP access
```

Selecting only clause 5.3.2.6 would lose the valid deregistration behavior in
clause 5.3.2.4.2. To favor completeness without depending on fragile literal
path matching, supply both:

```text
6.2.3.2  Resource: Amf3GppAccessRegistration, with descendants
5.3.2    Service Operations, with descendants
```

For the current GPT-5.5 seed prompts, this would increase the estimated prompt
size from approximately 5,800 tokens to approximately 19,000 tokens. These are
planning estimates derived from the extracted-text size rather than exact
model-tokenizer counts. The larger input is still practical for this model, but
increases cost and irrelevant context, so the budget and output quality must be
measured before applying the strategy to the full endpoint catalog.

The agents should turn the broad context into separate conditional rules rather
than one flattened endpoint-wide mechanism, for example:

```json
{
  "binding_rules": [
    {
      "source_section": "5.3.2.4.2",
      "applies_when": ["purgeFlag is set"],
      "mechanism": "received GUAMI matches stored GUAMI",
      "failure_codes": [403]
    },
    {
      "source_section": "5.3.2.6.2",
      "applies_when": ["a registration parameter is updated"],
      "mechanism": "requesting AMF is the currently registered AMF",
      "failure_codes": [422]
    }
  ]
}
```

The initial general rule to evaluate is: if the complete service-procedure
parent fits within a configurable 20k-25k token budget, include it and let the
agents identify the applicable leaves. Update the seed context ground truth to
represent both conditional procedures before using it to validate this
strategy.
