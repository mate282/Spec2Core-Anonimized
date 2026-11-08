import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = ROOT / 'output' / 'agent_pipeline' / 'seed_endpoints'
DEFAULT_CONTEXT_PACKS = DEFAULT_OUT_DIR / '02_operation_context_packs.jsonl'
DEFAULT_EXPECTED_BINDING_PROMPTS = DEFAULT_OUT_DIR / '03_expected_binding_prompts.jsonl'
DEFAULT_EXISTING_PROTECTION_PROMPTS = DEFAULT_OUT_DIR / '04_existing_protection_prompts.jsonl'

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open('r') as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}:{line_no}: invalid JSONL row: {exc}') from exc
            if not isinstance(row, dict):
                raise ValueError(f'{path}:{line_no}: expected a JSON object')
            if not row.get('endpoint_id'):
                raise ValueError(f'{path}:{line_no}: endpoint_id is required')
            if not isinstance(row.get('context_items'), list):
                raise ValueError(f'{path}:{line_no}: context_items must be a list')
            rows.append(row)
    return rows

def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        for row in rows:
            handle.write(json.dumps(row) + '\n')

def expected_binding_prompt(pack: Dict[str, Any]) -> Dict[str, Any]:
    system = 'You are the Expected Binding Agent for 5G SBI resource-instance authorization analysis. Your task is to infer the intended requester-to-resource instance binding, resource ownership/subject relationship, and authorization relationship required for secure operation of one SBI endpoint using only the supplied OpenAPI metadata and TS context items. Do not analyze whether the specification already enforces the binding; that belongs to the protection agent. Return JSON only.'
    user = {'task': 'Infer the expected resource-instance authorization binding for this endpoint. Focus on which resource instance is being addressed, which identifiers bind the request to that instance, who owns/controls or is the subject of that resource instance, and what authorization relationship an authorized requester should have to that instance for secure operation.', 'strict_rules': ['Use only openapi_metadata and context_items from the supplied context_pack.', 'Use context_id values exactly as provided when citing evidence.', 'Do not claim existing enforcement or protection status in this stage.', 'Do not treat OAuth scopes alone as resource-instance authorization.', 'Separate the expected ownership/subject relationship from any existing protection mechanism.', 'Use canonical uppercase 3GPP NF type codes in requester_nf_types (for example AMF, SMF, PCF).', 'Use exact identifier names from openapi_metadata/context_items in resource_identifiers; do not paraphrase them.', 'Use a lowercase snake_case label in relation_type.', 'If the binding is implicit, say so and explain the inference path.', 'Return strict JSON matching output_schema and no prose outside JSON.'], 'output_schema': {'endpoint_id': pack['endpoint_id'], 'expected_binding': {'resource_instance': 'specific resource instance protected by the endpoint', 'requester_nf_types': ['canonical 3GPP NF type codes, e.g. AMF, SMF, PCF'], 'resource_identifiers': ['exact path/body/query identifier names that select the resource instance'], 'relation_type': 'short machine-readable relation label, e.g. serving_nf or registered_nf', 'relation_statement': 'one sentence defining the requester-to-resource authorization invariant', 'strength': 'explicit|implicit|ambiguous|not_identified', 'binding_rationale': 'short explanation of why this binding is expected'}, 'evidence_used': [{'context_id': 'must match one context item', 'evidence_role': 'resource_definition|method_behavior|procedure_context|operation_metadata', 'quoted_text': 'short exact excerpt from the context item', 'rationale': 'why this evidence supports the expected binding'}], 'assumptions': ['assumptions needed to infer the binding'], 'gaps': ['missing context or ambiguity relevant to expected binding'], 'confidence': 'high|medium|low'}, 'context_pack': pack}
    return {'id': pack['endpoint_id'], 'endpoint_id': pack['endpoint_id'], 'agent': 'expected_binding', 'system': system, 'user': json.dumps(user, indent=2)}

def existing_protection_prompt(pack: Dict[str, Any]) -> Dict[str, Any]:
    system = 'You are the Existing Protection Agent for 5G SBI resource-instance authorization analysis. Your task is to extract authorization, ownership, and protection mechanisms that are visible in the supplied OpenAPI metadata and TS context items. Separate operation-level access control from resource-instance authorization coverage. Do not describe attack scenarios; describe only what protection the specification text does or does not specify. Return JSON only.'
    user = {'task': 'Identify existing or specified authorization, ownership, and protection mechanisms for this endpoint from the retrieved specification text. Focus on OAuth/scope requirements, allowed error/status behavior, procedural preconditions, and any checks or conditions that constrain access to the addressed resource instance. Assess resource-instance authorization coverage without framing it as an attack.', 'strict_rules': ['Use only openapi_metadata and context_items from the supplied context_pack.', 'Use context_id values exactly as provided when citing evidence.', 'Separate operation-level OAuth/scope protection from resource-instance authorization coverage.', 'Do not treat OAuth scopes alone as resource-instance authorization.', 'Do not describe attacker models or test ideas in this stage.', 'Do not invent implementation checks not present in the context.', 'Do not downgrade an explicit resource-instance check because unrelated general checks are absent; put absent or unclear checks in limitations.', 'If a check applies only under specific conditions, record that in coverage_notes.', 'Use condition_scoped (not condition_scoped_binding_check) for condition-limited coverage.', 'Return failure_codes as JSON integers (for example 403), never strings.', 'Return strict JSON matching output_schema and no prose outside JSON.'], 'output_schema': {'endpoint_id': pack['endpoint_id'], 'existing_protection': {'resource_binding': {'coverage': 'explicit_binding_check|condition_scoped|procedural_eligibility_only|operation_level_only|not_identified|ambiguous', 'mechanism': 'short description of the resource-instance authorization mechanism, or none identified', 'applies_when': ['conditions under which the mechanism applies'], 'failure_codes': [403], 'failure_causes': ['3GPP ProblemDetails causes specifically associated with this mechanism'], 'protected_relation': 'resource-instance relation protected by the mechanism, or none identified', 'coverage_notes': 'short note on scope, conditions, or ambiguity of the coverage'}, 'operation_level_controls': ['service-level OAuth, scope, or method-level controls described in the supplied context'], 'procedural_or_contextual_controls': ['implicit/procedural constraints from TS procedure text'], 'error_or_status_controls': ['403/401/ProblemDetails/status-code behavior relevant to authorization'], 'limitations': ['missing, ambiguous, or not identified protections relevant to resource-instance authorization'], 'protection_status': 'explicit|partial|procedural_only|operation_level_only|not_identified|ambiguous'}, 'evidence_used': [{'context_id': 'must match one context item', 'evidence_role': 'operation_level_control|resource_instance_binding_check|procedural_control|error_response|limitation', 'quoted_text': 'short exact excerpt from the context item', 'rationale': 'why this evidence supports the protection analysis'}], 'gaps': ['missing context or ambiguity relevant to existing protection'], 'confidence': 'high|medium|low'}, 'context_pack': pack}
    return {'id': pack['endpoint_id'], 'endpoint_id': pack['endpoint_id'], 'agent': 'existing_protection', 'system': system, 'user': json.dumps(user, indent=2)}

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Build binding and protection prompts from TS context packs.')
    subparsers = parser.add_subparsers(dest='command', required=True)
    binding = subparsers.add_parser('expected-binding', help='Build expected binding prompts.')
    binding.add_argument('--context-packs', default=str(DEFAULT_CONTEXT_PACKS))
    binding.add_argument('--output', default=str(DEFAULT_EXPECTED_BINDING_PROMPTS))
    protection = subparsers.add_parser('existing-protection', help='Build existing protection prompts.')
    protection.add_argument('--context-packs', default=str(DEFAULT_CONTEXT_PACKS))
    protection.add_argument('--output', default=str(DEFAULT_EXISTING_PROTECTION_PROMPTS))
    return parser

def main() -> int:
    args = build_parser().parse_args()
    packs = read_jsonl(Path(args.context_packs))
    if args.command == 'expected-binding':
        prompts = [expected_binding_prompt(pack) for pack in packs]
    else:
        prompts = [existing_protection_prompt(pack) for pack in packs]
    write_jsonl(Path(args.output), prompts)
    print(f'Wrote {len(prompts)} {args.command} prompts to {args.output}.')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
