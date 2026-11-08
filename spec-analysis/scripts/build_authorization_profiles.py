import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PIPELINE_DIR = ROOT / 'output' / 'agent_pipeline' / 'seed_endpoints'
DEFAULT_ENDPOINTS = ROOT / 'output' / 'seed_endpoint_list.json'
DEFAULT_CONTEXT_PACKS = DEFAULT_PIPELINE_DIR / '02_operation_context_packs.jsonl'
DEFAULT_EXPECTED_BINDING = DEFAULT_PIPELINE_DIR / '03_expected_binding_outputs.jsonl'
DEFAULT_EXISTING_PROTECTION = DEFAULT_PIPELINE_DIR / '04_existing_protection_outputs.jsonl'
DEFAULT_OUTPUT = ROOT / 'output' / 'authorization_profiles.json'
CONFIDENCE_ORDER = {'low': 0, 'medium': 1, 'high': 2}
STRENGTH_VALUES = {'explicit', 'implicit', 'ambiguous', 'not_identified'}
COVERAGE_VALUES = {'explicit_binding_check', 'condition_scoped', 'procedural_eligibility_only', 'operation_level_only', 'not_identified', 'ambiguous'}

def read_json(path: Path) -> Any:
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open(encoding='utf-8') as handle:
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
            rows.append(row)
    return rows

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write('\n')

def require_fields(data: Dict[str, Any], required: Dict[str, type], where: str) -> None:
    for key, expected_type in required.items():
        if key not in data:
            raise ValueError(f"{where}: missing required field '{key}'")
        if not isinstance(data[key], expected_type):
            raise ValueError(f'{where}.{key}: expected {expected_type.__name__}')

def require_string_list(value: Any, where: str, allow_empty: bool=True) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f'{where}: expected list')
    if not allow_empty and (not value):
        raise ValueError(f'{where}: at least one value is required')
    if not all((isinstance(item, str) and item.strip() for item in value)):
        raise ValueError(f'{where}: values must be non-empty strings')
    return value

def index_outputs(rows: Iterable[Dict[str, Any]], source: Path) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for line_no, row in enumerate(rows, start=1):
        endpoint_id = row.get('endpoint_id')
        if not isinstance(endpoint_id, str) or not endpoint_id:
            raise ValueError(f'{source}:{line_no}: endpoint_id is required')
        if endpoint_id in indexed:
            raise ValueError(f"{source}:{line_no}: duplicate endpoint_id '{endpoint_id}'")
        indexed[endpoint_id] = row
    return indexed

def index_context_ids(rows: Iterable[Dict[str, Any]], source: Path) -> Dict[str, set[str]]:
    indexed: Dict[str, set[str]] = {}
    for line_no, row in enumerate(rows, start=1):
        endpoint_id = row.get('endpoint_id')
        context_items = row.get('context_items')
        if not isinstance(endpoint_id, str) or not endpoint_id:
            raise ValueError(f'{source}:{line_no}: endpoint_id is required')
        if endpoint_id in indexed:
            raise ValueError(f"{source}:{line_no}: duplicate endpoint_id '{endpoint_id}'")
        if not isinstance(context_items, list):
            raise ValueError(f'{source}:{line_no}: context_items must be a list')
        context_ids = set()
        for item_index, item in enumerate(context_items, start=1):
            context_id = item.get('context_id') if isinstance(item, dict) else None
            if not isinstance(context_id, str) or not context_id:
                raise ValueError(f'{source}:{line_no}: context_items[{item_index}].context_id is required')
            context_ids.add(context_id)
        indexed[endpoint_id] = context_ids
    return indexed

def validate_confidence(value: Any, where: str) -> str:
    if value not in CONFIDENCE_ORDER:
        raise ValueError(f'{where}: expected one of {sorted(CONFIDENCE_ORDER)}')
    return value

def combine_confidence(expected: str, protection: str) -> str:
    return min((expected, protection), key=lambda value: CONFIDENCE_ORDER[value])

def build_expected_binding(output: Dict[str, Any], endpoint: Dict[str, Any]) -> Dict[str, Any]:
    endpoint_id = endpoint['id']
    require_fields(output, {'expected_binding': dict}, f'expected-binding[{endpoint_id}]')
    binding = output['expected_binding']
    require_fields(binding, {'requester_nf_types': list, 'resource_identifiers': list, 'relation_type': str, 'relation_statement': str, 'strength': str}, f'expected-binding[{endpoint_id}].expected_binding')
    requester_nf_types = require_string_list(binding['requester_nf_types'], f'expected-binding[{endpoint_id}].expected_binding.requester_nf_types', allow_empty=False)
    if any((nf_type != nf_type.upper() or not re.fullmatch('[A-Z][A-Z0-9]*', nf_type) for nf_type in requester_nf_types)):
        raise ValueError(f'expected-binding[{endpoint_id}].expected_binding.requester_nf_types: use canonical uppercase 3GPP NF type codes')
    resource_identifiers = require_string_list(binding['resource_identifiers'], f'expected-binding[{endpoint_id}].expected_binding.resource_identifiers', allow_empty=False)
    endpoint_resource_ids = set(endpoint.get('resource_ids') or [])
    if endpoint_resource_ids and (not endpoint_resource_ids.intersection(resource_identifiers)):
        raise ValueError(f'expected-binding[{endpoint_id}].expected_binding.resource_identifiers {resource_identifiers} do not include an endpoint path identifier {sorted(endpoint_resource_ids)}')
    relation_type = binding['relation_type']
    if not re.fullmatch('[a-z][a-z0-9_]*', relation_type):
        raise ValueError(f'expected-binding[{endpoint_id}].expected_binding.relation_type must be a lowercase snake_case label')
    if not binding['relation_statement'].strip():
        raise ValueError(f'expected-binding[{endpoint_id}].expected_binding.relation_statement cannot be empty')
    if binding['strength'] not in STRENGTH_VALUES:
        raise ValueError(f'expected-binding[{endpoint_id}].expected_binding.strength must be one of {sorted(STRENGTH_VALUES)}')
    return {'requester_nf_types': requester_nf_types, 'resource_identifiers': resource_identifiers, 'relation_type': relation_type, 'relation_statement': binding['relation_statement'], 'strength': binding['strength']}

def build_resource_binding(output: Dict[str, Any], endpoint_id: str) -> Dict[str, Any]:
    require_fields(output, {'existing_protection': dict}, f'existing-protection[{endpoint_id}]')
    protection = output['existing_protection']
    require_fields(protection, {'resource_binding': dict}, f'existing-protection[{endpoint_id}].existing_protection')
    binding = protection['resource_binding']
    require_fields(binding, {'coverage': str, 'mechanism': str, 'applies_when': list, 'failure_codes': list, 'failure_causes': list}, f'existing-protection[{endpoint_id}].existing_protection.resource_binding')
    if binding['coverage'] not in COVERAGE_VALUES:
        raise ValueError(f'existing-protection[{endpoint_id}].existing_protection.resource_binding.coverage must be one of {sorted(COVERAGE_VALUES)}')
    applies_when = require_string_list(binding['applies_when'], f'existing-protection[{endpoint_id}].existing_protection.resource_binding.applies_when')
    failure_causes = require_string_list(binding['failure_causes'], f'existing-protection[{endpoint_id}].existing_protection.resource_binding.failure_causes')
    failure_codes = binding['failure_codes']
    if not all((isinstance(code, int) and (not isinstance(code, bool)) for code in failure_codes)):
        raise ValueError(f'existing-protection[{endpoint_id}].existing_protection.resource_binding.failure_codes must contain integer HTTP status codes')
    return {'coverage': binding['coverage'], 'mechanism': binding['mechanism'], 'applies_when': applies_when, 'failure_codes': failure_codes, 'failure_causes': failure_causes}

def build_evidence_refs(*outputs: Dict[str, Any], valid_context_ids: set[str] | None=None) -> List[Dict[str, str]]:
    refs: List[Dict[str, str]] = []
    seen = set()
    for output in outputs:
        evidence_used = output.get('evidence_used', [])
        if not isinstance(evidence_used, list):
            raise ValueError(f'{output.get('endpoint_id', '<unknown>')}: evidence_used must be a list')
        for index, item in enumerate(evidence_used, start=1):
            if not isinstance(item, dict):
                raise ValueError(f'{output.get('endpoint_id', '<unknown>')}: evidence_used[{index}] must be an object')
            context_id = item.get('context_id')
            role = item.get('evidence_role')
            if not isinstance(context_id, str) or not context_id:
                raise ValueError(f'{output.get('endpoint_id', '<unknown>')}: evidence_used[{index}].context_id is required')
            if not isinstance(role, str) or not role:
                raise ValueError(f'{output.get('endpoint_id', '<unknown>')}: evidence_used[{index}].evidence_role is required')
            if valid_context_ids is not None and context_id not in valid_context_ids:
                raise ValueError(f"{output.get('endpoint_id', '<unknown>')}: evidence_used[{index}].context_id '{context_id}' is not present in that endpoint's context pack")
            key = (context_id, role)
            if key not in seen:
                refs.append({'context_id': context_id, 'role': role})
                seen.add(key)
    return refs

def build_profile(endpoint: Dict[str, Any], expected_output: Dict[str, Any], protection_output: Dict[str, Any], valid_context_ids: set[str] | None=None) -> Dict[str, Any]:
    endpoint_id = endpoint.get('id')
    require_fields(endpoint, {'id': str, 'service': str, 'method': str, 'endpoint': str, 'operationId': str, 'scopes': list}, f'endpoint[{endpoint_id or '<unknown>'}]')
    if expected_output.get('endpoint_id') != endpoint_id:
        raise ValueError(f"expected-binding output does not match endpoint '{endpoint_id}'")
    if protection_output.get('endpoint_id') != endpoint_id:
        raise ValueError(f"existing-protection output does not match endpoint '{endpoint_id}'")
    scopes = require_string_list(endpoint['scopes'], f'endpoint[{endpoint_id}].scopes')
    expected_confidence = validate_confidence(expected_output.get('confidence'), f'expected-binding[{endpoint_id}].confidence')
    protection_confidence = validate_confidence(protection_output.get('confidence'), f'existing-protection[{endpoint_id}].confidence')
    return {'schema_version': '1.0', 'endpoint_id': endpoint_id, 'target': {'service': endpoint['service'], 'method': endpoint['method'].upper(), 'path': endpoint['endpoint'], 'operation_id': endpoint['operationId'] or None}, 'expected_binding': build_expected_binding(expected_output, endpoint), 'existing_protection': {'operation_level': {'oauth_scopes': scopes}, 'resource_binding': build_resource_binding(protection_output, endpoint_id)}, 'confidence': combine_confidence(expected_confidence, protection_confidence), 'evidence_refs': build_evidence_refs(expected_output, protection_output, valid_context_ids=valid_context_ids)}

def build_catalog(endpoints: List[Dict[str, Any]], expected_outputs: Dict[str, Dict[str, Any]], protection_outputs: Dict[str, Dict[str, Any]], allow_incomplete: bool=False, context_ids_by_endpoint: Dict[str, set[str]] | None=None) -> List[Dict[str, Any]]:
    endpoint_ids = []
    seen_endpoint_ids = set()
    for index, endpoint in enumerate(endpoints, start=1):
        endpoint_id = endpoint.get('id') if isinstance(endpoint, dict) else None
        if not isinstance(endpoint_id, str) or not endpoint_id:
            raise ValueError(f'endpoints[{index}]: id is required')
        if endpoint_id in seen_endpoint_ids:
            raise ValueError(f"endpoints[{index}]: duplicate id '{endpoint_id}'")
        endpoint_ids.append(endpoint_id)
        seen_endpoint_ids.add(endpoint_id)
    unknown_expected = sorted(set(expected_outputs) - seen_endpoint_ids)
    unknown_protection = sorted(set(protection_outputs) - seen_endpoint_ids)
    if unknown_expected:
        raise ValueError(f'expected-binding outputs contain unknown endpoints: {unknown_expected}')
    if unknown_protection:
        raise ValueError(f'existing-protection outputs contain unknown endpoints: {unknown_protection}')
    if context_ids_by_endpoint is not None:
        missing_context_packs = sorted(seen_endpoint_ids - set(context_ids_by_endpoint))
        unknown_context_packs = sorted(set(context_ids_by_endpoint) - seen_endpoint_ids)
        if missing_context_packs:
            raise ValueError(f'missing context packs: {missing_context_packs}')
        if unknown_context_packs:
            raise ValueError(f'context packs contain unknown endpoints: {unknown_context_packs}')
    missing_expected = sorted(seen_endpoint_ids - set(expected_outputs))
    missing_protection = sorted(seen_endpoint_ids - set(protection_outputs))
    if not allow_incomplete and (missing_expected or missing_protection):
        details = []
        if missing_expected:
            details.append(f'missing expected-binding outputs: {missing_expected}')
        if missing_protection:
            details.append(f'missing existing-protection outputs: {missing_protection}')
        raise ValueError('; '.join(details))
    profiles = []
    for endpoint in endpoints:
        endpoint_id = endpoint['id']
        if endpoint_id not in expected_outputs or endpoint_id not in protection_outputs:
            continue
        profiles.append(build_profile(endpoint, expected_outputs[endpoint_id], protection_outputs[endpoint_id], valid_context_ids=context_ids_by_endpoint[endpoint_id] if context_ids_by_endpoint is not None else None))
    return profiles

def main() -> int:
    parser = argparse.ArgumentParser(description='Build canonical Part B authorization profiles from endpoint metadata and LLM outputs.')
    parser.add_argument('--endpoints', default=str(DEFAULT_ENDPOINTS))
    parser.add_argument('--context-packs', default=str(DEFAULT_CONTEXT_PACKS))
    parser.add_argument('--expected-binding', default=str(DEFAULT_EXPECTED_BINDING))
    parser.add_argument('--existing-protection', default=str(DEFAULT_EXISTING_PROTECTION))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    parser.add_argument('--allow-incomplete', action='store_true', help='Emit only endpoints that have both agent outputs instead of failing on missing outputs.')
    args = parser.parse_args()
    endpoints = read_json(Path(args.endpoints))
    if not isinstance(endpoints, list):
        raise ValueError(f'{args.endpoints}: expected a JSON array')
    expected_outputs = index_outputs(read_jsonl(Path(args.expected_binding)), Path(args.expected_binding))
    protection_outputs = index_outputs(read_jsonl(Path(args.existing_protection)), Path(args.existing_protection))
    context_ids_by_endpoint = index_context_ids(read_jsonl(Path(args.context_packs)), Path(args.context_packs))
    profiles = build_catalog(endpoints, expected_outputs, protection_outputs, allow_incomplete=args.allow_incomplete, context_ids_by_endpoint=context_ids_by_endpoint)
    write_json(Path(args.output), profiles)
    print(f'Wrote {len(profiles)} authorization profiles to {args.output}.')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
