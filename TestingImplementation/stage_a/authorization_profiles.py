import hashlib
import json
import re
import string
from pathlib import Path
import rules

def parse_authorization_profiles(path: Path) -> list[dict]:
    text = path.read_text(encoding='utf-8')
    data, _ = json.JSONDecoder().raw_decode(text)
    profiles = data if isinstance(data, list) else [data]
    partials: list[dict] = []
    for i, profile in enumerate(profiles):
        partials.extend(_parse_profile(i + 1, profile))
    return partials

def _parse_profile(index: int, profile: dict) -> list[dict]:
    target = profile.get('target', {}) or {}
    service = target.get('service', '')
    method = (target.get('method') or '').upper()
    path = target.get('path', '')
    endpoint_id = profile.get('endpoint_id') or f'{service} {method} {path}'
    batch_id = profile.get('batch_id')
    cases = profile.get('authorization_cases')
    if cases:
        operation_level = profile.get('operation_level', {}) or {}
        return [_parse_case(index, service, method, path, endpoint_id, target, case, case_index, len(cases), operation_level, batch_id, _case_fingerprint(profile, case)) for case_index, case in enumerate(cases)]
    return [_parse_legacy_profile(index, profile, target, service, method, path, endpoint_id)]

def _case_fingerprint(profile: dict, case: dict | None=None) -> str:
    material = {'schema_version': profile.get('schema_version'), 'endpoint_id': profile.get('endpoint_id'), 'target': profile.get('target'), 'operation_level': profile.get('operation_level'), 'authorization_case': case, 'expected_binding': profile.get('expected_binding') if case is None else None, 'existing_protection': profile.get('existing_protection') if case is None else None, 'batch_id': profile.get('batch_id')}
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()

def _parse_case(index: int, service: str, method: str, path: str, endpoint_id: str, target: dict, case: dict, case_index: int, case_count: int, operation_level: dict, batch_id: str | None, input_fingerprint: str) -> dict:
    expected_binding = case.get('expected_binding', {}) or {}
    case_protection = case.get('existing_protection', {}) or {}
    existing_protection = {'operation_level': operation_level, 'resource_binding': {'coverage': case_protection.get('coverage', ''), 'mechanism': case_protection.get('mechanism', ''), 'applies_when': case.get('applies_when') or [], 'failure_codes': case_protection.get('failure_codes', []), 'failure_causes': case_protection.get('failure_causes', []), 'protected_relation': case_protection.get('protected_relation', ''), 'coverage_notes': case_protection.get('coverage_notes', '')}}
    identifiers = expected_binding.get('resource_identifiers') or []
    resource_type, resource_why = rules.get_resource_type_from_identifiers(identifiers, path)
    canon_path = _canonicalize_path(path, resource_type)
    requester_types = expected_binding.get('requester_nf_types') or []
    nf_consumer = requester_types[0] if requester_types else ''
    case_id = case.get('case_id') or f'case_{case_index + 1}'
    base_attack_id = _attack_id(index, service, target.get('operation_id'), method, canon_path)
    attack_id = f'{base_attack_id}_{_case_letter(case_index)}'
    return {'section_number': index, 'attack_id': attack_id, 'title': f'{endpoint_id} — {case_id}', 'service': service, 'endpoint_raw': f'{method}{canon_path}', 'resource': resource_type, 'operation': 'read' if method == 'GET' else 'write', 'nf_consumer': nf_consumer, 'expected_binding': expected_binding, 'existing_protection': existing_protection, 'test_idea': _default_test_idea(service, method, canon_path, expected_binding), '_source': 'authorization_profiles.json', '_schema_version': '1.2', '_endpoint_id': endpoint_id, '_confidence': case.get('confidence'), '_evidence_refs': case.get('evidence_refs', []), '_operation_id_hint': target.get('operation_id'), '_requester_nf_types_all': requester_types, '_resource_type_reason': resource_why, '_case_id': case_id, '_case_index': case_index, '_case_count': case_count, '_batch_id': batch_id, '_input_fingerprint': input_fingerprint, '_execution_hint': case.get('execution_hint')}

def _parse_legacy_profile(index: int, profile: dict, target: dict, service: str, method: str, path: str, endpoint_id: str) -> dict:
    expected_binding = profile.get('expected_binding', {}) or {}
    existing_protection = profile.get('existing_protection', {}) or {}
    identifiers = expected_binding.get('resource_identifiers') or []
    resource_type, resource_why = rules.get_resource_type_from_identifiers(identifiers, path)
    canon_path = _canonicalize_path(path, resource_type)
    requester_types = expected_binding.get('requester_nf_types') or []
    nf_consumer = requester_types[0] if requester_types else ''
    attack_id = _attack_id(index, service, target.get('operation_id'), method, canon_path)
    return {'section_number': index, 'attack_id': attack_id, 'title': endpoint_id, 'service': service, 'endpoint_raw': f'{method}{canon_path}', 'resource': resource_type, 'operation': 'read' if method == 'GET' else 'write', 'nf_consumer': nf_consumer, 'expected_binding': expected_binding, 'existing_protection': existing_protection, 'test_idea': _default_test_idea(service, method, canon_path, expected_binding), '_source': 'authorization_profiles.json', '_schema_version': profile.get('schema_version'), '_endpoint_id': endpoint_id, '_confidence': profile.get('confidence'), '_evidence_refs': profile.get('evidence_refs', []), '_operation_id_hint': target.get('operation_id'), '_requester_nf_types_all': requester_types, '_resource_type_reason': resource_why, '_batch_id': profile.get('batch_id'), '_input_fingerprint': _case_fingerprint(profile)}

def _canonicalize_path(path: str, resource_type: str) -> str:
    if resource_type not in ('SUPI', 'SMF registration', 'AMF non-3GPP registration'):
        return path
    return re.sub('\\{(ueId|gpsi|supi|supiOrSuci)\\}', '{supi}', path, flags=re.IGNORECASE)

def _case_letter(case_index: int) -> str:
    letters = string.ascii_lowercase
    label = ''
    n = case_index
    while True:
        n, rem = divmod(n, 26)
        label = letters[rem] + label
        if n == 0:
            return label
        n -= 1

def _attack_id(index: int, service: str, operation_id: str | None, method: str, path: str) -> str:
    base = f'{service}_{operation_id}' if operation_id else f'{service}_{method}_{path}'
    slug = re.sub('[^a-zA-Z0-9]+', '_', base).strip('_').upper()
    return f'S{index:02d}_{slug}'

def _default_test_idea(service: str, method: str, path: str, expected_binding: dict) -> str:
    requesters = expected_binding.get('requester_nf_types') or ['the legitimate consumer NF']
    relation = expected_binding.get('relation_type', 'the expected resource binding')
    consumers = '/'.join(requesters)
    return f"An attacker-controlled second instance of {consumers} calls {method} {path} using another {consumers} instance's resource identifiers, to test whether '{relation}' is enforced at the resource-instance level rather than only via the service-level OAuth2 scope."
