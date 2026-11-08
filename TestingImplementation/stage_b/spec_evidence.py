from __future__ import annotations
from pathlib import Path
import openapi
import resolvers
import response_signature
import sbi_client

def has_standard_get(specs_dir: Path, service: str, path_template: str) -> bool:
    spec = openapi.resolve_spec(specs_dir, service)
    if not spec:
        return False
    return openapi.find_operation(spec, 'GET', path_template) is not None

def _fire_standard_get(cfg, scenario, url, owner_id, owner_role, actor_nf_type):
    target = scenario['target']
    scope = target.get('required_scope')
    if not scope:
        return None
    if cfg.get('capabilities', {}).get('oauth2', True):
        token, _error = resolvers.request_attacker_token(cfg, owner_id, scope, target['producer_nf_type'], actor_nf_type, owner_role, register=False)
        if not token:
            return None
    else:
        token = None
    return sbi_client.sbi_request('GET', url, token=token, **resolvers.tls_kwargs(cfg))

def read_via_standard_get(cfg: dict, scenario: dict, url: str, owner_id: str, owner_role: str, actor_nf_type: str) -> dict | None:
    resp = _fire_standard_get(cfg, scenario, url, owner_id, owner_role, actor_nf_type)
    if resp is None or resp.status_code != 200:
        return None
    body = sbi_client.parse_json_response(resp)
    return body if isinstance(body, dict) else None

def probe_via_standard_get(cfg: dict, scenario: dict, url: str, owner_id: str, owner_role: str, actor_nf_type: str) -> dict:
    resp = _fire_standard_get(cfg, scenario, url, owner_id, owner_role, actor_nf_type)
    if resp is None:
        return {'body': None, 'confirmed_absent': False}
    if resp.status_code == 404 and response_signature.classify(resp).get('kind') == 'problem_details':
        return {'body': None, 'confirmed_absent': True}
    if resp.status_code != 200:
        return {'body': None, 'confirmed_absent': False}
    body = sbi_client.parse_json_response(resp)
    return {'body': body if isinstance(body, dict) else None, 'confirmed_absent': False}
