import json
import re
from pathlib import Path

def load_catalog(path: Path) -> list[dict]:
    text = path.read_text(encoding='utf-8')
    data, _ = json.JSONDecoder().raw_decode(text)
    return data if isinstance(data, list) else [data]

def _normalize_service(service: str) -> str:
    return re.sub('[^a-z0-9]', '', (service or '').lower())

def _normalize_path(path: str) -> str:
    return re.sub('\\{[^}]*\\}', '{}', path or '').rstrip('/')

def find_profile(target: dict, catalog: list[dict]) -> tuple[dict | None, str]:
    op_id = target.get('operation_id')
    if op_id:
        for profile in catalog:
            if (profile.get('target') or {}).get('operation_id') == op_id:
                return (profile, f"matched by operation_id '{op_id}'")
    service = _normalize_service(target.get('service', ''))
    method = (target.get('method') or '').upper()
    path = _normalize_path(target.get('path_template', ''))
    for profile in catalog:
        p_target = profile.get('target') or {}
        if _normalize_service(p_target.get('service', '')) == service and (p_target.get('method') or '').upper() == method and (_normalize_path(p_target.get('path', '')) == path):
            return (profile, 'matched by normalized service+method+path')
    return (None, f"no catalog entry for service='{target.get('service')}' method='{method}' path='{target.get('path_template')}' (operation_id='{op_id}')")

def build_spec_analysis(profile: dict) -> dict:
    return {'endpoint_id': profile.get('endpoint_id'), 'schema_version': profile.get('schema_version'), 'expected_binding': profile.get('expected_binding'), 'existing_protection': profile.get('existing_protection'), 'confidence': profile.get('confidence'), 'evidence_refs': profile.get('evidence_refs', [])}
