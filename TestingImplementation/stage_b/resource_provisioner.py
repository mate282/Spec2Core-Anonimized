import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
REPO_ROOT = PROJECT_ROOT.parent
_shared_path = str(PROJECT_ROOT / 'shared')
if _shared_path not in sys.path:
    sys.path.insert(0, _shared_path)
import adapters
import resolvers
import sbi_client
import openapi
CONFIGS_DIR = PROJECT_ROOT / 'configs'
CATALOG_FILE = CONFIGS_DIR / 'resource_catalog.json'
OUTPUT_FILE = CONFIGS_DIR / 'provisioned_resources.yaml'
NO_CREATE_CATS = {'reused', 'reused_ue', 'reused_other', 'external', 'enum', 'auto', 'no_create_needed'}
DONE_STATUSES = {'created', 'already_present_via_lifecycle', 'reused', 'external', 'enum', 'no_create_needed'}
_TRUST_WITHOUT_VERIFY = DONE_STATUSES - {'created'}
_UE_IDENTITY_PARAMS = {'ueid', 'supi', 'supiorsuci', 'uecontextid'}
_LITERAL_SEED_VALUES = {'ueidentity': 'anyUE'}
_spec_cache: dict[str, dict] = {}

def _load_spec(spec_file: str) -> dict:
    if spec_file not in _spec_cache:
        with open(REPO_ROOT / spec_file, encoding='utf-8') as f:
            _spec_cache[spec_file] = yaml.safe_load(f)
    return _spec_cache[spec_file]

def _fixture_overrides(cfg: dict) -> dict:
    fx = cfg['fixture']
    plmn = {'mcc': fx['plmn']['mcc'], 'mnc': fx['plmn']['mnc']}
    nssai = {'sst': fx['slice']['sst'], 'sd': fx['slice'].get('sd')}
    return {'supi': fx['supi'], 'ueid': fx['supi'], 'gpsi': fx['supi'], 'plmnid': plmn, 'servingplmnid': plmn, 'dnn': fx['dnn'], 'pdusessionid': fx.get('pdu_session_id'), 'singlenssai': nssai, 'snssai': nssai}

def _synthesize_value(schema: dict, name_hint: str='value', depth: int=0):
    if depth > 6 or not isinstance(schema, dict):
        return f'test-{name_hint}'
    if 'enum' in schema and schema['enum']:
        return schema['enum'][0]
    if schema.get('anyOf'):
        return _synthesize_value(schema['anyOf'][0], name_hint, depth + 1)
    if schema.get('allOf'):
        return _synthesize_value(schema['allOf'][0], name_hint, depth + 1)
    schema_type = schema.get('type')
    if schema_type == 'object' or 'properties' in schema:
        props = schema.get('properties', {}) or {}
        if props:
            required = set(schema.get('required', []) or [])
            return {key: _synthesize_value(sub, key, depth + 1) for key, sub in props.items() if key in required or 'oneOf' not in (sub or {}) or 'type' in (sub or {})}
        additional = schema.get('additionalProperties')
        if isinstance(additional, dict) and schema.get('minProperties', 0) >= 1:
            return {'1': _synthesize_value(additional, name_hint, depth + 1)}
        return {}
    if schema_type == 'array':
        items = schema.get('items', {}) or {}
        return [_synthesize_value(items, name_hint, depth + 1)]
    if schema_type == 'integer':
        return schema.get('minimum', 1)
    if schema_type == 'number':
        return schema.get('minimum', 1.0)
    if schema_type == 'boolean':
        return False
    if schema_type == 'string':
        return _synthesize_string(schema.get('format', ''), name_hint)
    return _synthesize_string(schema_type or '', name_hint)

def _synthesize_string(hint_a: str, hint_b: str):
    combined = f'{hint_a} {hint_b}'.lower()
    if hint_a == 'uuid' or 'uuid' in combined:
        return str(uuid.uuid4())
    if hint_a == 'date-time' or any((t in combined for t in ('time', 'date', 'expiry', 'expires', 'stamp'))):
        return datetime.now(timezone.utc).isoformat()
    if any((t in combined for t in ('uri', 'url', 'callback'))):
        return 'http://example.invalid/callback'
    return f'test-{hint_b or hint_a or 'value'}'[:60]

def _apply_overrides(obj, overrides: dict):
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            low = key.lower()
            if low in overrides and overrides[low] is not None:
                obj[key] = overrides[low]
            else:
                _apply_overrides(obj[key], overrides)
    elif isinstance(obj, list):
        for item in obj:
            _apply_overrides(item, overrides)
_PATH_VAR_RE = re.compile('\\{([^}]+)\\}')

def _resolve_path_vars(path_template: str, created_values: dict) -> tuple[str | None, str | None]:
    resolved = path_template
    for var in _PATH_VAR_RE.findall(path_template):
        key = var.lower()
        if key not in created_values or created_values[key] is None:
            return (None, var)
        resolved = resolved.replace('{' + var + '}', str(created_values[key]))
    return (resolved, None)

def _extract_scope(spec: dict) -> str | None:
    servers = spec.get('servers', [])
    if not servers:
        return None
    match = re.search('/([a-z0-9][a-z0-9\\-]*)/v\\d+\\b', servers[0].get('url', ''))
    return match.group(1) if match else None

def _derive_nf_type(scope: str) -> str | None:
    if not scope or not scope.startswith('n') or '-' not in scope:
        return None
    return scope[1:].split('-')[0].upper()

def _strip_api_root(servers_url: str) -> str:
    parsed = urlparse(servers_url)
    path = parsed.path if parsed.netloc else re.sub('^\\{[^}]+\\}', '', parsed.path)
    return path.strip('/')

def _nrf_url(cfg: dict) -> str:
    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
    nrf = cfg['services']['nrf']
    return f'{scheme}://{nrf['host']}:{nrf['port']}'

def _producer_url(spec: dict, cfg: dict, nf_type: str, resolved_path: str) -> str | None:
    role = 'nrf' if nf_type == 'NRF' else f'{nf_type.lower()}_1'
    svc = cfg['services'].get(role)
    if not svc:
        return None
    base_path = _strip_api_root(spec.get('servers', [{}])[0].get('url', ''))
    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
    return f'{scheme}://{svc['host']}:{svc['port']}/{base_path}{resolved_path}'

def _mint_id(param: str) -> str:
    return str(uuid.uuid4())

def _record(results: dict, row: dict, status: str, value=None, detail: str=''):
    key = f'{row['param']}@{row['service']}@{row['prefix']}'
    results[key] = {'identifier': row['param'], 'service': row['service'], 'collection': row['prefix'], 'status': status, 'value': value, 'detail': detail, 'checked_at': datetime.now(timezone.utc).isoformat()}

def _seed_fixture_value(row: dict, cfg: dict):
    param = row['param'].lower()
    if param in _UE_IDENTITY_PARAMS:
        return cfg['fixture']['supi']
    if param in _LITERAL_SEED_VALUES:
        return _LITERAL_SEED_VALUES[param]
    if param == 'pdusessionid':
        return cfg['fixture'].get('pdu_session_id')
    if param == 'smpolicyid':
        return f'{cfg['fixture']['supi']}-{cfg['fixture'].get('pdu_session_id')}'
    if param in ('plmnid', 'servingplmnid'):
        return {'mcc': cfg['fixture']['plmn']['mcc'], 'mnc': cfg['fixture']['plmn']['mnc']}
    return None

def _maybe_get_token(cfg: dict, requester_id: str, requester_nf_type: str, nf_type: str, scope: str, tls: dict) -> tuple[str | None, dict | None]:
    if not cfg.get('capabilities', {}).get('oauth2', True):
        return (None, None)
    return sbi_client.get_token(nrf_url=_nrf_url(cfg), nf_instance_id=requester_id, nf_type=requester_nf_type, target_nf_type=nf_type, scope=scope, **tls)

def _still_exists(row: dict, cfg: dict, requester_id: str, value, requester_nf_type: str='SMF') -> bool | None:
    create_op, spec_file = (row.get('create_op'), row.get('file'))
    if not create_op or not spec_file or value is None:
        return None
    spec = _load_spec(spec_file)
    get_op = openapi.find_operation(spec, 'GET', create_op['path'])
    if get_op is None:
        return None
    scope = _extract_scope(spec)
    nf_type = _derive_nf_type(scope) if scope else None
    if not scope or not nf_type:
        return None
    tls = resolvers.tls_kwargs(cfg)
    token, err = _maybe_get_token(cfg, requester_id, requester_nf_type, nf_type, scope, tls)
    if err:
        return None
    own_var_key = row['param'].lower()
    resolved_path, missing = _resolve_path_vars(create_op['path'], {**_ue_seed(cfg), own_var_key: value})
    if resolved_path is None:
        return None
    url = _producer_url(spec, cfg, nf_type, resolved_path)
    if not url:
        return None
    resp = sbi_client.sbi_request('GET', url, token=token, **tls)
    if resp is None:
        return None
    return resp.status_code == 200

def _ue_seed(cfg: dict) -> dict:
    seed = {p: cfg['fixture']['supi'] for p in _UE_IDENTITY_PARAMS}
    seed.update(_LITERAL_SEED_VALUES)
    seed['pdusessionid'] = cfg['fixture'].get('pdu_session_id')
    return seed

def _process_row(row, cfg, created_values, requester_id, requester_nf_type, results, force, verbose):
    param_key = row['param'].lower()
    result_key = f'{row['param']}@{row['service']}@{row['prefix']}'
    existing = results.get(result_key)
    creator_override = row.get('creator_identity')
    if creator_override:
        override_id, override_nf_type = _requester_identity(cfg, creator_override)
        if override_id:
            requester_id, requester_nf_type = (override_id, override_nf_type)
        elif verbose:
            print(f'  ! creator_identity override {creator_override!r} for {result_key} could not be resolved ({cfg.get('_config_path', '?')}) — falling back to the default requester identity')
    if not force and existing and (existing['status'] in _TRUST_WITHOUT_VERIFY):
        created_values.setdefault(param_key, existing.get('value'))
        return 'skip'
    if not force and existing and (existing['status'] == 'created'):
        alive = _still_exists(row, cfg, requester_id, existing.get('value'), requester_nf_type)
        if alive:
            created_values.setdefault(param_key, existing.get('value'))
            return 'skip'
    if row['cat'] in NO_CREATE_CATS:
        value = _seed_fixture_value(row, cfg)
        if row['cat'] == 'no_create_needed' and value is None:
            value = _mint_id(row['param'])
        _record(results, row, row['cat'], value, row['note'])
        created_values.setdefault(param_key, value)
        return 'done'
    if row.get('auto_from_lifecycle'):
        value = _seed_fixture_value(row, cfg)
        _record(results, row, 'already_present_via_lifecycle', value, 'Already provisioned by the real UE registration / PDU session lifecycle (setupTest.py + UERANSIM) — no separate create call needed.')
        created_values.setdefault(param_key, value)
        return 'done'
    create_op = row.get('create_op')
    spec_file = row.get('file')
    if not create_op or not spec_file:
        _record(results, row, 'no_creator_found', None, 'No PUT/POST creator operation could be matched for this collection in the spec catalog — see docs/resource_provisioning_checklist.md.')
        return 'done'
    own_var_key = param_key
    if created_values.get(own_var_key) is None:
        created_values[own_var_key] = _mint_id(row['param'])
    resolved_path, missing = _resolve_path_vars(create_op['path'], created_values)
    if resolved_path is None:
        return 'pending'
    spec = _load_spec(spec_file)
    scope = _extract_scope(spec)
    nf_type = _derive_nf_type(scope) if scope else None
    if not scope or not nf_type:
        _record(results, row, 'no_creator_found', None, f"Could not derive an OAuth2 scope/NF type from {spec_file}'s servers block.")
        return 'done'
    operation = openapi.find_operation(spec, create_op['method'], create_op['path'])
    if operation is None:
        _record(results, row, 'no_creator_found', None, f'{create_op['method']} {create_op['path']} not found in {spec_file} at runtime.')
        return 'done'
    tls = resolvers.tls_kwargs(cfg)
    token, err = _maybe_get_token(cfg, requester_id, requester_nf_type, nf_type, scope, tls)
    if err:
        _record(results, row, 'unavailable_scope', None, f"Token request for scope '{scope}' (target_nf_type={nf_type}, requester_nf_type={requester_nf_type}) failed: {err}")
        return 'done'
    body_schema = openapi.get_request_body_schema(spec, operation)
    body = _synthesize_value(body_schema, row['param']) if body_schema else {}
    if isinstance(body, dict):
        _apply_overrides(body, _fixture_overrides(cfg))
    content_type = openapi.get_request_content_type(operation)
    url = _producer_url(spec, cfg, nf_type, resolved_path)
    if not url:
        role = 'nrf' if nf_type == 'NRF' else f'{nf_type.lower()}_1'
        _record(results, row, 'no_creator_found', None, f"No fixture role '{role}' in this lab config for producer NF type {nf_type}.")
        return 'done'
    if verbose:
        print(f'  {create_op['method']} {url}')
    resp = sbi_client.sbi_request(create_op['method'], url, token=token, json_body=body, content_type=content_type, **tls)
    if resp is None:
        _record(results, row, 'creation_failed', None, 'Connection failed (no response).')
        return 'done'
    if resp.status_code not in (200, 201, 204):
        body_excerpt = (resp.text or '')[:300]
        _record(results, row, 'creation_failed', None, f'HTTP {resp.status_code}: {body_excerpt}')
        return 'done'
    value = created_values[own_var_key]
    if create_op['method'] == 'POST':
        id_confirmed = False
        location = resp.headers.get('Location')
        if location:
            candidate = location.rstrip('/').rsplit('/', 1)[-1]
            static_last_segment = create_op['path'].rstrip('/').rsplit('/', 1)[-1]
            if candidate and candidate != static_last_segment:
                value = candidate
                id_confirmed = True
        if not id_confirmed:
            parsed = sbi_client.parse_json_response(resp)
            if isinstance(parsed, dict):
                response_field = row.get('response_field')
                if response_field:
                    v = parsed.get(response_field)
                    if isinstance(v, str):
                        value = v
                        id_confirmed = True
                else:
                    for k, v in parsed.items():
                        if k.lower() == param_key and isinstance(v, str):
                            value = v
                            id_confirmed = True
                            break
        created_values[own_var_key] = value
        if not id_confirmed:
            _record(results, row, 'creation_id_unresolved', None, f'{create_op['method']} {resolved_path} -> HTTP {resp.status_code}, but no Location header and no response body field named {row.get('response_field') or row['param']!r} -- the server-assigned id is not observable in the response.')
            return 'done'
    _record(results, row, 'created', value, f'{create_op['method']} {resolved_path} -> HTTP {resp.status_code}')
    return 'done'

def _requester_identity(cfg: dict, override: dict | None=None) -> tuple[str | None, str]:
    if override:
        nf_type = override.get('nf_type')
        fixture_role = override.get('fixture_role')
        if not nf_type or not fixture_role:
            return (None, 'SMF')
        adapter = adapters.get_adapter(cfg)
        return (adapter.resolve_identity(cfg, nf_type, fixture_role), nf_type)
    identities_file = CONFIGS_DIR / 'identities.yaml'
    if identities_file.exists():
        with open(identities_file, encoding='utf-8') as f:
            identities = yaml.safe_load(f) or {}
        entry = identities.get('services', {}).get('smf_1')
        if entry:
            return (entry['nf_instance_id'], 'SMF')
    adapter = adapters.get_adapter(cfg)
    return (adapter.resolve_identity(cfg, 'SMF', 'smf_1'), 'SMF')

def load_results() -> dict:
    if not OUTPUT_FILE.exists():
        return {}
    with open(OUTPUT_FILE, encoding='utf-8') as f:
        prior = yaml.safe_load(f) or {}
    return prior.get('resources', {}) or {}

def save_results(results: dict, cfg: dict) -> None:
    from collections import Counter
    counts = Counter((r['status'] for r in results.values()))
    out = {'generated_at': datetime.now(timezone.utc).isoformat(), 'lab_config': cfg.get('_config_path', '?'), 'summary': dict(counts), 'resources': results}
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.safe_dump(out, f, sort_keys=False, allow_unicode=True)

def load_catalog() -> list[dict]:
    with open(CATALOG_FILE, encoding='utf-8') as f:
        return json.load(f)

def run(cfg: dict, force: bool=False, verbose: bool=False) -> dict:
    catalog = load_catalog()
    results = {} if force else load_results()
    requester_id, requester_nf_type = _requester_identity(cfg)
    if not requester_id:
        raise RuntimeError('Could not resolve a requester NF identity (smf_1) — is the lab up?')
    created_values = _ue_seed(cfg)
    pending = list(catalog)
    for _pass in range(6):
        still_pending = []
        progressed = False
        for row in pending:
            outcome = _process_row(row, cfg, created_values, requester_id, requester_nf_type, results, force, verbose)
            if outcome == 'pending':
                still_pending.append(row)
            else:
                progressed = True
                if verbose and outcome == 'done':
                    key = f'{row['param']}@{row['service']}@{row['prefix']}'
                    print(f'[{results[key]['status']:>28}] {key}')
        pending = still_pending
        if not pending or not progressed:
            break
    for row in pending:
        _record(results, row, 'unresolved_dependency', None, "A path variable in this collection's create operation never became resolvable from the lab's fixtures or this run's already-created identifiers.")
    save_results(results, cfg)
    return results
_PLACEHOLDER_RE = re.compile('\\{[^}]+\\}')

def _normalize_path_template(template: str) -> str:
    return _PLACEHOLDER_RE.sub('{}', template)

def _service_name_from_file(file_path: str | None) -> str | None:
    if not file_path:
        return None
    stem = Path(file_path).stem
    return stem[:-len('_bundled')] if stem.endswith('_bundled') else stem

def _find_catalog_row(catalog: list[dict], param: str, service: str, path_template: str | None) -> dict | None:
    matches = [r for r in catalog if r['param'].lower() == param.lower() and (r['service'] == service or _service_name_from_file(r.get('file')) == service)]
    if not matches:
        return None
    if path_template:
        normalized_template = _normalize_path_template(path_template)
        for r in matches:
            if r['prefix'] and r['prefix'] != '/' and (_normalize_path_template(r['prefix']) in normalized_template):
                return r
    return matches[0]

def ensure_resource(var: str, service: str, cfg: dict, path_template: str | None=None) -> str | None:
    catalog = load_catalog()
    row = _find_catalog_row(catalog, var, service, path_template)
    if row is None:
        return None
    results = load_results()
    requester_id, requester_nf_type = _requester_identity(cfg)
    if not requester_id:
        return None
    created_values = _ue_seed(cfg)
    outcome = _process_row(row, cfg, created_values, requester_id, requester_nf_type, results, force=False, verbose=False)
    save_results(results, cfg)
    if outcome not in ('done', 'skip'):
        return None
    key = f'{row['param']}@{row['service']}@{row['prefix']}'
    entry = results.get(key, {})
    return entry.get('value') if entry.get('status') in DONE_STATUSES else None
SPEC_NONCONFORMANT_STATUSES = {'creation_id_unresolved'}

def last_provisioning_detail(var: str, service: str, path_template: str | None=None) -> dict | None:
    catalog = load_catalog()
    row = _find_catalog_row(catalog, var, service, path_template)
    if row is None:
        return None
    results = load_results()
    key = f'{row['param']}@{row['service']}@{row['prefix']}'
    entry = results.get(key)
    if not entry:
        return None
    return {'status': entry.get('status'), 'detail': entry.get('detail')}
