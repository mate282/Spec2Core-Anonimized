import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import yaml
import adapters
import resolvers
import sbi_client
import oracles
import restorer
import reporter
import validators
import response_signature
import spec_evidence
SPECS_DIR = Path(__file__).parent.parent.parent / 'docs' / 'specs'
SCENARIOS_DIR = Path(__file__).parent.parent / 'runs' / 'main' / 'scenarios'

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _excerpt(logs: str, keywords: list[str], max_lines: int=20) -> str:
    lines = [l for l in logs.splitlines() if any((k in l for k in keywords))]
    return '\n'.join(lines[-max_lines:])

def _describe_token_error(error: dict | None) -> str:
    if not error:
        return 'no further detail available'
    reason = error.get('reason')
    if reason == 'connection_error':
        return f'NRF unreachable ({error.get('detail', '?')})'
    if reason == 'http_error':
        return f'NRF rejected the token request: HTTP {error.get('status')} {error.get('body')}'
    if reason == 'no_access_token':
        return f'NRF returned HTTP {error.get('status')} with no access_token field: {error.get('body')}'
    return str(error)

def _scope_not_available(error: dict | None) -> bool:
    if not error or error.get('reason') != 'http_error':
        return False
    body = error.get('body')
    return isinstance(body, dict) and body.get('error') == 'invalid_scope'

def _guard_best_effort_denial(scenario: dict, verdict: str, reason: str) -> tuple[str, str]:
    hint = (scenario.get('spec_analysis') or {}).get('execution_hint') or {}
    if hint.get('status') == 'requires_state_setup' and verdict == 'SECURE':
        return ('INCONCLUSIVE', f'Best-effort probe denied, but the required TS procedural state was not staged; {reason}')
    return (verdict, reason)

def _load_scenario_by_code(code: str) -> dict | None:
    for path in sorted(SCENARIOS_DIR.glob('*.yaml')):
        with open(path, encoding='utf-8') as f:
            spec = yaml.safe_load(f)
        if spec.get('attack_id', '').startswith(f'{code}_'):
            return spec
    return None

def _fire_scenario_request(scenario: dict, cfg: dict, adapter) -> dict:
    try:
        actors = scenario['actors']
        actor_nf_type = actors['owner']['nf_type']
        owner_role = actors['owner']['fixture_role']
        attacker_role = actors['attacker']['fixture_role']
        owner_id = adapter.get_identity(cfg, actor_nf_type, owner_role)
        attacker_id = adapter.get_identity(cfg, actor_nf_type, attacker_role)
        if not owner_id or not attacker_id:
            return {'ok': False, 'status_code': None, 'body': None, 'error': f'{owner_role}/{attacker_role} not found in MongoDB'}
        resources = {'supi': cfg['fixture']['supi'], 'owner_id': owner_id, 'attacker_id': attacker_id}
        path_vars, _extraction_trace = resolvers.resolve_path_variables(scenario, cfg, adapter)
        resources.update(path_vars)
        ctx = resolvers.build_runtime_context(cfg, resources, attacker_role)
        method = scenario['request']['method']
        url = resolvers.build_url(scenario, cfg, path_vars, adapter)
        body_required = validators.body_is_required(SPECS_DIR, scenario)
        body = resolvers.build_payload(scenario['request'], ctx, body_required=body_required)
        params = resolvers.build_query_params(scenario['request'], ctx)
        multipart = resolvers.build_multipart(scenario['request'], ctx)
        tls = resolvers.tls_kwargs(cfg)
        token = None
        if cfg.get('capabilities', {}).get('oauth2', True):
            auth_spec = scenario['request']['authorization']
            token, token_error = resolvers.request_attacker_token(cfg, attacker_id, auth_spec['scope'], auth_spec['target_nf_type'], actor_nf_type, attacker_role)
            if not token:
                return {'ok': False, 'status_code': None, 'body': None, 'error': f'token error: {token_error}'}
        if multipart is not None:
            raw_body, content_type = multipart
            resp = sbi_client.sbi_request(method, url, token=token, raw_body=raw_body, content_type=content_type, params=params, **tls)
        else:
            content_type = validators.get_request_content_type(SPECS_DIR, scenario)
            resp = sbi_client.sbi_request(method, url, token=token, json_body=body, content_type=content_type, params=params, **tls)
        status = resp.status_code if resp is not None else None
        return {'ok': resp is not None, 'status_code': status, 'body': sbi_client.parse_json_response(resp), 'error': None, 'request': {'method': method, 'url': url, 'body': body, 'params': params}}
    except Exception as e:
        return {'ok': False, 'status_code': None, 'body': None, 'error': str(e)}

def run_scenario(scenario: dict, cfg: dict, results_dir: Path, verbose: bool=False, resolution_mode: str='static', ai_ctx: dict | None=None) -> dict:
    run_id = str(uuid.uuid4())[:8]
    scenario_id = scenario['attack_id']
    result: dict = {'run_id': run_id, 'scenario_id': scenario_id, 'scenario': scenario, 'timestamp': _now_iso(), 'verdict': 'INCONCLUSIVE', 'verdict_reason': 'Not executed', 'security_findings': [], 'setup': {}, 'resources': {}, 'controls': {}, 'attack': {'request': {}, 'response': {}}, 'evidence': {'pre': {}, 'post': {}}, 'restore': {}}
    sbi_client.clear_token_cache()
    adapter = adapters.get_adapter(cfg)

    def _fail(verdict: str, reason: str) -> dict:
        result['verdict'] = verdict
        result['verdict_reason'] = reason
        return result
    if verbose:
        print(f'  [1] Health check...')
    health = adapter.check_health(cfg)
    result['setup']['lab_healthy'] = health['healthy']
    result['setup']['health_details'] = health['details']
    if not health['healthy']:
        unhealthy = [k for k, v in health['details'].items() if v != 'running']
        return _fail('SETUP_FAILURE', f'Containers not running: {unhealthy}')
    preconditions = scenario.get('preconditions', [])
    amf1_id: str | None = None
    if 'subscriber_provisioned' in preconditions:
        if verbose:
            print(f'  [2] Provisioning subscriber...')
        prov = adapter.provision_subscriber(cfg)
        result['setup']['subscriber_provisioned'] = prov['ok']
        if not prov['ok']:
            result['setup']['error'] = prov.get('error')
            return _fail('SETUP_FAILURE', f'Provisioning failed: {prov.get('error')}')
        amf1_id = prov['amf1_instance_id']
    else:
        result['setup']['subscriber_provisioned'] = None
    if amf1_id is None:
        amf1_id = adapter.get_identity(cfg, 'AMF', 'amf_1')
    depends_on = scenario.get('depends_on')
    if depends_on:
        dep_code = depends_on['scenario']
        if verbose:
            print(f'  [2b] Firing dependency {dep_code} (state precondition)...')
        dep_scenario = _load_scenario_by_code(dep_code)
        if dep_scenario is None:
            result['setup']['dependency'] = {'scenario': dep_code, 'error': f"scenario '{dep_code}' not found in {SCENARIOS_DIR}"}
            if verbose:
                print(f'  -> dependency scenario not found, continuing anyway')
        else:
            dep_result = _fire_scenario_request(dep_scenario, cfg, adapter)
            result['setup']['dependency'] = {'scenario': dep_scenario['attack_id'], **dep_result}
            if verbose:
                if dep_result['error']:
                    print(f'  -> dependency call failed: {dep_result['error']} (continuing anyway)')
                else:
                    print(f'  -> dependency call: HTTP {dep_result['status_code']}')
            time.sleep(cfg['fixture'].get('evidence_settle_seconds', 0.5))
    if verbose:
        print(f'  [3] Resolving path variables...')
    actors = scenario['actors']
    actor_nf_type = actors['owner']['nf_type']
    owner_role = actors['owner']['fixture_role']
    attacker_role = actors['attacker']['fixture_role']
    owner_id = adapter.get_identity(cfg, actor_nf_type, owner_role)
    attacker_id = adapter.get_identity(cfg, actor_nf_type, attacker_role)
    if not owner_id:
        return _fail('SETUP_FAILURE', f'{owner_role} not found in MongoDB — is the lab up?')
    if not attacker_id:
        return _fail('SETUP_FAILURE', f'{attacker_role} not found in MongoDB — is the lab up?')
    resources: dict = {'supi': cfg['fixture']['supi'], 'amf1_id': amf1_id, 'owner_id': owner_id, 'attacker_id': attacker_id}
    oauth2_enabled = cfg.get('capabilities', {}).get('oauth2', True)
    attacker_token = None
    scope = None
    target_nf_type = None
    if oauth2_enabled:
        if verbose:
            print('  [3a] Checking target service scope...')
        auth_spec = scenario['request']['authorization']
        scope = auth_spec['scope']
        target_nf_type = auth_spec['target_nf_type']
        attacker_token, token_error = resolvers.request_attacker_token(cfg, attacker_id, scope, target_nf_type, actor_nf_type, attacker_role)
        if not attacker_token:
            result['setup']['token_error'] = token_error
            verdict = 'NOT_IMPLEMENTED' if _scope_not_available(token_error) else 'SETUP_FAILURE'
            return _fail(verdict, f'Could not obtain token (scope: {scope}, target: {target_nf_type}) — {_describe_token_error(token_error)}')
        resources['attacker_token_ok'] = True
    else:
        resources['attacker_token_ok'] = None
        result['setup']['oauth2_enabled'] = False
    try:
        owner_ctx = {'owner_id': owner_id, 'owner_role': owner_role, 'actor_nf_type': actor_nf_type, 'specs_dir': SPECS_DIR}
        path_vars, extraction_trace = resolvers.resolve_path_variables(scenario, cfg, adapter, resolution_mode=resolution_mode, ai_ctx=ai_ctx, owner_ctx=owner_ctx)
        resources.update(path_vars)
    except resolvers.SetupError as e:
        if e.extraction_trace:
            result['setup']['extraction_agent'] = e.extraction_trace
        return _fail('SETUP_FAILURE', str(e))
    if extraction_trace:
        result['setup']['extraction_agent'] = extraction_trace
        if verbose:
            for var, cmp in extraction_trace.items():
                if cmp.get('resolved_via') == 'resource_provisioner':
                    print(f'       extraction_agent[{var}]: no curated resolver — resolved via resource_provisioner ({cmp['agent_reasoning']})')
                    continue
                if cmp.get('fallback'):
                    status = 'resolved via agent fallback' if cmp['agent_resolved'] else 'agent fallback FAILED'
                    print(f'       extraction_agent[{var}]: no curated resolver — {status} (value={cmp['agent_value']!r}, confidence={cmp['agent_confidence']})')
                    continue
                match_str = 'MATCH' if cmp['match'] else 'MISMATCH' if cmp['match'] is False else 'unresolved'
                print(f'       extraction_agent[{var}]: static={cmp['static_value']!r} agent={cmp['agent_value']!r} ({match_str}, confidence={cmp['agent_confidence']})')
    result['resources'] = resources
    ctx = resolvers.build_runtime_context(cfg, resources, attacker_role)
    method = scenario['request']['method']
    try:
        url = resolvers.build_url(scenario, cfg, path_vars, adapter)
    except ValueError as e:
        return _fail('SETUP_FAILURE', str(e))
    body_required = validators.body_is_required(SPECS_DIR, scenario)
    empty_default = validators.body_default_empty_value(SPECS_DIR, scenario)
    body = resolvers.build_payload(scenario['request'], ctx, body_required=body_required, empty_default=empty_default)
    params = resolvers.build_query_params(scenario['request'], ctx)
    multipart = resolvers.build_multipart(scenario['request'], ctx)
    tls = resolvers.tls_kwargs(cfg)
    json_content_type = validators.get_request_content_type(SPECS_DIR, scenario)

    def _fire(fire_token: str | None):
        if multipart is not None:
            raw_body, content_type = multipart
            return sbi_client.sbi_request(method, url, token=fire_token, raw_body=raw_body, content_type=content_type, params=params, **tls)
        return sbi_client.sbi_request(method, url, token=fire_token, json_body=body, content_type=json_content_type, params=params, **tls)
    if verbose:
        print(f'  [4b] Pre-flight schema validation...')
    if multipart is None:
        preflight = validators.validate_request(SPECS_DIR, scenario, body, params)
    else:
        preflight = {'valid': True, 'errors': [], 'schema_checked': False}
    result['attack']['preflight_validation'] = preflight
    if not preflight['valid']:
        return _fail('SETUP_FAILURE', f'Local payload/query validation failed against the 3GPP OpenAPI schema (request never sent): {'; '.join(preflight['errors'])}')
    if not oauth2_enabled:
        if verbose:
            print(f'  [5] OAuth2 disabled for this core (capabilities.oauth2: false) — skipping token request')
        attacker_token = None
    result['resources'] = resources
    if oauth2_enabled:
        if verbose:
            print(f'  [6] Missing-token control...')
        r_no_token = _fire(None)
        if r_no_token is not None:
            result['controls']['missing_token'] = r_no_token.status_code
    else:
        result['controls']['missing_token'] = 'N/A — oauth2 disabled for this core'
    if verbose:
        print(f'  [7] Pre-attack evidence...')
    pre_ev: dict = {}
    resource_type = scenario['resource']['type']
    owner_ev_spec = scenario['resource'].get('owner_evidence', {})
    key_field = 'ueId'
    use_mongo_lookup = owner_ev_spec.get('resolver') == 'MONGO_LOOKUP'
    if use_mongo_lookup:
        collection = owner_ev_spec.get('collection', '')
        key_field = owner_ev_spec.get('key', 'ueId')
        supi = cfg['fixture']['supi']
    try_standard_get = use_mongo_lookup and resource_type == 'SUPI' and (method in ('PUT', 'PATCH')) and spec_evidence.has_standard_get(SPECS_DIR, scenario['target']['service'], scenario['request']['path_template'])
    try_generic_get = not use_mongo_lookup and method in ('PUT', 'PATCH', 'DELETE') and spec_evidence.has_standard_get(SPECS_DIR, scenario['target']['service'], scenario['request']['path_template'])

    def _read_binding() -> tuple[dict | None, str, bool]:
        if try_standard_get:
            binding = spec_evidence.read_via_standard_get(cfg, scenario, url, owner_id, owner_role, actor_nf_type)
            if binding is not None:
                return (binding, 'standard_get', False)
            return (adapter.get_structured_doc(collection, key_field, supi), 'adapter_db', False)
        if use_mongo_lookup:
            return (adapter.get_structured_doc(collection, key_field, supi), 'adapter_db', False)
        if try_generic_get:
            probe = spec_evidence.probe_via_standard_get(cfg, scenario, url, owner_id, owner_role, actor_nf_type)
            return (probe['body'], 'standard_get_generic', probe['confirmed_absent'])
        return (None, 'none', False)
    if use_mongo_lookup or try_generic_get:
        pre_ev['binding'], pre_ev['binding_source'], pre_ev['binding_confirmed_absent'] = _read_binding()
    smf_logs_pre = adapter.read_logs(cfg['services']['smf_1']['container'], tail=100)
    amf_logs_pre = adapter.read_logs(cfg['services']['amf_1']['container'], tail=100)
    pcf_logs_pre = adapter.read_logs(cfg['services']['pcf_1']['container'], tail=100)
    pre_ev['smf_logs'] = smf_logs_pre
    pre_ev['amf_logs'] = amf_logs_pre
    pre_ev['pcf_logs'] = pcf_logs_pre
    if resource_type == 'UE context':
        ctx_present = adapter.check_data_plane_alive()
        pre_ev['ue_context_present'] = ctx_present
        if verbose:
            print(f'  [8] UE context present (pre-attack): {ctx_present}  (uesimtun0 alive in the ue container)')
    result['evidence']['pre'] = pre_ev
    if verbose:
        print(f'  [9] Attack: {method} {url}')
    resp = _fire(attacker_token)
    status = resp.status_code if resp is not None else None
    resp_body = sbi_client.parse_json_response(resp)
    result['attack']['request'] = {'method': method, 'url': url, 'params': params, 'body': body, 'multipart': multipart is not None}
    signature = response_signature.classify(resp)
    result['attack']['response'] = {'status_code': status, 'body': resp_body, 'signature': signature}
    if verbose:
        print(f'  -> HTTP {status}  (signature: {signature.get('kind')})')
    owner_control = None
    denial_codes = scenario['verdict']['denial_codes']
    if oauth2_enabled and status in denial_codes and oracles.needs_owner_control_check(scenario):
        if verbose:
            print(f'  [9b] Owner-control check: firing the identical request as {owner_role}...')
        owner_token, owner_token_error = resolvers.request_attacker_token(cfg, owner_id, scope, target_nf_type, actor_nf_type, owner_role, register=False)
        if owner_token:
            oc_ctx = resolvers.build_runtime_context(cfg, {'attacker_id': owner_id}, owner_role)
            oc_body = resolvers.build_payload(scenario['request'], oc_ctx, body_required=body_required)
            oc_params = resolvers.build_query_params(scenario['request'], oc_ctx)
            oc_multipart = resolvers.build_multipart(scenario['request'], oc_ctx)
            if oc_multipart is not None:
                oc_raw_body, oc_content_type = oc_multipart
                oc_resp = sbi_client.sbi_request(method, url, token=owner_token, raw_body=oc_raw_body, content_type=oc_content_type, params=oc_params, **tls)
            else:
                oc_resp = sbi_client.sbi_request(method, url, token=owner_token, json_body=oc_body, content_type=json_content_type, params=oc_params, **tls)
            oc_status = oc_resp.status_code if oc_resp is not None else None
            oc_resp_body = sbi_client.parse_json_response(oc_resp)
            owner_control = {'ok': oc_resp is not None, 'status_code': oc_status, 'body': oc_resp_body, 'cause': oracles.extract_cause(oc_resp_body), 'error': None, 'request_body': oc_body, 'request_params': oc_params}
        else:
            owner_control = {'ok': False, 'status_code': None, 'body': None, 'cause': None, 'error': f'token error: {owner_token_error}'}
        result['attack']['owner_control'] = owner_control
        if verbose:
            print(f'       -> HTTP {owner_control.get('status_code')} (cause: {owner_control.get('cause')})' if owner_control.get('ok') else f'       -> owner-control check failed: {owner_control.get('error')}')
    if verbose:
        print(f'  [10] Post-attack evidence...')
    time.sleep(cfg['fixture'].get('evidence_settle_seconds', 0.5))
    post_ev: dict = {}
    if use_mongo_lookup or try_generic_get:
        post_ev['binding'], post_ev['binding_source'], post_ev['binding_confirmed_absent'] = _read_binding()
    smf_logs_post = adapter.read_logs(cfg['services']['smf_1']['container'], tail=100)
    amf_logs_post = adapter.read_logs(cfg['services']['amf_1']['container'], tail=100)
    pcf_logs_post = adapter.read_logs(cfg['services']['pcf_1']['container'], tail=100)
    post_ev['smf_logs'] = smf_logs_post
    post_ev['amf_logs'] = amf_logs_post
    post_ev['pcf_logs'] = pcf_logs_post
    result['evidence']['post'] = post_ev
    result['evidence']['amf_logs_excerpt'] = _excerpt(amf_logs_post, ['AmfUe', 'removed', 'release', 'context', 'ue-contexts'])
    result['evidence']['smf_logs_excerpt'] = _excerpt(smf_logs_post, ['Release', 'release', 'smContext', 'deleted', 'removed', 'PFCP', '204'])
    result['evidence']['pcf_logs_excerpt'] = _excerpt(pcf_logs_post, ['SMpolicy', 'Update', 'update', 'policy', 'Policy'])
    if verbose:
        print(f'  [11] Verdict ({resource_type}, {method})...')
    verdict, reason = oracles.evaluate(scenario, resp, pre_ev, post_ev, resources, owner_control, request_body=body, core_adapter=cfg.get('core_adapter', 'free5gc'))
    verdict, reason = _guard_best_effort_denial(scenario, verdict, reason)
    result['verdict'] = verdict
    result['verdict_reason'] = reason
    result['security_findings'] = oracles.security_findings(scenario, resp, verdict)
    if verbose:
        print(f'  -> {verdict}: {reason}')
    if verbose:
        print(f'  [12] Restoring...')
    result['restore'] = restorer.restore_after_scenario(scenario, cfg, resources, adapter)
    return result

def run_and_report(scenario: dict, cfg: dict, results_dir: Path, verbose: bool=False, resolution_mode: str='static', ai_ctx: dict | None=None) -> tuple[dict, Path]:
    result = run_scenario(scenario, cfg, results_dir, verbose, resolution_mode, ai_ctx)
    run_dir = reporter.write_report(result, results_dir)
    return (result, run_dir)
