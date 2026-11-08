import copy
import json
import uuid
import sbi_client
FIELD_SEMANTICS: dict[str, str] = {'amfInstanceId': 'attacker_id', 'ausfInstanceId': 'attacker_id', 'servingNetworkName': 'fixture_serving_network_name', 'guami.plmnId': 'fixture_plmn', 'guami.amfId': 'attacker_amf_id_hex', 'deregCallbackUri': 'attacker_dereguri', 'pduSessionId': 'fixture_pdu_session_id', 'n2InfoContainer.smInfo.pduSessionId': 'fixture_pdu_session_id', 'nfId': 'attacker_id', 'n1MessageContainer.nfId': 'attacker_id', 'smfInstanceId': 'attacker_id', 'nwdafInstanceId': 'attacker_id', 'smsfInstanceId': 'attacker_id', 'nfInstanceId': 'attacker_id'}
QUERY_FIELD_SEMANTICS: dict[str, str] = {'plmn-id': 'fixture_plmn', 'single-nssai': 'fixture_slice', 'dnn': 'fixture_dnn', 'smf-instance-id': 'attacker_id'}
SERVICE_BASE_PATH: dict[str, str] = {'Nudm_UECM': 'nudm-uecm/v1', 'Nudm_SDM': 'nudm-sdm/v2', 'Namf Comm': 'namf-comm/v1', 'Namf_Comm': 'namf-comm/v1', 'Namf_Communication': 'namf-comm/v1', 'Nsmf_PDUSession': 'nsmf-pdusession/v1', 'Namf_Location': 'namf-loc/v1', 'Namf_MT': 'namf-mt/v1', 'Nausf_SoRProtection': 'nausf-sorprotection/v1', 'Nausf_UPUProtection': 'nausf-upuprotection/v1', 'Nnef_SMContext': 'nnef-smcontext/v1', 'Nnef_SMService': 'nnef-smservice/v1', 'Npcf_SMPolicyControl': 'npcf-smpolicycontrol/v1', 'Nudr_DR': 'nudr-dr/v2'}
SERVICE_BASE_PATH_BY_ADAPTER: dict[str, dict[str, str]] = {'open5gs': {'Nudr_DR': 'nudr-dr/v1'}}
LOG_PARSE_PATTERNS: dict[str, str] = {'SM context': '/sm-contexts/(urn:uuid:[0-9a-f-]{36})(?:/|\\"|\\s)'}
_OPEN5GS_SM_CONTEXT_PROBE_MAX_INDEX = 30

def _probe_smcontextref_open5gs(cfg: dict) -> str | None:
    smf = cfg['services']['smf_1']
    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
    tls = tls_kwargs(cfg)
    supi = cfg['fixture']['supi']
    for i in range(1, _OPEN5GS_SM_CONTEXT_PROBE_MAX_INDEX + 1):
        url = f'{scheme}://{smf['host']}:{smf['port']}/nsmf-pdusession/v1/sm-contexts/{i}/modify'
        resp = sbi_client.sbi_request('POST', url, json_body={}, **tls)
        if resp is None:
            continue
        if resp.status_code == 400 and supi in (resp.text or ''):
            return str(i)
    return None

def build_runtime_context(cfg: dict, resources: dict, attacker_role: str) -> dict:
    plmn = cfg['fixture']['plmn']
    slce = cfg['fixture']['slice']
    supi = cfg['fixture']['supi']
    attacker_id = resources.get('attacker_id', '')
    attacker_svc = cfg['services'][attacker_role]
    serving_network_name = f'5G:mnc{str(plmn['mnc']).zfill(3)}.mcc{str(plmn['mcc']).zfill(3)}.3gppnetwork.org'
    return {'attacker_id': attacker_id, 'attacker_amf_id_hex': attacker_svc.get('amf_id'), 'attacker_dereguri': f'http://{attacker_svc['container']}:8000/namf-comm/v1/ue-contexts/{supi}/deregistration', 'fixture_supi': supi, 'fixture_plmn': plmn, 'fixture_serving_network_name': serving_network_name, 'fixture_slice': slce, 'fixture_dnn': cfg['fixture']['dnn'], 'fixture_pdu_session_id': cfg['fixture'].get('pdu_session_id')}

def resolve_path_variables(scenario: dict, cfg: dict, adapter, resolution_mode: str='static', ai_ctx: dict | None=None, owner_ctx: dict | None=None) -> tuple[dict, dict]:
    path_vars: dict = {}
    extraction_trace: dict = {}
    resource_spec = scenario.get('resource', {})
    ai_ctx = ai_ctx or {}
    agent_enabled = resolution_mode in ('compare', 'agent') and bool(ai_ctx.get('api_key'))

    def _verify_ctx_for(var: str) -> dict | None:
        if not owner_ctx:
            return None
        return {'scenario': scenario, 'cfg': cfg, 'adapter': adapter, 'var_name': var, 'known_path_vars': dict(path_vars), **owner_ctx}
    for var in resource_spec.get('identifier_variables', []):
        if var in ('supi', 'supiOrSuci'):
            path_vars[var] = cfg['fixture']['supi']
        elif var in ('ueContextId',):
            path_vars[var] = cfg['fixture']['supi']
        elif var in ('serviceType',):
            path_vars[var] = 'AF_GUIDANCE_FOR_URSP'
        elif var in ('ueIdentity',):
            path_vars[var] = 'anyUE'
        elif var in ('pduSessionId',):
            path_vars[var] = str(cfg['fixture']['pdu_session_id'])
        elif var in ('servingNetworkName',):
            plmn = cfg['fixture']['plmn']
            path_vars[var] = f'5G:mnc{str(plmn['mnc']).zfill(3)}.mcc{str(plmn['mcc']).zfill(3)}.3gppnetwork.org'
        elif var in ('servingPlmnId',):
            plmn = cfg['fixture']['plmn']
            path_vars[var] = f'{plmn['mcc']}{plmn['mnc']}'
        elif var in ('smPolicyId',):
            static_value = f'{cfg['fixture']['supi']}-{cfg['fixture']['pdu_session_id']}'
            value = _resolve_with_optional_agent(var, static_value, adapter, resolution_mode, ai_ctx, agent_enabled, extraction_trace, verify_ctx=_verify_ctx_for(var), description=f"The {resource_spec.get('type', var)!r} resource identifier used as the '{var}' path variable in the request path {scenario.get('request', {}).get('path_template', '?')!r}. It identifies a policy resource tied to the test subscriber's active PDU session. The test subscriber's SUPI is {cfg['fixture']['supi']!r}. You are not told how this identifier is composed — it may be a fixed combination of values already available in this lab, or it may need to be discovered by inspecting the producing network function's own logs or database.")
            path_vars[var] = value
        elif var in ('smContextRef',):
            resolver = resource_spec.get('resolver', '')
            static_value = None
            if resolver == 'LOG_PARSE':
                if cfg.get('core_adapter') == 'open5gs':
                    static_value = _probe_smcontextref_open5gs(cfg)
                else:
                    owner_ev = resource_spec.get('owner_evidence', {})
                    container = owner_ev.get('container', 'smf')
                    pattern = owner_ev.get('pattern', LOG_PARSE_PATTERNS.get('SM context', ''))
                    tail = owner_ev.get('tail')
                    static_value = adapter.search_logs(container, pattern, tail)
            value = _resolve_with_optional_agent(var, static_value, adapter, resolution_mode, ai_ctx, agent_enabled, extraction_trace, verify_ctx=_verify_ctx_for(var), description=f"The {resource_spec.get('type', var)!r} resource identifier used as the '{var}' path variable in the request path {scenario.get('request', {}).get('path_template', '?')!r}. It is generated at runtime by the producing network function when the resource is created — there is no fixed formula for it, so it is most likely only observable in that NF's own logs, not as a stored database field. The test subscriber's SUPI is {cfg['fixture']['supi']!r}.")
            if not value:
                raise SetupError(f"Could not resolve path variable '{var}' (resolver: {resolver or resolution_mode}) — is there an active PDU session in the ue container?", extraction_trace)
            path_vars[var] = value
        else:
            value = _resolve_via_resource_provisioner(var, scenario, cfg, extraction_trace)
            nonconformance = extraction_trace.get(var, {}).get('producer_spec_nonconformance')
            if not value:
                value = _resolve_via_agent_fallback(var, resource_spec, scenario, cfg, adapter, ai_ctx, extraction_trace, verify_ctx=_verify_ctx_for(var))
            if not value:
                if nonconformance:
                    raise SetupError(f"Could not resolve path variable '{var}' — PRODUCER_SPEC_NONCONFORMANT: {nonconformance} The automatic extraction-agent fallback also could not find it independently (see extraction_trace/evidence.json for its own reasoning) — this is a producer-NF implementation gap, not a pipeline one; no resolver could ever fix it, the information genuinely isn't exposed anywhere observable.", extraction_trace)
                raise SetupError(f"Could not resolve path variable '{var}' — no curated resolver exists for it (resource type: {resource_spec.get('type', '?')!r}) and the automatic extraction-agent fallback did not produce a value (pass --ai-key to enable it, or check its reasoning in extraction_trace/evidence.json if it was already tried). Add a curated resolver in resolvers.py if this identifier's resolution strategy is now known instead of relying on the agent every run.", extraction_trace)
            path_vars[var] = value
    return (path_vars, extraction_trace)

def _resolve_via_resource_provisioner(var: str, scenario: dict, cfg: dict, extraction_trace: dict) -> str | None:
    import resource_provisioner
    service = scenario['target']['service']
    path_template = scenario.get('request', {}).get('path_template')
    value = resource_provisioner.ensure_resource(var, service, cfg, path_template=path_template)
    if value:
        extraction_trace[var] = {'static_value': None, 'agent_value': value, 'agent_resolved': True, 'agent_confidence': 1.0, 'agent_reasoning': f"resolved via resource_provisioner.py's catalog (configs/provisioned_resources.yaml) — value={value!r}", 'agent_trace': [], 'match': None, 'fallback': True, 'resolved_via': 'resource_provisioner'}
        return value
    detail = resource_provisioner.last_provisioning_detail(var, service, path_template)
    if detail and detail.get('status') in resource_provisioner.SPEC_NONCONFORMANT_STATUSES:
        extraction_trace.setdefault(var, {})['producer_spec_nonconformance'] = detail.get('detail')
    return None

def _resolve_via_agent_fallback(var: str, resource_spec: dict, scenario: dict, cfg: dict, adapter, ai_ctx: dict, extraction_trace: dict, verify_ctx: dict | None=None) -> str | None:
    if not ai_ctx.get('api_key'):
        extraction_trace[var] = {'static_value': None, 'agent_value': None, 'agent_resolved': False, 'agent_confidence': 0.0, 'agent_reasoning': 'no curated resolver exists for this identifier, and no AI key was configured to attempt the automatic extraction-agent fallback (pass --ai-key)', 'agent_trace': [], 'match': None, 'fallback': True}
        return None
    import extraction_agent
    resource_type = resource_spec.get('type', var)
    owner_ev_desc = resource_spec.get('owner_evidence', {}).get('description', '')
    path_template = scenario.get('request', {}).get('path_template', '?')
    description = f"The {resource_type!r} resource identifier used as the '{var}' path variable in the request path {path_template!r}. This project has no known formula or fixed-field lookup for this identifier — it must be discovered from the producing network function's own runtime state (logs and/or database)." + (f' Known evidence about how it is exposed: {owner_ev_desc}.' if owner_ev_desc else '') + f" The test subscriber's SUPI is {cfg.get('fixture', {}).get('supi', '?')!r}."
    agent_result = extraction_agent.resolve_identifier(var_name=var, description=description, adapter=adapter, verify_ctx=verify_ctx, **ai_ctx)
    extraction_trace[var] = {'static_value': None, 'agent_value': agent_result.get('value'), 'agent_resolved': agent_result.get('resolved'), 'agent_confidence': agent_result.get('confidence'), 'agent_reasoning': agent_result.get('reasoning'), 'agent_trace': agent_result.get('trace'), 'match': None, 'fallback': True}
    return agent_result.get('value') if agent_result.get('resolved') else None

def _resolve_with_optional_agent(var: str, static_value, adapter, resolution_mode: str, ai_ctx: dict, agent_enabled: bool, extraction_trace: dict, description: str, verify_ctx: dict | None=None) -> str | None:
    agent_result = None
    if agent_enabled:
        import extraction_agent
        agent_result = extraction_agent.resolve_identifier(var_name=var, description=description, adapter=adapter, verify_ctx=verify_ctx, **ai_ctx)
        extraction_trace[var] = {'static_value': static_value, 'agent_value': agent_result.get('value'), 'agent_resolved': agent_result.get('resolved'), 'agent_confidence': agent_result.get('confidence'), 'agent_reasoning': agent_result.get('reasoning'), 'agent_trace': agent_result.get('trace'), 'match': agent_result.get('value') == static_value if agent_result.get('resolved') else None}
    value = static_value
    if resolution_mode == 'agent' and agent_result and agent_result.get('resolved'):
        value = agent_result['value']
    return value

class SetupError(Exception):

    def __init__(self, message: str, extraction_trace: dict | None=None):
        super().__init__(message)
        self.extraction_trace = extraction_trace or {}

def build_url(scenario: dict, cfg: dict, path_vars: dict, adapter=None) -> str:
    service = scenario['target']['service']
    producer_nf = scenario['target']['producer_nf_type']
    path_tpl = scenario['request']['path_template']
    actor_nf = scenario['actors']['owner']['nf_type']
    owner_role = scenario['actors']['owner']['fixture_role']
    scope = scenario['target'].get('required_scope')
    if producer_nf == actor_nf:
        role = owner_role
    else:
        role = f'{producer_nf.lower()}_1'
    svc = cfg['services'].get(role)
    if svc is None:
        raise ValueError(f"No lab fixture '{role}' configured for producer NF type '{producer_nf}'")
    adapter_overrides = SERVICE_BASE_PATH_BY_ADAPTER.get(cfg.get('core_adapter', 'free5gc'), {})
    base_path = adapter_overrides.get(service) or SERVICE_BASE_PATH.get(service)
    if base_path is None and adapter is not None and scope:
        base_path = adapter.discover_service_base_path(cfg, scope, producer_nf, role)
    if base_path is None:
        base_path = ''
    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
    base = f'{scheme}://{svc['host']}:{svc['port']}/{base_path}'
    path = path_tpl
    for var, val in path_vars.items():
        path = path.replace(f'{{{var}}}', str(val))
    if not path.startswith('/'):
        path = '/' + path
    return base + path
_MISSING = object()

def _get_nested(d: dict, dotted_path: str):
    for k in dotted_path.split('.'):
        if not isinstance(d, dict) or k not in d:
            return _MISSING
        d = d[k]
    return d

def _set_nested(d: dict, dotted_path: str, value) -> None:
    keys = dotted_path.split('.')
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value

def build_payload(request_spec: dict, ctx: dict, body_required: bool=False, empty_default: dict | list | None=None) -> dict | list | None:
    if request_spec['method'] in ('GET', 'DELETE'):
        return None
    if empty_default is None:
        empty_default = {}
    template = request_spec.get('payload_example')
    if template is None:
        return copy.deepcopy(empty_default) if body_required else None
    if not template:
        return copy.deepcopy(template)
    payload = copy.deepcopy(template)
    for field_path, ctx_key in FIELD_SEMANTICS.items():
        value = ctx.get(ctx_key)
        if value is None:
            continue
        if _get_nested(payload, field_path) is not _MISSING:
            _set_nested(payload, field_path, value)
    return payload

def build_query_params(request_spec: dict, ctx: dict) -> dict | None:
    template = request_spec.get('query_params_example') or {}
    if not template:
        return None
    params = copy.deepcopy(template)
    for name, ctx_key in QUERY_FIELD_SEMANTICS.items():
        if name not in params:
            continue
        value = ctx.get(ctx_key)
        if value is not None:
            params[name] = value
    return {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in params.items()}

def build_multipart(request_spec: dict, ctx: dict) -> tuple[bytes, str] | None:
    binary_parts = request_spec.get('binary_parts_example')
    if not binary_parts:
        return None
    built_payload = build_payload(request_spec, ctx)
    payload = built_payload if built_payload is not None else {}
    parts: list[tuple[dict, bytes]] = [({'Content-Type': 'application/json'}, json.dumps(payload).encode('utf-8'))]
    for name, part in binary_parts.items():
        content_type = part.get('content_type', 'application/octet-stream')
        content_id = part.get('content_id', name)
        data = bytes.fromhex(part.get('placeholder_hex', '00'))
        parts.append(({'Content-ID': content_id, 'Content-Type': content_type}, data))
    boundary = uuid.uuid4().hex
    body = _encode_multipart_related(parts, boundary)
    content_type_header = f'multipart/related; boundary="{boundary}"'
    return (body, content_type_header)

def _encode_multipart_related(parts: list[tuple[dict, bytes]], boundary: str) -> bytes:
    chunks: list[bytes] = []
    for headers, data in parts:
        chunks.append(f'--{boundary}\r\n'.encode())
        for key, value in headers.items():
            chunks.append(f'{key}: {value}\r\n'.encode())
        chunks.append(b'\r\n')
        chunks.append(data)
        chunks.append(b'\r\n')
    chunks.append(f'--{boundary}--\r\n'.encode())
    return b''.join(chunks)

def tls_kwargs(cfg: dict) -> dict:
    caps = cfg.get('capabilities', {})
    http2 = bool(caps.get('http2'))
    if not caps.get('mtls_required'):
        return {'cert': None, 'verify': True, 'http2': http2}
    cert_path, key_path = (caps.get('client_cert'), caps.get('client_key'))
    cert = (cert_path, key_path) if cert_path and key_path else None
    return {'cert': cert, 'verify': caps.get('ca_bundle') or True, 'http2': http2}

def request_attacker_token(cfg: dict, attacker_id: str, scope: str, target_nf_type: str, actor_nf_type: str, attacker_role: str, register: bool=True) -> tuple[str | None, dict | None]:
    tls = tls_kwargs(cfg)
    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
    nrf_svc = cfg['services']['nrf']
    nrf_url = f'{scheme}://{nrf_svc['host']}:{nrf_svc['port']}'
    if register and actor_nf_type.upper() == 'AMF':
        sbi_client.register_nf(nrf_url=nrf_url, nf_instance_id=attacker_id, nf_type=actor_nf_type, target_nf_type=target_nf_type, amf_id=cfg['services'][attacker_role]['amf_id'], **tls)
    return sbi_client.get_token(nrf_url=nrf_url, nf_instance_id=attacker_id, nf_type=actor_nf_type, target_nf_type=target_nf_type, scope=scope, **tls)
