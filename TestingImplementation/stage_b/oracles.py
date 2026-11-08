import sbi_client
import response_signature
import operation_strategy
CONFIRMED = 'CONFIRMED_VULNERABILITY'
SECURE = 'SECURE'
ROBUSTNESS = 'ROBUSTNESS_BUG'
NOT_IMPLEMENTED = 'NOT_IMPLEMENTED'
SETUP_FAIL = 'SETUP_FAILURE'
INCONCLUSIVE = 'INCONCLUSIVE'
CROSS_OWNER_REQUEST_ACCEPTED = 'CROSS_OWNER_REQUEST_ACCEPTED'
CONCRETE_EFFECT_CONFIRMED = 'CONCRETE_EFFECT_CONFIRMED'
_RELEASE_LOG_NEEDLE_BY_ADAPTER = {'free5gc': lambda sm_ref, supi: f'smContext[{sm_ref}] is deleted from pool' if sm_ref else None, 'open5gs': lambda sm_ref, supi: f'Removed Session: UE IMSI:[{supi}]' if supi else None}

def _has_disclosed_data(value):
    if isinstance(value, dict):
        return any((_has_disclosed_data(child) for child in value.values()))
    if isinstance(value, list):
        return any((_has_disclosed_data(child) for child in value))
    if isinstance(value, str):
        return bool(value.strip()) and value not in {'imsi-', 'msisdn-', 'extid-', 'nai-', 'gci-', 'gli-'}
    return value is not None

def security_findings(scenario: dict, resp, verdict: str) -> list[str]:
    if resp is None:
        return []
    status = resp.status_code
    success_codes = (scenario.get('verdict') or {}).get('success_codes') or []
    findings = []
    if status in success_codes:
        findings.append(CROSS_OWNER_REQUEST_ACCEPTED)
    if verdict == CONFIRMED:
        findings.append(CONCRETE_EFFECT_CONFIRMED)
    return findings

def needs_owner_control_check(scenario: dict) -> bool:
    resource_type = (scenario.get('resource') or {}).get('type')
    method = (scenario.get('target') or {}).get('method')
    return not (operation_strategy.for_scenario(scenario) == operation_strategy.AMF_3GPP_REGISTRATION and method in ('PUT', 'PATCH') or (resource_type == 'AMF non-3GPP registration' and method in ('PUT', 'PATCH')) or (resource_type == 'SMF registration' and method in ('PUT', 'PATCH', 'DELETE')))

def extract_cause(body) -> str | None:
    if not isinstance(body, dict):
        return None
    for candidate in (body, body.get('error'), (body.get('jsonData') or {}).get('error')):
        if isinstance(candidate, dict) and candidate.get('cause'):
            return candidate['cause']
    return None

def evaluate(scenario: dict, resp, pre_evidence: dict, post_evidence: dict, resources: dict, owner_control: dict | None=None, request_body=None, core_adapter: str='free5gc') -> tuple[str, str]:
    resource_type = scenario['resource']['type']
    if resource_type == 'SUPI' and operation_strategy.for_scenario(scenario) != operation_strategy.AMF_3GPP_REGISTRATION:
        resource_type = 'SUPI-addressed resource'
    method = scenario['target']['method']
    path_template = scenario['target']['path_template']
    success_codes = scenario['verdict']['success_codes']
    denial_codes = scenario['verdict']['denial_codes']
    status = resp.status_code if resp is not None else None
    if status is None:
        return (INCONCLUSIVE, 'No response (connection failed or timed out)')
    if status in denial_codes:
        attacker_cause = extract_cause(_safe_body(resp))
        return _evaluate_denial(resource_type, method, status, pre_evidence, post_evidence, resources, owner_control, attacker_cause)
    if status >= 500:
        if status == 501 and response_signature.classify(resp).get('kind') == 'empty_body':
            return (NOT_IMPLEMENTED, f'HTTP {status} — operation not implemented in this core (empty stub response), no ownership check could ever run')
        return (ROBUSTNESS, f'HTTP {status} — server error (5xx), no ownership bypass demonstrated')
    if status in success_codes:
        return _evaluate_success(resource_type, method, path_template, status, resp, pre_evidence, post_evidence, resources, request_body, core_adapter)
    return (INCONCLUSIVE, f'HTTP {status} — unclassifiable status code (expected: success={success_codes}, denial={denial_codes})')

def _evaluate_denial(resource_type, method, status, pre_ev, post_ev, resources, owner_control=None, attacker_cause=None):
    if resource_type in ('SUPI', 'AMF non-3GPP registration') and method in ('PUT', 'PATCH'):
        pre_amf = (pre_ev.get('binding') or {}).get('amfInstanceId')
        post_amf = (post_ev.get('binding') or {}).get('amfInstanceId')
        if pre_amf and post_amf and (pre_amf == post_amf):
            return (SECURE, f'HTTP {status} + {resource_type} binding unchanged -> ownership check is in place')
        if pre_amf and post_amf and (pre_amf != post_amf):
            return (INCONCLUSIVE, f'HTTP {status} but {resource_type} binding changed — inconsistent state')
        return (SECURE, f'HTTP {status} — request explicitly denied')
    if resource_type == 'SMF registration' and method in ('PUT', 'PATCH'):
        pre_smf = (pre_ev.get('binding') or {}).get('smfInstanceId')
        post_smf = (post_ev.get('binding') or {}).get('smfInstanceId')
        if pre_smf and post_smf and (pre_smf == post_smf):
            return (SECURE, f'HTTP {status} + SMF registration unchanged -> ownership check is in place')
        if pre_smf and post_smf and (pre_smf != post_smf):
            return (INCONCLUSIVE, f'HTTP {status} but SMF registration changed — inconsistent state')
        return (SECURE, f'HTTP {status} — request explicitly denied')
    if resource_type == 'SMF registration' and method == 'DELETE':
        pre_present = bool(pre_ev.get('binding'))
        post_present = bool(post_ev.get('binding'))
        if pre_present and post_present:
            return (SECURE, f'HTTP {status} + SMF registration still present -> ownership check is in place')
        if pre_present and (not post_present):
            return (INCONCLUSIVE, f'HTTP {status} but the SMF registration was removed — inconsistent state')
        return (SECURE, f'HTTP {status} — request explicitly denied')
    if owner_control is not None and owner_control.get('ok'):
        oc_status = owner_control.get('status_code')
        oc_cause = owner_control.get('cause')
        if oc_status is not None and oc_status < 300:
            return (SECURE, f'HTTP {status} + owner-control confirmed: the identical request succeeds for the legitimate owner (HTTP {oc_status}) — ownership check is in place')
        if oc_status == status and oc_cause and attacker_cause and (oc_cause == attacker_cause):
            return (INCONCLUSIVE, f"HTTP {status} but the legitimate owner's IDENTICAL request was ALSO denied (HTTP {oc_status}, cause: {oc_cause}) — this denial does not demonstrate an ownership check; likely a state precondition or payload-validity issue unrelated to caller identity (see needs_owner_control_check())")
        if oc_status == status:
            return (INCONCLUSIVE, f"HTTP {status} but the legitimate owner's IDENTICAL request was ALSO denied with the same status (HTTP {oc_status}) — owner-control could not confirm this is an ownership check rather than a shared precondition/validation failure (causes: attacker={attacker_cause!r}, owner={oc_cause!r})")
        return (SECURE, f'HTTP {status} — request explicitly denied (ownership check is in place); owner-control got a different result (HTTP {oc_status}, cause: {oc_cause})')
    if owner_control is not None and (not owner_control.get('ok')):
        return (SECURE, f'HTTP {status} — request explicitly denied (ownership check is in place); owner-control check could not be run ({owner_control.get('error')})')
    return (SECURE, f'HTTP {status} — request explicitly denied (ownership check is in place)')

def _json_patch_pointer_get(doc: dict, pointer: str):
    node = doc
    for raw_segment in pointer.lstrip('/').split('/'):
        if not raw_segment:
            continue
        segment = raw_segment.replace('~1', '/').replace('~0', '~')
        if not isinstance(node, dict) or segment not in node:
            return (False, None)
        node = node[segment]
    return (True, node)

def _json_patch_effect(request_body, pre_doc: dict, post_doc: dict) -> str | None:
    if not isinstance(request_body, list):
        return None
    for entry in request_body:
        if not isinstance(entry, dict):
            continue
        pointer = entry.get('path')
        if not isinstance(pointer, str) or not pointer:
            continue
        pre_found, pre_val = _json_patch_pointer_get(pre_doc or {}, pointer)
        post_found, post_val = _json_patch_pointer_get(post_doc or {}, pointer)
        if pre_found != post_found or pre_val != post_val:
            pre_repr = pre_val if pre_found else '<absent>'
            post_repr = post_val if post_found else '<absent>'
            return f'{pointer}: {pre_repr!r} -> {post_repr!r}'
    return None

def _dict_diff(pre, post, max_fields: int=3) -> str | None:
    if pre == post:
        return None
    if not (isinstance(pre, dict) and isinstance(post, dict)):
        return f'<root>: {pre!r} -> {post!r}'
    changed = []
    for key in sorted(set(pre) | set(post)):
        pre_val, post_val = (pre.get(key, '<absent>'), post.get(key, '<absent>'))
        if pre_val != post_val:
            changed.append(f'{key}: {pre_val!r} -> {post_val!r}')
    return '; '.join(changed[:max_fields]) if changed else f'<root>: {pre!r} -> {post!r}'

def _evaluate_success(resource_type, method, path_template, status, resp, pre_ev, post_ev, resources, request_body=None, core_adapter: str='free5gc'):
    if method == 'GET':
        body = _safe_body(resp)
        if isinstance(body, (dict, list)) and _has_disclosed_data(body):
            return (CONFIRMED, f'HTTP {status} + structured data exposed to a non-owner')
        return (INCONCLUSIVE, f'HTTP {status}: cross-owner GET accepted, but no substantive response content was returned — disclosure not verified')
    if resource_type in ('SUPI', 'AMF non-3GPP registration') and method in ('PUT', 'PATCH'):
        pre_binding = pre_ev.get('binding')
        post_binding = post_ev.get('binding')
        if pre_binding is None:
            return (SETUP_FAIL, f'{resource_type} binding missing before the attack — subscriber not provisioned')
        if post_binding is None:
            return (INCONCLUSIVE, f'HTTP {status} but post-attack state could not be read from MongoDB')
        pre_amf = pre_binding.get('amfInstanceId', '')
        post_amf = post_binding.get('amfInstanceId', '')
        owner_id = resources.get('amf1_id', '')
        attacker_id = resources.get('attacker_id', '')
        if method == 'PUT':
            if post_amf == attacker_id:
                return (CONFIRMED, f'HTTP {status} + {resource_type} binding changed: owner({owner_id[:8]}...) -> attacker({attacker_id[:8]}...) [GUAMI: {post_binding.get('guami', {}).get('amfId', '?')}]')
            if post_amf == pre_amf:
                return (INCONCLUSIVE, f'HTTP {status} accepted but binding unchanged ({post_amf[:8]}...) — side effect not verified')
            return (INCONCLUSIVE, f'HTTP {status} + binding changed to an unexpected value ({post_amf[:8]}...)')
        if method == 'PATCH':
            pre_guami = pre_binding.get('guami', {}).get('amfId', '?')
            post_guami = post_binding.get('guami', {}).get('amfId', '?')
            pre_purge = pre_binding.get('purgeFlag')
            post_purge = post_binding.get('purgeFlag')
            if post_amf == pre_amf and post_guami == pre_guami and (post_purge == pre_purge):
                patch_detail = _json_patch_effect(request_body, pre_binding, post_binding)
                if patch_detail:
                    return (CONFIRMED, f'HTTP {status} + {resource_type} binding modified via JSON-Patch with no ownership check ({patch_detail})')
                return (INCONCLUSIVE, f'HTTP {status} accepted but binding unchanged — positive response with no state change')
            if post_purge != pre_purge and post_amf == pre_amf and (post_guami == pre_guami):
                return (CONFIRMED, f'HTTP {status} + {resource_type} binding purgeFlag modified with no GUAMI check (purgeFlag: {pre_purge} -> {post_purge})')
            return (CONFIRMED, f'HTTP {status} + {resource_type} binding modified with no GUAMI check (GUAMI: {pre_guami} -> {post_guami})')
    if resource_type == 'SMF registration' and method in ('PUT', 'PATCH'):
        pre_binding = pre_ev.get('binding')
        post_binding = post_ev.get('binding')
        if pre_binding is None:
            return (SETUP_FAIL, 'SMF registration missing before the attack — no active PDU session for this SUPI')
        if post_binding is None:
            return (INCONCLUSIVE, f'HTTP {status} but post-attack state could not be read from MongoDB')
        pre_smf = pre_binding.get('smfInstanceId', '')
        post_smf = post_binding.get('smfInstanceId', '')
        owner_id = resources.get('owner_id', '')
        attacker_id = resources.get('attacker_id', '')
        if post_smf == attacker_id:
            return (CONFIRMED, f'HTTP {status} + SMF registration changed: owner({owner_id[:8]}...) -> attacker({attacker_id[:8]}...)')
        if post_smf == pre_smf:
            return (INCONCLUSIVE, f'HTTP {status} accepted but SMF registration unchanged ({post_smf[:8]}...) — side effect not verified')
        return (INCONCLUSIVE, f'HTTP {status} + SMF registration changed to an unexpected value ({post_smf[:8]}...)')
    if resource_type == 'SMF registration' and method == 'DELETE':
        pre_binding = pre_ev.get('binding')
        post_binding = post_ev.get('binding')
        if pre_binding is None:
            return (SETUP_FAIL, 'SMF registration missing before the attack — no active PDU session for this SUPI')
        if post_binding is None:
            return (CONFIRMED, f'HTTP {status} + SMF registration removed by a non-owning SMF')
        return (INCONCLUSIVE, f'HTTP {status} accepted but the SMF registration is still present in MongoDB — side effect not verified')
    if resource_type == 'UE context':
        context_present_before = pre_ev.get('ue_context_present', False)
        supi = resources.get('supi', '')
        if not context_present_before:
            return (INCONCLUSIVE, f'HTTP {status} but the UE context was not proven present before the attack — requires UERANSIM with a registered UE')
        if path_template.rstrip('/').endswith('/assign-ebi'):
            body = _safe_body(resp)
            effect_fields = ('assignedEbiList', 'releasedEbiList', 'modifiedEbiList')
            observed_effects = {field: body.get(field) for field in effect_fields if isinstance(body, dict) and isinstance(body.get(field), list) and body.get(field)}
            if observed_effects:
                return (CONFIRMED, f'HTTP {status} + assign-ebi response confirms a concrete EBI effect ({', '.join(observed_effects)}) on the live UE context (SUPI: {supi})')
            return (INCONCLUSIVE, f'HTTP {status}: cross-owner assign-ebi request accepted on a live UE context, but the response contains no non-empty assigned/released/modified EBI list — concrete effect not verified')
        pre_lines = set((pre_ev.get('amf_logs') or '').splitlines())
        post_lines = set((post_ev.get('amf_logs') or '').splitlines())
        new_lines = post_lines - pre_lines
        operation = path_template.rstrip('/').rsplit('/', 1)[-1]
        if method == 'POST' and operation == 'n1-n2-messages':
            if any(('Send Downlink Nas Transport' in line for line in new_lines)):
                return (CONFIRMED, f'HTTP {status} + new AMF log confirms downlink NAS transmission')
        elif method == 'POST' and operation == 'subscriptions' and (status == 201):
            body = _safe_body(resp)
            if isinstance(body, dict) and _has_disclosed_data(body.get('n1n2NotifySubscriptionId')):
                return (CONFIRMED, f'HTTP {status} + server-assigned N1N2 subscription ID returned')
        elif method == 'POST' and operation == 'provide-loc-info':
            body = _safe_body(resp)
            if isinstance(body, dict) and _has_disclosed_data(body.get('location')):
                return (CONFIRMED, f'HTTP {status} + UE location data exposed to a non-owner')
        elif method == 'POST' and operation == 'release' and supi and any((f'AmfUe[{supi}] is removed' in line for line in new_lines)):
            return (CONFIRMED, f'HTTP {status} + AMF logs confirm UE context removal (SUPI: {supi})')
        return (INCONCLUSIVE, f'HTTP {status}: cross-owner {method} accepted on a live UE context, but no operation-specific effect was verified; context existence and handler receipt are not sufficient')
    if resource_type == 'SM context' and path_template.rstrip('/').endswith('/release'):
        pre_smf_set = set((pre_ev.get('smf_logs') or '').splitlines())
        post_smf_set = set((post_ev.get('smf_logs') or '').splitlines())
        new_lines = post_smf_set - pre_smf_set
        sm_ref = resources.get('smContextRef', '')
        supi = resources.get('supi', '')
        needle = _RELEASE_LOG_NEEDLE_BY_ADAPTER.get(core_adapter, _RELEASE_LOG_NEEDLE_BY_ADAPTER['free5gc'])(sm_ref, supi)
        evidence = [line for line in new_lines if needle and needle in line]
        if evidence:
            return (CONFIRMED, f'HTTP {status} + SMF logs confirm SM context release (deletion of the addressed context {sm_ref})')
        return (INCONCLUSIVE, f'HTTP {status} but SMF logs show no evidence of release (smContextRef: {(sm_ref[:30] if sm_ref else 'N/A')}...)')
    if method in ('PUT', 'PATCH', 'DELETE') and pre_ev.get('binding_source') == 'standard_get_generic':
        pre_doc = pre_ev.get('binding')
        post_doc = post_ev.get('binding')
        if pre_doc is None and method in ('PUT', 'PATCH') and pre_ev.get('binding_confirmed_absent') and post_doc:
            return (CONFIRMED, f'HTTP {status} + resource created by a non-owner with no ownership check (confirmed via GET read-back: confirmed absent before, now present: {post_doc!r})')
        if pre_doc is None:
            pass
        elif method == 'DELETE':
            if post_doc is None:
                if post_ev.get('binding_confirmed_absent'):
                    return (CONFIRMED, f'HTTP {status} + resource removed by a non-owner with no ownership check (confirmed via GET read-back: present before, gone after)')
                return (INCONCLUSIVE, f'HTTP {status} accepted but the post-attack GET did not establish absence — side effect not verified')
            return (INCONCLUSIVE, f'HTTP {status} accepted but the resource is still present via GET read-back — side effect not verified')
        elif post_doc is not None:
            diff = _dict_diff(pre_doc, post_doc)
            if diff:
                return (CONFIRMED, f'HTTP {status} + resource modified by a non-owner with no ownership check (confirmed via GET read-back: {diff})')
            return (INCONCLUSIVE, f'HTTP {status} accepted but GET read-back shows no change — side effect not verified')
    return (INCONCLUSIVE, f"HTTP {status}: cross-owner {method} accepted for resource.type '{resource_type}', but no concrete state change or effect-specific evidence was observed")

def _safe_body(resp):
    body = sbi_client.parse_json_response(resp)
    return body if isinstance(body, (dict, list)) else None
