import json
import re
from pathlib import Path
import rules
import openapi as openapi_loader
import ai_client
import schema_validate
import execution_hint
import operation_strategy

def enrich(partial: dict, specs_dir: Path, ai_config: dict, fixture_nf_types: set[str] | None=None) -> dict:
    attack_id = partial['attack_id']
    service = partial['service']
    method, path_suffix = _parse_endpoint(partial['endpoint_raw'])
    producer_nf, nf_reason = rules.get_producer_nf(service)
    spec = openapi_loader.resolve_spec(specs_dir, service)
    operation_id = None
    openapi_schema = {}
    query_params_schema = []
    path_params_schema = []
    header_params_schema = []
    scope = None
    op = None
    scope_reason = f"no OpenAPI spec found for service '{service}' under {specs_dir} — provide the 3GPP YAML or set required_scope manually"
    if spec is not None:
        scope = openapi_loader.get_service_scope(spec)
        scope_reason = "derived from the spec's servers[] URL" if scope else 'spec has no usable servers[] block'
        op = openapi_loader.find_operation(spec, method, path_suffix)
        if op:
            operation_id = op.get('operationId')
            openapi_schema = openapi_loader.get_request_body_schema(spec, op, specs_dir=specs_dir)
            query_params_schema = openapi_loader.get_query_params_schema(spec, op, specs_dir=specs_dir)
            path_params_schema = openapi_loader.get_path_params_schema(spec, op, specs_dir=specs_dir)
            header_params_schema = openapi_loader.get_header_params_schema(spec, op, specs_dir=specs_dir)
    runtime_strategy = operation_strategy.for_operation(service, operation_id)
    existing_protection_raw = partial['existing_protection']
    if isinstance(existing_protection_raw, dict):
        coverage = (existing_protection_raw.get('resource_binding') or {}).get('coverage', '')
        expected_vulnerable, vuln_reason = rules.classify_coverage(coverage)
        vuln_source = 'deterministic_coverage_rule'
    else:
        expected_vulnerable, vuln_reason = rules.detect_vulnerability_expectation(existing_protection_raw)
        vuln_source = 'deterministic_rule'
    vuln_confidence = 0.85 if expected_vulnerable is not None else 0.0
    if ai_config.get('api_key'):
        ai_vuln = ai_client.classify_vulnerability_expectation(existing_protection=_as_text(existing_protection_raw), test_idea=partial['test_idea'], expected_binding=_as_text(partial['expected_binding']), api_key=ai_config.get('api_key', ''), base_url=ai_config.get('base_url', 'https://api.openai.com/v1'), completions_path=ai_config.get('completions_path', '/chat/completions'))
        if ai_vuln and ai_vuln.get('confidence', 0.0) > 0.0:
            expected_vulnerable = ai_vuln['expected_vulnerable']
            vuln_reason = ai_vuln['reasoning']
            vuln_source = 'ai_classifier'
            vuln_confidence = ai_vuln['confidence']
    requester_types_all = partial.get('_requester_nf_types_all') or []
    hint = partial.get('_execution_hint')
    selected_consumer, fixture_selection_reason, fixture_selection_resolved = _select_configured_requester_nf(partial.get('nf_consumer', ''), requester_types_all, fixture_nf_types, preferred_requester=(hint or {}).get('requester_nf_type'))
    consumer_nf, consumer_reason = rules.validate_nf_consumer(selected_consumer)
    if fixture_selection_reason:
        consumer_reason += f' — {fixture_selection_reason}'
    _raw_alias = rules.RAW_CONSUMER_NF_ALIASES.get(selected_consumer)
    if fixture_nf_types is not None:
        configured_nf_types = {nf.upper() for nf in fixture_nf_types}
        if fixture_selection_resolved:
            _fixture_nf = consumer_nf or 'UNKNOWN'
        elif 'AMF' in configured_nf_types:
            _fixture_nf = 'AMF'
        else:
            _fixture_nf = consumer_nf or 'UNKNOWN'
    else:
        _fixture_nf = _raw_alias or rules.LAB_FIXTURE_NF_SUBSTITUTES.get(consumer_nf, consumer_nf) or 'UNKNOWN'
    requester_compatibility = _classify_requester_compatibility(requester_types=requester_types_all, hint_requester=(hint or {}).get('requester_nf_type'), selected_requester=selected_consumer, runtime_fixture=_fixture_nf, fixture_available=fixture_selection_resolved if fixture_nf_types is not None else None)
    if len(requester_types_all) > 1 and (not fixture_selection_resolved):
        consumer_reason += f" — expected_binding.requester_nf_types lists multiple types {requester_types_all}; no configured owner/attacker pair could be selected; using '{consumer_nf}', verify this is intended"
    MAX_VALIDATION_RETRIES = 2
    needs_ai = method not in ('GET', 'DELETE') or bool(query_params_schema)
    ai_result = None
    validation_errors: list[str] = []
    validation_attempts = 0
    binary_parts_meta = openapi_schema.get('_binary_parts_content_type') or {}
    if needs_ai:
        validation_schema = schema_validate.schema_for_request_validation(openapi_schema, op)
        raw_ai = None
        validation_feedback = None
        for attempt in range(1, MAX_VALIDATION_RETRIES + 2):
            validation_attempts = attempt
            print(f'  [AI] Requesting payload/query-params enrichment for {attack_id} ({method})' + (f' — retry {attempt - 1}/{MAX_VALIDATION_RETRIES} after validation failure' if attempt > 1 else '') + ' ...')
            raw_ai = ai_client.enrich_with_ai(service=service, method=method, path_template=path_suffix, test_idea=partial['test_idea'], expected_binding=_as_text(partial['expected_binding']), existing_protection=_as_text(existing_protection_raw), openapi_schema=openapi_schema, query_params_schema=query_params_schema, path_params_schema=path_params_schema, header_params_schema=header_params_schema, api_key=ai_config.get('api_key', ''), base_url=ai_config.get('base_url', 'https://api.openai.com/v1'), completions_path=ai_config.get('completions_path', '/chat/completions'), validation_feedback=validation_feedback, execution_hint=hint)
            if raw_ai:
                if raw_ai.get('payload_example'):
                    raw_ai['payload_example'] = _sanitize_payload(raw_ai['payload_example'], frozenset(_extract_path_vars(path_suffix)), frozenset(validation_schema.get('required') or []))
                    raw_ai['payload_example'] = _strip_unrequested_fields(raw_ai['payload_example'], frozenset(validation_schema.get('required') or []), hint, openapi_schema)
                    raw_ai['binary_parts_example'] = _drop_binary_parts_orphaned_by_field_removal(raw_ai['payload_example'], raw_ai.get('binary_parts_example'))
                if raw_ai.get('query_params_example'):
                    raw_ai['query_params_example'] = _sanitize_query_params(raw_ai['query_params_example'])
                    raw_ai['query_params_example'] = _filter_query_params_to_allowed(raw_ai['query_params_example'], query_params_schema, hint)
            if isinstance(openapi_schema, dict) and openapi_schema.get('type') == 'array' and (not ((hint or {}).get('body_required_fields') or (hint or {}).get('body_any_of_fields'))) and (not (raw_ai or {}).get('payload_example')):
                raw_ai = dict(raw_ai or {})
                raw_ai['payload_example'] = []
            if not ai_config.get('api_key'):
                validation_errors = []
                break
            validation_errors = schema_validate.validate_body(validation_schema, (raw_ai or {}).get('payload_example')) + schema_validate.validate_query_params(query_params_schema, (raw_ai or {}).get('query_params_example')) + execution_hint.check_conformance((raw_ai or {}).get('payload_example'), hint, (raw_ai or {}).get('query_params_example'))
            if binary_parts_meta and _referenced_content_ids((raw_ai or {}).get('payload_example')) and (not (raw_ai or {}).get('binary_parts_example')):
                validation_errors.append(f"binary_parts_example is missing/empty, but this operation's schema declares multipart binary parts ({sorted(binary_parts_meta.keys())}) — supply an entry for whichever of these payload_example actually references via a RefToBinaryData contentId (not necessarily every one)")
            orphaned_parts = _find_orphaned_binary_parts((raw_ai or {}).get('payload_example'), (raw_ai or {}).get('binary_parts_example'))
            if orphaned_parts:
                validation_errors.append(f"binary_parts_example includes {orphaned_parts}, but payload_example has no RefToBinaryData.contentId field matching its content_id — an orphaned multipart part free5GC rejects outright (400 'multipart binary data need Content-ID'); either add the matching contentId reference to payload_example or drop this part")
            if not validation_errors:
                break
            print(f'  [AI] Draft failed validation: {validation_errors}')
            validation_feedback = {'payload_example': (raw_ai or {}).get('payload_example'), 'query_params_example': (raw_ai or {}).get('query_params_example'), 'binary_parts_example': (raw_ai or {}).get('binary_parts_example'), 'errors': validation_errors}
        ai_result = raw_ai
    binary_parts_example = _build_binary_parts_example(binary_parts_meta, (ai_result or {}).get('binary_parts_example'))
    _raw_payload_example = (ai_result or {}).get('payload_example')
    if isinstance(_raw_payload_example, list):
        payload_fields = sorted({k for item in _raw_payload_example if isinstance(item, dict) for k in item})
    else:
        payload_fields = list((_raw_payload_example or {}).keys())
    payload_example = _raw_payload_example
    query_params_fields = list((ai_result or {}).get('query_params_example', {}).keys())
    query_params_example = (ai_result or {}).get('query_params_example') or None
    resource_type = partial['resource']
    known_resource = rules.is_known_resource_type(resource_type)
    resource_resolver = rules.RESOURCE_TO_RESOLVER.get(resource_type, 'UNKNOWN')
    spec = {'schema_version': '1.0', 'attack_id': attack_id, 'title': partial['title'], 'implementation_profile': 'free5gc_v4_2_3_lab', 'source_provenance': {'attack_catalog': partial.get('_source', 'AttacksList.md'), 'openapi_operation': f'{service} {method}' if operation_id else None, 'authorization_profile_batch': partial.get('_batch_id'), 'authorization_profile_fingerprint': partial.get('_input_fingerprint')}, 'target': {'producer_nf_type': producer_nf or 'UNKNOWN', 'service': service, 'operation_id': operation_id, 'method': method, 'path_template': path_suffix, 'required_scope': scope or 'UNKNOWN'}, 'security_property': {'type': 'resource_ownership_read' if partial['operation'] == 'read' else 'resource_ownership_write', 'statement': _statement_from_ai(ai_result) or _default_statement(partial)}, 'actors': {'owner': {'nf_type': _fixture_nf, 'fixture_role': f'{_fixture_nf.lower()}_1'}, 'attacker': {'nf_type': _fixture_nf, 'fixture_role': f'{_fixture_nf.lower()}_2'}}, 'resource': {'type': resource_type, 'identifier_variables': _extract_path_vars(path_suffix), 'resolver': resource_resolver, 'runtime_strategy': runtime_strategy, 'owner_evidence': _owner_evidence(resource_type, runtime_strategy)}, 'request': {'method': method, 'path_template': path_suffix, 'payload_fields': payload_fields, 'payload_example': payload_example, 'query_params_fields': query_params_fields, 'query_params_example': query_params_example, 'binary_parts_fields': list(binary_parts_meta.keys()), 'binary_parts_example': binary_parts_example, 'authorization': {'token_actor': 'attacker', 'target_nf_type': producer_nf or 'UNKNOWN', 'scope': scope or 'UNKNOWN'}}, 'preconditions': rules.get_default_preconditions(resource_type) + list((hint or {}).get('state_preconditions') or []), 'verdict': {'expected_vulnerable': expected_vulnerable, 'success_codes': [200, 201, 204], 'denial_codes': [401, 403]}}
    if partial.get('_source') == 'authorization_profiles.json':
        spec['spec_analysis'] = {'endpoint_id': partial.get('_endpoint_id'), 'schema_version': partial.get('_schema_version'), 'expected_binding': partial.get('expected_binding'), 'existing_protection': partial.get('existing_protection'), 'confidence': partial.get('_confidence'), 'evidence_refs': partial.get('_evidence_refs', [])}
        if partial.get('_case_id') is not None:
            spec['spec_analysis']['case_id'] = partial['_case_id']
            spec['spec_analysis']['case_index'] = partial.get('_case_index')
            spec['spec_analysis']['case_count'] = partial.get('_case_count')
        if hint is not None:
            spec['spec_analysis']['execution_hint'] = hint
        spec['spec_analysis']['requester_compatibility'] = requester_compatibility
    ai_confidence = (ai_result or {}).get('confidence', 0.0)
    schema_validation_failed = bool(validation_errors)
    annotations = {'required_scope': {'value': scope, 'source': 'derived_from_openapi' if scope else 'missing', 'confidence': 0.95 if scope else 0.0, 'review': scope is None, 'reason': scope_reason}, 'producer_nf_type': {'value': producer_nf, 'source': 'derived_from_service_prefix' if producer_nf else 'missing', 'confidence': 0.95 if producer_nf else 0.0, 'review': producer_nf is None, 'reason': nf_reason}, 'expected_vulnerable': {'value': expected_vulnerable, 'source': vuln_source, 'confidence': vuln_confidence, 'review': expected_vulnerable is None, 'reason': vuln_reason}, 'nf_consumer': {'value': consumer_nf, 'source': ('authorization_profiles+lab_config' if fixture_selection_resolved else partial.get('_source', 'attacks_list_md')) if consumer_nf else 'missing', 'confidence': 0.9 if consumer_nf else 0.0, 'review': consumer_nf is None or (len(requester_types_all) > 1 and (not fixture_selection_resolved)), 'reason': consumer_reason}, 'requester_compatibility': {'value': requester_compatibility['status'], 'source': 'authorization_profiles+execution_hint+lab_config', 'confidence': 1.0, 'review': requester_compatibility['status'] in {'HINT_REQUESTER_MISMATCH', 'HINT_REQUESTER_UNSPECIFIED', 'UNSUPPORTED_IN_LAB', 'UNSUPPORTED_IN_LAB_FALLBACK'}, 'reason': requester_compatibility['reason']}, 'openapi_operation_id': {'value': operation_id, 'source': 'openapi' if operation_id else 'missing', 'confidence': 0.99 if operation_id else 0.0, 'review': operation_id is None and spec is not None, 'reason': 'found in the OpenAPI spec' if operation_id else 'no OpenAPI spec available for this service' if spec is None else 'operation not found in the spec'}, 'resource_resolver': {'value': resource_resolver, 'source': 'deterministic_rule' if known_resource else 'missing', 'confidence': 0.9 if known_resource else 0.0, 'review': not known_resource, 'reason': 'resource type is in RESOURCE_TO_RESOLVER' if known_resource else f"resource type '{resource_type}' has no curated resolver strategy — add an entry to rules.RESOURCE_TO_RESOLVER and the matching runtime logic in stage_b/resolvers.py"}, 'preconditions': {'value': spec['preconditions'], 'source': 'deterministic_rule' if known_resource else 'baseline_only', 'confidence': 0.9 if known_resource else 0.0, 'review': not known_resource, 'reason': 'preconditions derived from the resource type' if known_resource else f"resource type '{resource_type}' is unknown — only the common baseline preconditions were applied; add an entry to rules.RESOURCE_PRECONDITIONS if this resource needs additional setup"}, 'payload': {'source': 'none_required' if method in ('GET', 'DELETE') else 'ai_inferred' if ai_confidence > 0 else 'missing', 'confidence': 1.0 if method in ('GET', 'DELETE') else 0.0 if schema_validation_failed else ai_confidence, 'review': method not in ('GET', 'DELETE') and (ai_confidence < 0.5 or schema_validation_failed), 'reason': 'no body required' if method in ('GET', 'DELETE') else f'still fails validation (schema and/or execution-hint conformance) after {validation_attempts} attempt(s): ' + '; '.join(validation_errors) if schema_validation_failed else (ai_result or {}).get('reasoning', '') or 'no AI configured — add one with --ai-key'}, 'query_params': {'source': 'none_required' if not query_params_schema else 'ai_inferred' if ai_confidence > 0 else 'missing', 'confidence': 1.0 if not query_params_schema else 0.0 if schema_validation_failed else ai_confidence, 'review': bool(query_params_schema) and (ai_confidence < 0.5 or schema_validation_failed), 'reason': 'no query parameters declared on this operation' if not query_params_schema else f'still fails validation (schema and/or execution-hint conformance) after {validation_attempts} attempt(s): ' + '; '.join(validation_errors) if schema_validation_failed else (ai_result or {}).get('reasoning', '') or 'no AI configured — add one with --ai-key'}, 'binary_parts': {'source': 'none_required' if not binary_parts_meta else 'ai_inferred' if binary_parts_example else 'missing', 'confidence': 1.0 if not binary_parts_meta else min(ai_confidence, 0.3) if binary_parts_example else 0.0, 'review': bool(binary_parts_meta), 'reason': 'no multipart/related binary parts declared on this operation' if not binary_parts_meta else "binary_parts_example filled with placeholder content_id/bytes — verify content_id matches payload_example's RefToBinaryData.contentId; the binary content itself is fake, not real protocol data" if binary_parts_example else f'operation declares multipart binary parts ({list(binary_parts_meta.keys())}) but no binary_parts_example was provided — fill in manually in the review file'}, 'execution_hint': {'source': 'none' if hint is None else 'schema_v1.2_service_hardened', 'confidence': 1.0 if hint is None else 0.0, 'review': hint is not None, 'reason': 'no execution_hint for this case (single-case endpoint, or not yet produced upstream)' if hint is None else (f"status='{hint.get('status')}' — this case additionally needs runtime state this pipeline cannot stage on its own ({'; '.join(hint.get('state_preconditions') or []) or 'see preconditions above'}); a conformant payload_example alone cannot guarantee this case is actually reached. " if execution_hint.needs_state_setup(hint) else '') + (f'payload_example still violates the hint after {validation_attempts} attempt(s): ' + '; '.join((v for v in validation_errors if v.startswith('execution hint:'))) if any((v.startswith('execution hint:') for v in validation_errors)) else 'payload_example satisfies every field-level constraint in the hint — verify state_preconditions/gaps below by hand before approving')}}
    needs_review = any((a.get('review', False) for a in annotations.values()))
    review_reasons = [f'  {field}: {a['reason']}' for field, a in annotations.items() if a.get('review', False)]
    return {'spec': spec, 'annotations': annotations, 'needs_review': needs_review, 'review_reasons': review_reasons}

def _declared_nf_type(requester: str) -> str | None:
    validated, _ = rules.validate_nf_consumer((requester or '').strip())
    return validated

def _select_configured_requester_nf(default_requester: str, requester_types: list[str], fixture_nf_types: set[str] | None, preferred_requester: str | None=None) -> tuple[str, str, bool]:
    if not requester_types or fixture_nf_types is None:
        return (default_requester, '', False)
    configured = {nf.upper() for nf in fixture_nf_types}
    preferred = (preferred_requester or '').upper()
    ordered_requesters = sorted(requester_types, key=lambda requester: 0 if str(requester).upper() == preferred else 1)
    for requester in ordered_requesters:
        declared_nf = _declared_nf_type(requester)
        if declared_nf and declared_nf.upper() in configured:
            selection_basis = 'execution-hint requester' if str(requester).upper() == preferred else 'first authorized requester'
            return (requester, f"selected '{requester}' as the {selection_basis} with configured '{declared_nf.lower()}_1'/'{declared_nf.lower()}_2' fixtures", True)
    return (default_requester, f'none of the authorized requester types {requester_types} has a configured owner/attacker fixture pair', False)

def _classify_requester_compatibility(requester_types: list[str], hint_requester: str | None, selected_requester: str | None, runtime_fixture: str | None, fixture_available: bool | None=None) -> dict:
    allowed = [str(value).upper() for value in requester_types if value]
    actual = (runtime_fixture or 'UNKNOWN').upper()
    selected = (selected_requester or 'UNKNOWN').upper()
    effective_hint = (hint_requester or '').upper()
    if not allowed:
        return {'status': 'NOT_APPLICABLE', 'expected_nf_types': [], 'hint_requester_nf_type': hint_requester, 'selected_requester_nf_type': selected_requester, 'runtime_fixture_nf_type': runtime_fixture, 'fallback_used': False, 'reason': 'No structured requester NF list is available for this legacy input.'}
    if not effective_hint and len(allowed) == 1:
        effective_hint = allowed[0]
    common = {'expected_nf_types': requester_types, 'hint_requester_nf_type': hint_requester or (requester_types[0] if len(allowed) == 1 else None), 'selected_requester_nf_type': selected_requester, 'runtime_fixture_nf_type': runtime_fixture, 'fallback_used': actual != selected}
    if actual not in allowed:
        return {**common, 'status': 'UNSUPPORTED_IN_LAB_FALLBACK', 'reason': f'No authorized requester fixture is available; {runtime_fixture or 'UNKNOWN'} is used as a best-effort fallback for {selected_requester or 'UNKNOWN'}. Runtime evidence is diagnostic only.'}
    if fixture_available is False:
        return {**common, 'status': 'UNSUPPORTED_IN_LAB', 'reason': f'No configured owner/attacker fixture pair is available for any authorized requester {requester_types}. The selected requester {selected_requester or 'UNKNOWN'} cannot be exercised by this lab.'}
    if not effective_hint and len(allowed) > 1:
        return {**common, 'status': 'HINT_REQUESTER_UNSPECIFIED', 'reason': 'The authorization case permits multiple requester NF types, but this legacy execution hint does not state which requester its variant was built for.'}
    if effective_hint and actual != effective_hint:
        return {**common, 'status': 'HINT_REQUESTER_MISMATCH', 'reason': f'The execution hint was built for {effective_hint}, while the lab selected {actual}. Both may be authorized, but payload/procedure equivalence is not established.'}
    return {**common, 'status': 'MATCHED', 'reason': f'The runtime requester {actual} matches the execution-hint requester.'}

def _parse_endpoint(endpoint_raw: str) -> tuple[str, str]:
    s = endpoint_raw.strip()
    match = re.match('^([A-Z]+)\\s*/?(.*)', s)
    if match:
        method = match.group(1).upper()
        path = '/' + match.group(2).lstrip('/')
        return (method, path)
    return ('UNKNOWN', '/' + s)

def _extract_path_vars(path: str) -> list[str]:
    return re.findall('\\{(\\w+)\\}', path)

def _default_statement(partial: dict) -> str:
    return f"An unauthorized NF must not be able to {partial['operation']} the resource '{partial['resource']}' belonging to another NF using only a service-level token for {partial['service']}. Expected binding: {_as_text(partial['expected_binding'])}"

def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    if not value:
        return ''
    return json.dumps(value, ensure_ascii=False)

def _statement_from_ai(ai_result: dict | None) -> str | None:
    if ai_result and ai_result.get('security_statement'):
        return ai_result['security_statement']
    return None

def _owner_evidence(resource_type: str, runtime_strategy: str=operation_strategy.GENERIC) -> dict:
    if runtime_strategy == operation_strategy.AMF_3GPP_REGISTRATION:
        return {'resolver': 'MONGO_LOOKUP', 'collection': 'subscriptionData.contextData.amf3gppAccess', 'key': 'ueId', 'description': 'The SUPI->AMF-1 binding must exist in MongoDB'}
    EVIDENCE = {'UE context': {'resolver': 'HTTP_PROBE', 'endpoint': 'GET /namf-comm/v1/ue-contexts/{ueContextId}', 'description': 'The UE context must exist on AMF-1 (200 response)'}, 'SM context': {'resolver': 'LOG_PARSE', 'container': 'smf', 'pattern': '/sm-contexts/(urn:uuid:[0-9a-f-]{36})', 'description': 'smContextRef is extracted from SMF logs with --tail 2000'}, 'SM Policy': {'resolver': 'DIRECT', 'description': 'smPolicyId is deterministic ("<supi>-<pduSessionId>") — confirmed live against PCF logs, no log parsing needed (see rules.py\'s RESOURCE_TO_RESOLVER SM_POLICY_DIRECT entry)'}, 'SMF registration': {'resolver': 'MONGO_LOOKUP', 'collection': 'subscriptionData.contextData.smfRegistrations', 'key': 'ueId', 'description': "The SUPI's SMF registration for the active PDU session must exist in MongoDB"}, 'AMF non-3GPP registration': {'resolver': 'MONGO_LOOKUP', 'collection': 'subscriptionData.contextData.amfNon3gppAccess', 'key': 'ueId', 'description': "The SUPI's non-3GPP AMF registration must exist in MongoDB"}}
    return EVIDENCE.get(resource_type, {'resolver': 'UNKNOWN', 'description': 'not mapped'})

def _sanitize_payload(payload, path_vars: frozenset[str]=frozenset(), required_fields: frozenset[str]=frozenset()):
    if isinstance(payload, list):
        return [_sanitize_payload(item, path_vars, required_fields) if isinstance(item, dict) else item for item in payload]
    result: dict = {}
    for k, v in payload.items():
        if k in path_vars and k not in required_fields:
            continue
        if isinstance(v, str) and v == k:
            continue
        if isinstance(v, dict):
            cleaned = _sanitize_payload(v, path_vars, required_fields)
            if cleaned:
                result[k] = cleaned
        else:
            result[k] = v
    return result

def _strip_unrequested_fields(payload, top_level_required: frozenset[str], hint: dict | None, full_schema: dict | None=None):
    if isinstance(full_schema, dict) and full_schema.get('type') == 'array':
        item_schema = full_schema.get('items') or {}
        item_required = frozenset(item_schema.get('required') or [])
        if not isinstance(payload, list):
            return payload
        return [_strip_unrequested_fields(item, item_required, hint, item_schema) if isinstance(item, dict) else item for item in payload]
    hint = hint or {}
    positive = list(hint.get('body_required_fields') or []) + list(hint.get('body_any_of_fields') or [])
    absent = list(hint.get('body_absent_fields') or [])
    allowed_top = set(top_level_required) | {f.split('.')[0] for f in positive} | {f.split('.')[0] for f in absent}
    nested_positive_by_prefix: dict[str, set[str]] = {}
    for f in positive:
        if '.' in f:
            prefix, rest = f.split('.', 1)
            nested_positive_by_prefix.setdefault(prefix, set()).add(rest.split('.')[0])
    nested_absent_by_prefix: dict[str, set[str]] = {}
    for f in absent:
        if '.' in f:
            prefix, rest = f.split('.', 1)
            nested_absent_by_prefix.setdefault(prefix, set()).add(rest.split('.')[0])
    properties = (full_schema or {}).get('properties') or {}
    result: dict = {}
    for k, v in payload.items():
        if k not in allowed_top:
            continue
        if isinstance(v, dict):
            nested_schema_required = set((properties.get(k) or {}).get('required') or [])
            nested_allowed = nested_schema_required | nested_positive_by_prefix.get(k, set()) | nested_absent_by_prefix.get(k, set())
            v = {nk: nv for nk, nv in v.items() if nk in nested_allowed}
        result[k] = v
    return result

def _filter_query_params_to_allowed(params: dict, query_params_schema: list[dict] | None, hint: dict | None) -> dict:
    hint = hint or {}
    schema_required = {p['name'] for p in query_params_schema or [] if p.get('required')}
    positive = set(hint.get('query_required_fields') or []) | set(hint.get('query_any_of_fields') or [])
    absent = set(hint.get('query_absent_fields') or [])
    allowed = schema_required | positive | absent
    return {k: v for k, v in params.items() if k in allowed}

def _drop_binary_parts_orphaned_by_field_removal(payload_example: dict, binary_parts_example: dict | None) -> dict | None:
    if not binary_parts_example:
        return binary_parts_example
    referenced = _referenced_content_ids(payload_example)
    return {name: part for name, part in binary_parts_example.items() if isinstance(part, dict) and part.get('content_id') in referenced}

def _referenced_content_ids(payload_example) -> set[str]:
    found: set[str] = set()

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == 'contentId' and isinstance(v, str):
                    found.add(v)
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
    _walk(payload_example)
    return found

def _find_orphaned_binary_parts(payload_example, binary_parts_example: dict | None) -> list[str]:
    if not binary_parts_example:
        return []
    referenced = _referenced_content_ids(payload_example)
    return [name for name, part in binary_parts_example.items() if isinstance(part, dict) and part.get('content_id') not in referenced]

def _build_binary_parts_example(binary_parts_meta: dict, ai_binary_parts: dict | None) -> dict | None:
    if not binary_parts_meta or not ai_binary_parts:
        return None
    result = {}
    for name, part in ai_binary_parts.items():
        if name not in binary_parts_meta or not isinstance(part, dict):
            continue
        result[name] = {'content_type': binary_parts_meta[name], 'content_id': part.get('content_id', f'{name}_ref'), 'placeholder_hex': part.get('placeholder_hex', '00')}
    return result or None

def _sanitize_query_params(params: dict) -> dict:
    return {k: v for k, v in params.items() if not (isinstance(v, str) and v == k)}
