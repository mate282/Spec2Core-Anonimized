import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
import yaml
_SHARED_DIR = Path(__file__).resolve().parent
if str(_SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(_SHARED_DIR))
import openapi as openapi_loader
SPECS_DIR = _SHARED_DIR.parent.parent / 'docs' / 'specs'
_SCENARIO_CODE_RE = re.compile('^(S\\d+)_')
_CASE_SUFFIX_RE = re.compile('_([a-z]+)$')
_SCENARIO_NUM_RE = re.compile('^S(\\d+)')

def _scenario_sort_key(scenario_id: str) -> tuple[int, str, str]:
    m = _SCENARIO_NUM_RE.match(scenario_id)
    num = int(m.group(1)) if m else -1
    case_m = _CASE_SUFFIX_RE.search(scenario_id)
    suffix = case_m.group(1) if case_m else ''
    return (num, suffix, scenario_id)
_VERDICT_LABEL = {'CONFIRMED_VULNERABILITY': '[CONFIRMED_VULNERABILITY]', 'SECURE': '[SECURE]', 'ROBUSTNESS_BUG': '[ROBUSTNESS_BUG]', 'NOT_IMPLEMENTED': '[NOT_IMPLEMENTED]', 'SETUP_FAILURE': '[SETUP_FAILURE]', 'INCONCLUSIVE': '[INCONCLUSIVE]'}
_VERDICT_BUCKET = {'CONFIRMED_VULNERABILITY': 'vulnerable', 'SECURE': 'secure', 'ROBUSTNESS_BUG': 'problem', 'NOT_IMPLEMENTED': 'problem', 'SETUP_FAILURE': 'problem', 'INCONCLUSIVE': 'problem'}

def scenario_folder_name(scenario_id: str) -> str:
    m = _SCENARIO_CODE_RE.match(scenario_id)
    code = m.group(1) if m else scenario_id
    case_m = _CASE_SUFFIX_RE.search(scenario_id)
    if case_m:
        code = f'{code}_{case_m.group(1)}'
    return code

def write_report(result: dict, results_dir: Path) -> Path:
    run_dir = results_dir / scenario_folder_name(result['scenario_id'])
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_markdown(result, run_dir / 'report.md')
    _write_json(result, run_dir / 'evidence.json')
    return run_dir

def _write_markdown(result: dict, path: Path) -> None:
    sid = result['scenario_id']
    verdict = result['verdict']
    reason = result['verdict_reason']
    label = _VERDICT_LABEL.get(verdict, f'[{verdict}]')
    lines = [f'# Security Test Report — {sid}', f'', f'**Run ID:** `{result['run_id']}`', f'**Timestamp:** {result['timestamp']}', f'**Verdict:** {label}', f'']
    spec_analysis = result.get('scenario', {}).get('spec_analysis') or {}
    case_id = spec_analysis.get('case_id')
    if case_id is not None:
        case_index = spec_analysis.get('case_index')
        case_count = spec_analysis.get('case_count')
        lines += [f'**Authorization case:** `{case_id}` ({(case_index or 0) + 1} of {case_count} for this endpoint)', f'']
    lines += [f'> {reason}', f'', '## Runtime security observations', '', f'- Cross-owner request accepted: `{'CROSS_OWNER_REQUEST_ACCEPTED' in (result.get('security_findings') or [])}`', f'- Concrete effect confirmed: `{'CONCRETE_EFFECT_CONFIRMED' in (result.get('security_findings') or [])}`', '', f'---', f'']
    target = result.get('scenario', {}).get('target', {})
    if target:
        lines += ['## Target', '', '| Attribute | Value |', '|---|---|', f'| Service | `{target.get('service', '?')}` |', f'| Method | `{target.get('method', '?')}` |', f'| Path template | `{target.get('path_template', '?')}` |', f'| Producer NF | `{target.get('producer_nf_type', '?')}` |', f'| OAuth2 scope | `{target.get('required_scope', '?')}` |', '']
    setup = result.get('setup', {})
    lines += ['## Setup', '', f'- Lab healthy: `{setup.get('lab_healthy', '?')}`', f'- Subscriber provisioned: `{setup.get('subscriber_provisioned', '?')}`']
    if setup.get('error'):
        lines.append(f'- Error: {setup['error']}')
    dep = setup.get('dependency')
    if dep:
        if dep.get('error'):
            lines.append(f'- Dependency `{dep.get('scenario', '?')}`: **failed** — {dep['error']} (continued anyway)')
        else:
            lines.append(f'- Dependency `{dep.get('scenario', '?')}`: fired first, HTTP `{dep.get('status_code', '?')}`')
    lines.append('')
    extraction = setup.get('extraction_agent')
    if extraction:
        lines += ['## Extraction agent (prototype)', '', '| Variable | Static value | Agent value | Match | Confidence |', '|---|---|---|---|---|']
        for var, cmp in extraction.items():
            if cmp.get('fallback'):
                static_display = '*(none — no curated resolver, agent-only fallback)*'
                match = '✅' if cmp.get('agent_resolved') else '❌'
            else:
                static_display = f'`{cmp.get('static_value')}`'
                match = '✅' if cmp.get('match') else '❌' if cmp.get('match') is False else '—'
            lines.append(f'| `{var}` | {static_display} | `{cmp.get('agent_value')}` | {match} | {cmp.get('agent_confidence', 0):.2f} |')
            if cmp.get('agent_reasoning'):
                lines.append(f'  - Agent reasoning: {cmp['agent_reasoning']}')
        lines.append('')
    else:
        resolver = (result.get('scenario', {}).get('resource', {}) or {}).get('resolver', '?')
        lines += ['## Extraction agent (prototype)', '', f"- Not invoked for this run: `{sid}`'s identifier variable(s) resolved via the curated `{resolver}` resolver, with no uncurated variable falling back to the agent (see `stage_b/resolvers.py::resolve_path_variables()`). Re-run with `--resolution-mode compare` or `agent` (plus `--ai-key`) to see the agent's reasoning alongside the static resolver's value even when they'd agree.", '']
    resources = result.get('resources', {})
    if resources:
        lines += ['## Resources', '']
        for k, v in resources.items():
            display = str(v)
            if len(display) > 50:
                display = display[:20] + '…' + display[-10:]
            lines.append(f'- `{k}`: `{display}`')
        lines.append('')
    controls = result.get('controls', {})
    if controls:
        lines += ['## Controls', '']
        mt = controls.get('missing_token')
        if mt is not None:
            expected = '401/403'
            note = 'OK' if mt in (401, 403) else 'UNEXPECTED'
            lines.append(f'- Missing token control: HTTP `{mt}` (expected {expected}) — {note}')
        lines.append('')
    attack = result.get('attack', {})
    req = attack.get('request', {})
    resp = attack.get('response', {})
    lines += ['## Attack Request', '', f'- Method: `{req.get('method', '?')}`', f'- URL: `{req.get('url', '?')}`']
    if req.get('params'):
        lines.append(f'- Query params: `{req['params']}`')
    if req.get('body'):
        lines += ['- Body (full, as actually sent — see evidence.json for the same data):', '```json', json.dumps(req['body'], indent=2, ensure_ascii=False), '```']
    lines.append('')
    lines += ['## Attack Response', '']
    if resp:
        lines.append(f'- Status: `{resp.get('status_code', '?')}`')
        body = resp.get('body')
        if body is not None:
            if isinstance(body, str):
                lines.append(f'- Body: `{body}`')
            else:
                lines += ['- Body:', '```json', json.dumps(body, indent=2, ensure_ascii=False), '```']
    lines.append('')
    owner_control = attack.get('owner_control')
    if owner_control is not None:
        lines += ['## Owner-Control Check', '']
        if owner_control.get('ok'):
            lines.append(f"- Owner's request: `HTTP {owner_control.get('status_code')}`" + (f' (cause: `{owner_control['cause']}`)' if owner_control.get('cause') else ''))
            if owner_control.get('request_body'):
                lines += ['- Owner request body (full):', '```json', json.dumps(owner_control['request_body'], indent=2, ensure_ascii=False), '```']
        else:
            lines.append(f'- Owner-control check could not be run: {owner_control.get('error')}')
        lines.append('')
    evidence = result.get('evidence', {})
    pre = evidence.get('pre', {})
    post = evidence.get('post', {})
    lines += ['## Evidence', '']
    if pre.get('binding'):
        b = pre['binding']
        lines.append(f'- Pre-attack binding: amfId=`{b.get('guami', {}).get('amfId', '?')}`, amfInstanceId=`{str(b.get('amfInstanceId', '?'))[:16]}…`')
    if post.get('binding'):
        b = post['binding']
        lines.append(f'- Post-attack binding: amfId=`{b.get('guami', {}).get('amfId', '?')}`, amfInstanceId=`{str(b.get('amfInstanceId', '?'))[:16]}…`')
    if pre.get('ue_context_present') is not None:
        lines.append(f'- UE context present (pre-attack): `{pre['ue_context_present']}`')
    for log_key, label in [('amf_logs_excerpt', 'AMF'), ('smf_logs_excerpt', 'SMF')]:
        excerpt = evidence.get(log_key, '')
        if excerpt and excerpt.strip():
            lines += [f'', f'### {label} Log Excerpt', '```', excerpt.strip(), '```']
    lines.append('')
    restore = result.get('restore', {})
    lines += ['## Restore', '', f'- Strategy: `{restore.get('strategy', '?')}`', f'- Success: `{restore.get('success', '?')}`']
    if restore.get('error'):
        lines.append(f'- Error: {restore['error']}')
    lines.append('')
    lines += ['## Stage C', '', "This file (`report.md`) only covers Stage B's execution. For the spec-vs-runtime comparison and the full deterministic + AI reasoning behind the final verdict, see `stage_c_analysis.md` (or `.json`) in this same results folder, written by `stage_c.py`."]
    path.write_text('\n'.join(lines), encoding='utf-8')

def _redact(text: str) -> str:
    text = re.sub('Bearer [A-Za-z0-9._\\-]{10,}', 'Bearer [REDACTED]', text)
    text = re.sub('"access_token"\\s*:\\s*"[A-Za-z0-9._\\-]{10,}"', '"access_token": "[REDACTED]"', text)
    return text

def _write_json(result: dict, path: Path) -> None:
    raw = json.dumps(result, indent=2, default=str, ensure_ascii=False)
    path.write_text(_redact(raw), encoding='utf-8')

def _read_stage_c_analysis(evidence_path: Path) -> dict | None:
    analysis_path = evidence_path.parent / 'stage_c_analysis.json'
    if not analysis_path.exists():
        return None
    try:
        return json.loads(analysis_path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return None

def _http_status(row: dict) -> int | None:
    return (row.get('attack') or {}).get('response', {}).get('status_code')

def _response_signature(row: dict) -> dict:
    return (row.get('attack') or {}).get('response', {}).get('signature') or {}

def _cause_suffix(sig: dict) -> str:
    cause = sig.get('cause')
    return f' (cause: {cause})' if cause else ''

def _classify_problem(row: dict) -> str:
    verdict = row.get('verdict')
    reason = row.get('verdict_reason') or ''
    status = _http_status(row)
    sig = _response_signature(row)
    suffix = _cause_suffix(sig)
    if verdict == 'SETUP_FAILURE' and 'Local payload/query validation failed' in reason:
        return 'MALFORMED_REQUEST_LOCAL — our own payload/query params fail 3GPP schema validation (request never sent — see Reason for the exact field)'
    if verdict == 'NOT_IMPLEMENTED':
        token_error = (row.get('setup') or {}).get('token_error') or {}
        body = token_error.get('body')
        if token_error.get('reason') == 'http_error' and isinstance(body, dict) and (body.get('error') == 'invalid_scope'):
            return f'NOT_IMPLEMENTED_SCOPE — NRF rejected the scope request (HTTP {token_error.get('status')}: {body})'
        return 'NOT_IMPLEMENTED_501 — HTTP 501 stub (route registered, handler empty)'
    if verdict == 'ROBUSTNESS_BUG':
        if status == 501 and sig.get('kind') == 'empty_body':
            return 'NOT_IMPLEMENTED_501 — HTTP 501 stub (route registered, handler empty)'
        if status == 500:
            return f'SERVER_ERROR — 500 (handler ran and crashed on our input){suffix}'
        if status is not None:
            return f'SERVER_ERROR — {status} (5xx, not the plain 501 stub){suffix}'
        return 'SERVER_ERROR — 5xx'
    if verdict == 'SETUP_FAILURE':
        if 'PRODUCER_SPEC_NONCONFORMANT:' in reason:
            detail = reason.split('PRODUCER_SPEC_NONCONFORMANT:', 1)[-1].strip()
            return f'SPEC_NONCONFORMANT_PROVISIONING — {detail}'
        if 'Could not obtain token' in reason:
            token_error = (row.get('setup') or {}).get('token_error') or {}
            if token_error.get('reason') == 'http_error':
                return f'NOT_IMPLEMENTED_SCOPE — NRF rejected the scope request (HTTP {token_error.get('status')}: {token_error.get('body')}) — target NF never registers this OAuth2 scope'
            if token_error.get('reason') == 'connection_error':
                return 'SETUP_PROBLEM — NRF unreachable while requesting the attacker token (network/lab issue, not a finding)'
            return 'NOT_IMPLEMENTED_SCOPE — target NF never registers this OAuth2 scope with the NRF'
        if _requires_state_setup(row.get('scenario') or {}):
            return "SETUP_PROBLEM (REQUIRES_STATE_SETUP) — expected: this case's own execution_hint already names the unstaged precondition, not an unrelated lab/pipeline issue"
        return 'SETUP_PROBLEM — environment/precondition failure, not a finding'
    if verdict == 'INCONCLUSIVE':
        findings = row.get('security_findings') or []
        if 'CROSS_OWNER_REQUEST_ACCEPTED' in findings and 'CONCRETE_EFFECT_CONFIRMED' not in findings:
            return f'EFFECT_UNVERIFIED — HTTP {status}{suffix}: request accepted, but no concrete effect was confirmed'
        owner_control = (row.get('attack') or {}).get('owner_control')
        if owner_control and owner_control.get('ok') and (owner_control.get('status_code') == status):
            return f"STATE_OR_VALIDATION_DEPENDENT — HTTP {status}{suffix}, and the legitimate owner's IDENTICAL request was ALSO denied (owner cause: {owner_control.get('cause')}) — not an ownership check, a shared precondition/validation failure (see oracles.needs_owner_control_check())"
        if sig.get('kind') == 'router_not_found':
            if _manually_confirmed_not_implemented(row.get('scenario') or {}):
                return 'NOT_IMPLEMENTED_404 — HTTP 404, plain-text router response; manually verified live that the request used the textually-correct 3GPP-spec path (not a path_template bug on our side) — this operation has no registered route in this free5GC build (see reviewer_notes for the specific evidence)'
            return "WRONG_PATH — HTTP 404, plain-text router response (path_template doesn't match free5GC's registered route — see S17)"
        if status == 404:
            return f'UNVERIFIED — HTTP 404{suffix} (JSON body, not a router miss — likely a resource-not-found from wrong fixture/precondition data, check manually)'
        if status == 400 or (sig.get('kind') == 'problem_details' and status is not None and (status < 500)):
            if _manually_confirmed_not_implemented(row.get('scenario') or {}):
                return "NOT_IMPLEMENTED_400 — HTTP 400, generic message-parse-layer rejection; manually verified live/against source that this core's SBI dispatcher has no registered sub-resource case for this operation at all and falls through to a mismatched body decoder (not a payload bug on our side — see reviewer_notes for the specific evidence)"
            return f"MALFORMED_REQUEST — HTTP {status}{suffix} (the target core's own handler rejected the request body/params — check the payload against the 3GPP schema and the cause above)"
        if status is not None:
            return f'UNVERIFIED — HTTP {status}{suffix} (outside declared success/denial codes)'
        return 'UNVERIFIED — no response'
    return '—'

def _execution_hint_empty(hint: dict) -> bool:
    if not hint:
        return True
    constraint_keys = ('body_required_fields', 'body_any_of_fields', 'body_absent_fields', 'body_required_values', 'query_required_fields', 'query_any_of_fields', 'query_absent_fields', 'query_required_values')
    return not any((hint.get(key) for key in constraint_keys))
_REQUEST_SHAPE_CACHE: dict[tuple, tuple | None] = {}

def _resolved_request_shape(specs_dir: Path, service: str, method: str, path: str):
    cache_key = (str(specs_dir), service, method, path)
    if cache_key in _REQUEST_SHAPE_CACHE:
        return _REQUEST_SHAPE_CACHE[cache_key]
    result = None
    spec = openapi_loader.resolve_spec(specs_dir, service)
    if spec is not None:
        op = openapi_loader.find_operation(spec, method, path)
        if op is not None:
            body_schema = openapi_loader.get_request_body_schema(spec, op, specs_dir=specs_dir)
            body_required = body_schema.get('required') or []
            query_params = openapi_loader.get_query_params_schema(spec, op, specs_dir=specs_dir)
            query_required = [p for p in query_params if p.get('required')]
            has_input = bool(op.get('requestBody')) or bool(query_params)
            result = (has_input, body_required, query_required)
    _REQUEST_SHAPE_CACHE[cache_key] = result
    return result

def _input_guidance_status(scenario: dict, specs_dir: Path) -> str:
    target = scenario.get('target', {}) or {}
    request = scenario.get('request', {}) or {}
    service = target.get('service')
    method = request.get('method')
    path = request.get('path_template')
    if not (service and method and path):
        return 'UNKNOWN'
    shape = _resolved_request_shape(specs_dir, service, method, path)
    if shape is None:
        return 'UNKNOWN'
    has_input, body_required, query_required = shape
    if not has_input:
        return 'NOT_NEEDED'
    hint = (scenario.get('spec_analysis') or {}).get('execution_hint') or {}
    if not body_required and (not query_required) and _execution_hint_empty(hint):
        return 'NO_REQUIRED_NO_HINT'
    return 'CONSTRAINED'

def _execution_flags_cell(input_status: str, scenario: dict) -> str:
    flags = []
    if input_status == 'NO_REQUIRED_NO_HINT':
        flags.append('⚠️ NO_REQUIRED_NO_HINT (AGENT_FALLBACK)')
    elif input_status == 'NOT_NEEDED':
        flags.append('ℹ️ NO_INPUT_NEEDED')
    elif input_status == 'UNKNOWN':
        flags.append('❓ OPENAPI_UNRESOLVED')
    if _requires_state_setup(scenario):
        flags.append('⚠️ REQUIRES_STATE_SETUP')
    requester_status = _requester_compatibility_status(scenario)
    if requester_status in {'UNSUPPORTED_IN_LAB', 'UNSUPPORTED_IN_LAB_FALLBACK'}:
        compatibility = (scenario.get('spec_analysis') or {}).get('requester_compatibility') or {}
        runtime_nf = compatibility.get('runtime_fixture_nf_type') or 'UNKNOWN'
        if compatibility.get('fallback_used') is not False:
            flags.append(f'⚠️ UNSUPPORTED_IN_LAB — {runtime_nf} NF consumer fallback used')
        else:
            selected_nf = compatibility.get('selected_requester_nf_type') or runtime_nf
            flags.append(f'⚠️ UNSUPPORTED_IN_LAB — no configured {selected_nf} owner/attacker fixture pair')
    elif requester_status == 'HINT_REQUESTER_MISMATCH':
        flags.append('⚠️ HINT_REQUESTER_MISMATCH')
    elif requester_status == 'HINT_REQUESTER_UNSPECIFIED':
        flags.append('⚠️ HINT_REQUESTER_UNSPECIFIED')
    return ', '.join(flags) or '—'
_SCENARIO_CATALOG_CACHE: dict[str, dict[str, dict]] = {}
_REVIEW_CATALOG_CACHE: dict[str, dict[str, dict]] = {}

def _load_scenario_catalog(scenarios_dir: Path | None) -> dict[str, dict]:
    if scenarios_dir is None or not scenarios_dir.is_dir():
        return {}
    cache_key = str(scenarios_dir)
    if cache_key in _SCENARIO_CATALOG_CACHE:
        return _SCENARIO_CATALOG_CACHE[cache_key]
    catalog: dict[str, dict] = {}
    for scenario_path in sorted(scenarios_dir.glob('*.yaml')):
        try:
            scenario = yaml.safe_load(scenario_path.read_text(encoding='utf-8')) or {}
        except (OSError, yaml.YAMLError):
            continue
        sid = scenario.get('attack_id')
        if sid:
            catalog[sid] = scenario
    _SCENARIO_CATALOG_CACHE[cache_key] = catalog
    return catalog

def _load_review_catalog(scenarios_dir: Path | None) -> dict[str, dict]:
    if scenarios_dir is None:
        return {}
    review_dir = scenarios_dir.parent / 'review'
    if not review_dir.is_dir():
        return {}
    cache_key = str(scenarios_dir)
    if cache_key in _REVIEW_CATALOG_CACHE:
        return _REVIEW_CATALOG_CACHE[cache_key]
    catalog: dict[str, dict] = {}
    for review_path in sorted(review_dir.glob('*_review.yaml')):
        try:
            review = yaml.safe_load(review_path.read_text(encoding='utf-8')) or {}
        except (OSError, yaml.YAMLError):
            continue
        sid = (review.get('enriched_spec') or {}).get('attack_id')
        if sid:
            catalog[sid] = review
    _REVIEW_CATALOG_CACHE[cache_key] = catalog
    return catalog

def _requires_state_setup(scenario: dict) -> bool:
    hint = (scenario.get('spec_analysis') or {}).get('execution_hint') or {}
    return hint.get('status') == 'requires_state_setup'

def _manually_confirmed_not_implemented(scenario: dict) -> bool:
    hint = (scenario.get('spec_analysis') or {}).get('execution_hint') or {}
    return bool(hint.get('manually_confirmed_not_implemented'))

def _requester_compatibility_status(scenario: dict) -> str:
    compatibility = (scenario.get('spec_analysis') or {}).get('requester_compatibility') or {}
    return compatibility.get('status') or 'UNKNOWN'

def write_summary(results_dir: Path, scenarios_dir: Path | None=None, scenario_ids: set[str] | None=None, output_name: str='SUMMARY.md') -> Path:
    if scenarios_dir is None:
        inferred = results_dir.parent / 'scenarios'
        scenarios_dir = inferred if inferred.is_dir() else None
    catalog = _load_scenario_catalog(scenarios_dir)
    review_catalog = _load_review_catalog(scenarios_dir)
    if scenario_ids is not None:
        catalog = {sid: scenario for sid, scenario in catalog.items() if sid in scenario_ids}
        batch_ids = {str((scenario.get('source_provenance') or {}).get('authorization_profile_batch')) for scenario in catalog.values() if (scenario.get('source_provenance') or {}).get('authorization_profile_batch')}
        review_catalog = {sid: review for sid, review in review_catalog.items() if sid in scenario_ids or str(((review.get('enriched_spec') or {}).get('source_provenance') or {}).get('authorization_profile_batch')) in batch_ids}
    best_effort_scenarios = {sid: scenario for sid, scenario in catalog.items() if _requires_state_setup(scenario)}
    latest: dict[str, dict] = {}
    stage_c: dict[str, dict] = {}
    for evidence_path in results_dir.glob('*/evidence.json'):
        try:
            data = json.loads(evidence_path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            continue
        sid = data.get('scenario_id')
        if not sid:
            continue
        if scenario_ids is not None and sid not in scenario_ids:
            continue
        current = latest.get(sid)
        if current is None or data.get('timestamp', '') > current.get('timestamp', ''):
            latest[sid] = data
            stage_c[sid] = _read_stage_c_analysis(evidence_path)
    path = results_dir / output_name
    input_total = len(set(review_catalog) | set(catalog))
    finalized_total = len(catalog)
    unresolved_reviews = {sid: review for sid, review in review_catalog.items() if sid not in catalog}
    unresolved_total = len(unresolved_reviews)
    if not latest:
        path.write_text('\n'.join(['# Test Summary', '', f'Input authorization cases: {input_total}', f'Finalized scenarios: {finalized_total}', f'Unresolved cases: {unresolved_total}', 'Executed results tracked: 0', '', 'No results yet.', '']), encoding='utf-8')
        return path
    rows = sorted(latest.values(), key=lambda d: _scenario_sort_key(d['scenario_id']))

    def normalized_stage_c_assessment(row: dict) -> str:
        analysis = stage_c.get(row['scenario_id'])
        verdict = (analysis or {}).get('final_verdict') or 'NOT_ANALYZED'
        if verdict == 'PROTECTION_CONFIRMED':
            verdict = 'CHECK_CONFIRMED'
        elif verdict == 'INCONCLUSIVE':
            verdict = 'SPEC_ASSESSMENT_UNRESOLVED'
        return verdict
    input_guidance = {row['scenario_id']: _input_guidance_status(catalog.get(row['scenario_id'], row.get('scenario', {}) or {}), SPECS_DIR) for row in rows}
    ambiguous_count = sum((1 for status in input_guidance.values() if status == 'NO_REQUIRED_NO_HINT'))
    not_needed_count = sum((1 for status in input_guidance.values() if status == 'NOT_NEEDED'))
    requester_statuses = {sid: _requester_compatibility_status(scenario) for sid, scenario in catalog.items()}
    unsupported_requester_count = sum((status in {'UNSUPPORTED_IN_LAB', 'UNSUPPORTED_IN_LAB_FALLBACK'} for status in requester_statuses.values()))
    hint_requester_mismatch_count = sum((status in {'HINT_REQUESTER_MISMATCH', 'HINT_REQUESTER_UNSPECIFIED'} for status in requester_statuses.values()))
    best_effort_count = len(best_effort_scenarios)
    executed_count = len(rows)
    pending_count = max(finalized_total - executed_count, 0) if catalog else 0
    _NOT_IMPLEMENTED_DIAGNOSTICS = {'NOT_IMPLEMENTED_501', 'NOT_IMPLEMENTED_SCOPE', 'NOT_IMPLEMENTED_404', 'NOT_IMPLEMENTED_400'}

    def attack_outcome(row: dict, diagnostic_label: str) -> str:
        verdict = row.get('verdict')
        findings = row.get('security_findings') or []
        if verdict == 'CONFIRMED_VULNERABILITY':
            return 'EFFECT_CONFIRMED'
        if verdict == 'SECURE':
            return 'REQUEST_BLOCKED'
        if verdict == 'NOT_IMPLEMENTED' or diagnostic_label in _NOT_IMPLEMENTED_DIAGNOSTICS:
            return 'NOT_IMPLEMENTED'
        if verdict == 'SETUP_FAILURE':
            return 'SETUP_FAILURE'
        if 'CROSS_OWNER_REQUEST_ACCEPTED' in findings and 'CONCRETE_EFFECT_CONFIRMED' not in findings:
            return 'REQUEST_ACCEPTED_EFFECT_UNVERIFIED'
        return 'RUNTIME_INCONCLUSIVE'
    outcome_order = ['EFFECT_CONFIRMED', 'REQUEST_BLOCKED', 'REQUEST_ACCEPTED_EFFECT_UNVERIFIED', 'RUNTIME_INCONCLUSIVE', 'SETUP_FAILURE', 'NOT_IMPLEMENTED']
    outcome_counts = {outcome: 0 for outcome in outcome_order}
    outcome_diagnostics = {outcome: {} for outcome in outcome_order}
    stage_c_by_outcome = {outcome: {} for outcome in outcome_order}
    for row in rows:
        diagnostic_label = _classify_problem(row).split(' — ', 1)[0]
        outcome = attack_outcome(row, diagnostic_label)
        outcome_counts[outcome] += 1
        assessment = normalized_stage_c_assessment(row)
        assessment_bucket = stage_c_by_outcome[outcome]
        assessment_bucket[assessment] = assessment_bucket.get(assessment, 0) + 1
        if outcome not in {'EFFECT_CONFIRMED', 'REQUEST_BLOCKED'}:
            if diagnostic_label != outcome:
                bucket = outcome_diagnostics[outcome]
                bucket[diagnostic_label] = bucket.get(diagnostic_label, 0) + 1
    attack_effect_confirmed_count = outcome_counts['EFFECT_CONFIRMED']
    attack_blocked_count = outcome_counts['REQUEST_BLOCKED']
    accepted_without_effect_count = outcome_counts['REQUEST_ACCEPTED_EFFECT_UNVERIFIED']
    attack_result_unresolved_count = outcome_counts['RUNTIME_INCONCLUSIVE']
    attack_not_executed_count = outcome_counts['SETUP_FAILURE']
    endpoint_not_implemented_count = outcome_counts['NOT_IMPLEMENTED']
    implemented_assessment_unresolved_count = accepted_without_effect_count + attack_result_unresolved_count + attack_not_executed_count
    lines = ['# Test Summary', '', f'Last updated: {datetime.now(timezone.utc).isoformat()}']
    if catalog:
        lines += [f'Input authorization cases: {input_total}', f'Finalized scenarios: {finalized_total}', f'Unresolved cases: {unresolved_total}', f'Executed results tracked: {executed_count}', f'Best-effort cases (⚠️ REQUIRES_STATE_SETUP): {best_effort_count}', f'Pending finalized/no current result: {pending_count}']
    else:
        lines.append(f'Scenarios tracked: {len(rows)}')
    lines += ['', f'## Stage B execution outcomes — {executed_count} cases', '', 'These categories are mutually exclusive and sum to the executed-result total.', '']
    for outcome in outcome_order:
        lines.append(f'- {outcome}: **{outcome_counts[outcome]}**')
        for diagnostic, count in sorted(outcome_diagnostics[outcome].items()):
            lines.append(f'  - {diagnostic}: **{count}**')
    lines += ['', f'## Stage C specification assessment — {executed_count} cases', '', f'Concrete runtime outcomes assessed: **{attack_effect_confirmed_count + attack_blocked_count}**']
    for outcome in ('EFFECT_CONFIRMED', 'REQUEST_BLOCKED'):
        lines.append(f'- {outcome}: **{outcome_counts[outcome]}**')
        for assessment, count in sorted(stage_c_by_outcome[outcome].items()):
            lines.append(f'  - {assessment}: **{count}**')
    lines += ['', f'Assessment unresolved on implemented endpoints: **{implemented_assessment_unresolved_count}**']
    for outcome in ('REQUEST_ACCEPTED_EFFECT_UNVERIFIED', 'RUNTIME_INCONCLUSIVE', 'SETUP_FAILURE'):
        lines.append(f'- {outcome}: **{outcome_counts[outcome]}**')
        for assessment, count in sorted(stage_c_by_outcome[outcome].items()):
            lines.append(f'  - {assessment}: **{count}**')
    lines += ['', f'Excluded because the endpoint is not implemented: **{endpoint_not_implemented_count}**', '', f'- Input construction:', f'  - ℹ️ NO_INPUT_NEEDED (operation has no request body or query parameters): **{not_needed_count}**', f'  - ⚠️ NO_REQUIRED_NO_HINT (AGENT_FALLBACK: input exists, but OpenAPI and the hint provide no field constraints): **{ambiguous_count}**', f'  - ⚠️ UNSUPPORTED_IN_LAB (no configured owner/attacker pair; any fallback is diagnostic only): **{unsupported_requester_count}**', f'  - ⚠️ HINT_REQUESTER_MISMATCH/UNSPECIFIED (hint variant not established for the selected authorized NF): **{hint_requester_mismatch_count}**', '', '## Legend — what each verdict/category means', '', '**Stage B outcome labels** (normalized from `oracles.py` without rewriting historical evidence):', '- `EFFECT_CONFIRMED` — the cross-owner request was accepted and a concrete effect was verified (DB write, log line, exposed data).', '- `REQUEST_BLOCKED` — the cross-owner request was explicitly denied and no resource change was observed.', '- `REQUEST_ACCEPTED_EFFECT_UNVERIFIED` — the request was accepted, but the expected effect was not demonstrated.', '- `RUNTIME_INCONCLUSIVE` — the request was sent, but the response/evidence does not support a conclusive execution outcome.', "- `NOT_IMPLEMENTED` — free5GC genuinely doesn't implement this operation in this build — nothing crashed, no ownership check could ever run, nothing to fix on our side. Deliberately kept separate from `ROBUSTNESS_BUG`/`RUNTIME_INCONCLUSIVE`/`SETUP_FAILURE`'s own counts, even when the raw per-scenario `verdict` field underneath is one of those (see the three sub-labels below — the regrouping is report-level only, done 2026-10-15 after it read as misleadingly 'ambiguous' to have a manually-confirmed non-implementation sitting inside those totals). Stage C never calls the AI model for this verdict — there's no runtime behavior to compare against the spec.", "- `SETUP_FAILURE` — the test never got as far as sending the attack request (couldn't get a token, lab unhealthy, a local schema-validation failure, etc.), AND the reason isn't a confirmed non-implementation (see `NOT_IMPLEMENTED_SCOPE` below — that one reclassifies out of this bucket). Stage C never calls the AI model for this verdict either, for the same reason.", '', '**Diagnostic reason** (a sub-classification of non-definitive runtime outcomes, not another verdict — see `validators.py`/`response_signature.py`/`reporter._classify_problem()`):', "- `MALFORMED_REQUEST_LOCAL` — caught *before* the request was ever sent: `runner.py` validates the fully-substituted payload/query params against the 3GPP OpenAPI schema (the same schema Stage A drafted the payload from) and the request itself violates it (missing required field, wrong type, ...). Always our own bug — fix the scenario YAML, this is never free5GC's fault.", "- `MALFORMED_REQUEST` — the request WAS sent and free5GC's own handler rejected it (typically HTTP 400) with a `ProblemDetails` body. The local check above didn't catch it (e.g. a cross-field business rule no static schema expresses), so check the `cause` shown in this row first — it may still be our payload, or it may be a genuine free5GC input-validation bug.", "- `NOT_IMPLEMENTED_501` — HTTP `501` with an empty JSON body (`{}`/`[]`) — free5GC's genuine 'this operation was never written' stub signature.", "- `NOT_IMPLEMENTED_SCOPE` — the target NF never advertises this OAuth2 scope to the NRF at all (the NRF's own token-rejection body is parsed and shown, not just inferred from the reason text) — the request can never even be sent.", "- `NOT_IMPLEMENTED_404` — the same bare-gin-404 router-miss signature as `WRONG_PATH`, but for a case where a reviewer has already done the manual check that category asks for and confirmed, live, that the request fired the textually-correct 3GPP-spec path (so this isn't a path_template bug on this project's side) and free5GC still has no registered route for it at all. Opt-in per scenario (`spec_analysis.execution_hint.manually_confirmed_not_implemented: true` — see each flagged scenario's `reviewer_notes` for the specific live evidence); every other `WRONG_PATH` stays unflagged and ambiguous until someone does the same check. Found needed 2026-10-10 diagnosing batch_08, where several `Nudr_DR` sub-resource families have every single HTTP verb missing, not just one. Renamed from `NOT_IMPLEMENTED_CONFIRMED` and regrouped under the top-level `NOT_IMPLEMENTED` count (was `RUNTIME_INCONCLUSIVE`) 2026-10-15 — same underlying `evidence.json` `verdict` field, this is a report-aggregation-only change (see `NOT_IMPLEMENTED`'s own entry above).", '- `NOT_IMPLEMENTED_400` — same opt-in mechanism as `NOT_IMPLEMENTED_404` (`manually_confirmed_not_implemented: true`), for a different core\'s different "not implemented" signature: Open5GS\'s generic SBI message parser (`ogs_sbi_parse_request()`) doesn\'t fall through to a clean 404/501 for an unrecognized sub-resource — its `SWITCH(resource.component[2])` dispatcher\'s `DEFAULT` case (`lib/sbi/message.c`) decodes the body as if it were the *creation* operation\'s schema instead, so an operation that was never given its own dispatch case (confirmed against Open5GS v2.7.5 source, not inferred from the status code alone — e.g. `Nsmf_PDUSession RetrieveSmContext`/`SendMoData`, whose `sm-contexts/{ref}` dispatch in `src/smf/smf-sm.c` only has `MODIFY`/`RELEASE` cases) fails generic JSON-schema decoding and returns a structurally-ambiguous `400 "cannot parse HTTP sbi_message"` that looks identical to a malformed-payload rejection. Added 2026-10-28 diagnosing `S45`/`S46` against `runs/open5gs/` — see each flagged scenario\'s `reviewer_notes` for the exact source citation.', "- `SERVER_ERROR` — a 5xx that is *not* the plain-501-empty-body stub signature (e.g. a `500`, or a `501` with a non-empty body). The handler actually ran on our input and broke — could be a genuine free5GC bug or a malformed request on our side; check the `cause` shown in this row and the NF's logs before writing it off.", "- `WRONG_PATH` — HTTP 404 whose body is the literal plain-text string gin's router emits for an unmatched route (verified structurally, not guessed from the status code alone) — the scenario's `path_template` doesn't match the path free5GC actually registered for that operation (free5GC deviates from the 3GPP-spec path on several endpoints — see S17's `cancel-pos-info` vs `cancel-loc-info`). Needs a manual check against the running NF.", "- `STATE_OR_VALIDATION_DEPENDENT` — a denial that owner-control (`runner.py` step 9b, see its own docstring) actively disproved as an ownership check: the SAME request, fired with the legitimate owner's token, was ALSO denied with the same cause. Found live, 2026-09-03, for S07/S15/S16 — all three previously read as `SECURE`, but their own `existing_protection.resource_binding.mechanism` text explicitly denies any ownership check is even specified; the real cause was an unstaged state precondition (S07's handover) or a synthetic/placeholder payload failing an unrelated validation (S15's NAS integrity check). This category only ever appears under `INCONCLUSIVE`.", '- `EFFECT_UNVERIFIED` — the cross-owner request received an accepted response, but no concrete effect was confirmed.', "- `UNVERIFIED` — any other HTTP 404 (a JSON body was returned, so it's not a router miss — more likely a resource genuinely not found, e.g. wrong fixture data) or any other status outside the declared success/denial codes. Needs a manual check, not an automatic write-off either way.", "- `SPEC_NONCONFORMANT_PROVISIONING` — resource_provisioner.py's create call for a path-variable identifier succeeded, but the producer NF's own response doesn't conform to its declared OpenAPI contract closely enough to disclose the id it just created (e.g. no mandatory `Location` header on a 2xx — TS 29.500 §5.2.3). Never a lab/environment issue and never fixable by adding a resolver: the identifier genuinely isn't observable anywhere from outside the process. Found live 2026-09-30 (free5GC's `Nudm_EE` `CreateEeSubscription`).", '- `SETUP_PROBLEM (REQUIRES_STATE_SETUP)` — this case\'s own `execution_hint.status` is `requires_state_setup` (see the "Best-effort authorization cases" table below for its exact TS precondition) and the pipeline couldn\'t get far enough to even fire the request — expected, not a lab/pipeline issue, nothing to chase. Distinguishes this from the plain `SETUP_PROBLEM` row below, which otherwise reads identically whether the case was ever supposed to need a precondition or not.', '- `SETUP_PROBLEM` — any other SETUP_FAILURE (lab down, provisioning failed, NRF unreachable, etc.) on a case that was NOT flagged `requires_state_setup` — a genuine environment issue, re-run once fixed.', '', "**Execution Flags** (independent of verdict/category — computed from the live OpenAPI spec and the scenario's `spec_analysis.execution_hint`):", '- `ℹ️ NO_INPUT_NEEDED` — the operation declares neither a request body nor query parameters; no field-selection execution hint is necessary.', '- `⚠️ NO_REQUIRED_NO_HINT (AGENT_FALLBACK)` — the operation has request input, but its OpenAPI schema has no required request-body field or required query parameter, AND the execution_hint has no body or query field constraints (required, any-of, value, or absent). Neither source tells the payload/query drafter what the request actually needs to reach this case — the same ambiguity the still-open deterministic-field-filter design question is about (see CLAUDE.md\'s "Known open issues"; S06/S08/S09/S13/S15 originally motivated it, before a manual audit or `requires_state_setup` reclassification resolved each one). Worth a manual look before trusting the drafted payload/query params blindly.', '- `⚠️ REQUIRES_STATE_SETUP` — the TS procedure requires a specific runtime state that the tester did not establish automatically. This flag can coexist with `⚠️ NO_REQUIRED_NO_HINT (AGENT_FALLBACK)`.', '- `⚠️ UNSUPPORTED_IN_LAB` — no authorized requester has a configured owner/attacker pair in the lab. When a fallback NF exists it is shown explicitly and used only for a diagnostic best-effort probe; Stage C keeps the result inconclusive.', '- `⚠️ HINT_REQUESTER_MISMATCH` — the selected requester is authorized by the profile, but the execution hint was constructed for another authorized requester; payload/procedure equivalence has not been established, so Stage C keeps the result inconclusive.', '- `⚠️ HINT_REQUESTER_UNSPECIFIED` — a legacy hint covers a multi-requester case without saying which requester its representative variant targets.', '- `—` — the schema and/or the hint do constrain the payload/query params.', "- `❓ OPENAPI_UNRESOLVED` — the operation's spec file or matching path+method couldn't be resolved under `docs/specs/` at report-generation time, so schema-requiredness itself is unknown.", '', '**Optional checks:** `OPTIONAL_CHECK_NOT_APPLIED` means the supplied TS analysis permits omitting the observed check. It is not a mandatory-check implementation nonconformance or an automatic specification-gap finding; the Stage B effect remains separate.', '', "**Check Match** (only for `CHECK_CONFIRMED`): `EXPECTED_CHECK` means the observed status/cause matches the selected authorization case's declared failure oracle; `ALTERNATIVE_CHECK` means the request was blocked, but by a different observable check.", '', '| Scenario | Stage B Outcome | HTTP | Request Accepted | Concrete Effect | Runtime Diagnostic | Execution Flags | Stage B Reason | Run ID | Timestamp | Stage C Assessment | Check Match | Stage C Confidence |', '|---|---|---|---|---|---|---|---|---|---|---|---|---|']
    for row in rows:
        reason = (row.get('verdict_reason') or '').replace('|', '\\|')
        analysis = stage_c.get(row['scenario_id'])
        c_verdict = normalized_stage_c_assessment(row) if analysis else '—'
        c_match = analysis.get('protection_match') or '—' if analysis else '—'
        c_confidence = analysis['confidence'] if analysis else '—'
        status = _http_status(row)
        status_s = str(status) if status is not None else '—'
        raw_category = _classify_problem(row)
        category = raw_category.replace('|', '\\|')
        diagnostic_label = raw_category.split(' — ', 1)[0]
        scenario = catalog.get(row['scenario_id'], row.get('scenario', {}) or {})
        guidance = _execution_flags_cell(input_guidance.get(row['scenario_id'], 'UNKNOWN'), scenario)
        findings = row.get('security_findings') or []
        if 'security_findings' in row:
            accepted = 'yes' if 'CROSS_OWNER_REQUEST_ACCEPTED' in findings else 'no'
            effect = 'yes' if 'CONCRETE_EFFECT_CONFIRMED' in findings else 'no'
        else:
            accepted = effect = '—'
        lines.append(f'| {row['scenario_id']} | {attack_outcome(row, diagnostic_label)} | {status_s} | {accepted} | {effect} | {category} | {guidance} | {reason} | {row['run_id']} | {row['timestamp']} | {c_verdict} | {c_match} | {c_confidence} |')
    lines.append('')
    if unresolved_reviews:
        lines += ['## Unresolved authorization cases', '', 'These Stage A inputs were not finalized and are therefore absent from runtime execution.', '', '| Case | Approved | Execution-hint status |', '|---|---|---|']
        for sid, review in sorted(unresolved_reviews.items(), key=lambda kv: _scenario_sort_key(kv[0])):
            enriched = review.get('enriched_spec') or {}
            hint = (enriched.get('spec_analysis') or {}).get('execution_hint') or {}
            approved = 'yes' if review.get('approved') is True else 'no'
            hint_status = str(hint.get('status') or '—').replace('|', '\\|')
            lines.append(f'| {sid} | {approved} | {hint_status} |')
        lines.append('')
    if catalog:
        lines += ['## Best-effort authorization cases', '', 'These requests are attempted, but Stage C keeps the case-specific result inconclusive because the pipeline does not establish the TS procedural state listed below.', '', '| Scenario | Status | Preconditions |', '|---|---|---|']
        for sid, scenario in sorted(best_effort_scenarios.items(), key=lambda kv: _scenario_sort_key(kv[0])):
            hint = (scenario.get('spec_analysis') or {}).get('execution_hint') or {}
            preconditions = '; '.join(hint.get('state_preconditions') or []) or 'See execution hint'
            preconditions = preconditions.replace('|', '\\|').replace('\n', ' ')
            lines.append(f'| {sid} | requires_state_setup | {preconditions} |')
        lines.append('')
    path.write_text('\n'.join(lines), encoding='utf-8')
    return path

def write_batch_summaries(results_dir: Path, scenarios_dir: Path | None=None) -> list[Path]:
    if scenarios_dir is None:
        inferred = results_dir.parent / 'scenarios'
        scenarios_dir = inferred if inferred.is_dir() else None
    catalog = _load_scenario_catalog(scenarios_dir)
    review_catalog = _load_review_catalog(scenarios_dir)
    batches: dict[str, set[str]] = {}
    for sid, scenario in catalog.items():
        batch_id = (scenario.get('source_provenance') or {}).get('authorization_profile_batch')
        if batch_id:
            batches.setdefault(str(batch_id), set()).add(sid)
    for sid, review in review_catalog.items():
        enriched = review.get('enriched_spec') or {}
        batch_id = (enriched.get('source_provenance') or {}).get('authorization_profile_batch')
        if batch_id:
            batches.setdefault(str(batch_id), set()).add(sid)
    paths = []
    for batch_id, ids in sorted(batches.items()):
        safe_id = re.sub('[^A-Za-z0-9]+', '_', batch_id).strip('_').upper()
        paths.append(write_summary(results_dir, scenarios_dir, scenario_ids=ids, output_name=f'SUMMARY_{safe_id}.md'))
    return paths
