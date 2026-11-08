import json
from pathlib import Path
import ai_client
CHECK_CONFIRMED = 'CHECK_CONFIRMED'
SPECIFICATION_GAP = 'SPECIFICATION_GAP'
IMPLEMENTATION_NONCONFORMANCE = 'IMPLEMENTATION_NONCONFORMANCE'
OPTIONAL_CHECK_NOT_APPLIED = 'OPTIONAL_CHECK_NOT_APPLIED'
UNEXPECTED_PROTECTION = 'UNEXPECTED_PROTECTION'
CONDITION_NOT_TRIGGERED = 'CONDITION_NOT_TRIGGERED'
NO_SPEC_DATA = 'NO_SPEC_DATA'
INCONCLUSIVE = 'INCONCLUSIVE'
EXPECTED_CHECK = 'EXPECTED_CHECK'
ALTERNATIVE_CHECK = 'ALTERNATIVE_CHECK'
_NON_COMPARABLE_ORACLE_VERDICTS = {'ROBUSTNESS_BUG', 'NOT_IMPLEMENTED', 'SETUP_FAILURE', 'INCONCLUSIVE'}
_BYPASS_ORACLE_VERDICTS = {'CONFIRMED_VULNERABILITY'}
_DENIED_ORACLE_VERDICTS = {'SECURE'}
_AI_RESOLVABLE_DETERMINISTIC_VERDICTS = {CONDITION_NOT_TRIGGERED, INCONCLUSIVE}
_VALID_FINAL_VERDICTS = {CHECK_CONFIRMED, SPECIFICATION_GAP, IMPLEMENTATION_NONCONFORMANCE, OPTIONAL_CHECK_NOT_APPLIED, UNEXPECTED_PROTECTION, CONDITION_NOT_TRIGGERED, NO_SPEC_DATA, INCONCLUSIVE}
_LEGACY_SYSTEM_PROMPT = Path(__file__).with_name('legacy_comparison_prompt.txt').read_text()
SYSTEM_PROMPT = 'You are a security researcher analyzing 5G Core SBI resource-ownership attacks.\n\nYou are given:\n1. test_expectation: what the 3GPP TS 29.5xx specification says SHOULD happen — the expected\n   resource-instance binding (expected_binding: which NF type should own this resource, and how)\n   and any explicit protection already identified in the spec text (existing_protection: whether a\n   resource-binding check is described, its coverage, its mechanism, and — importantly —\n   applies_when: the specific condition(s) under which that check actually fires; a check described\n   in the spec can be condition-scoped, meaning it only triggers for a subset of requests to this\n   same endpoint). existing_protection.protected_relation, when present, states precisely which\n   requester-to-resource relation the check verifies (e.g. "SMF instance indicated by nfId is the\n   stored SMF instance hosting the SM Context") — more actionable than mechanism\'s prose summary.\n   existing_protection.coverage_notes, when present, is the analyst\'s own caveat about the coverage\n   label\'s limits and whether applying the check is optional (e.g. "the supplied text does not\n   state how the requester identity is bound to the nfId value"). Read these qualifications when\n   assessing normative requirements; they are not evidence about the target\'s runtime behavior\n   and must not override runtime_result\'s observed effect or denial. When test_expectation\n   carries case_id/case_index/case_count, this scenario tests exactly ONE of that many distinct,\n   independently-analyzed authorization cases for the same underlying endpoint (e.g. a PATCH that\n   updates an ordinary field vs. the same PATCH used to purge/deregister) — the spec\'s own protection\n   can legitimately differ between siblings, so never reason about "this endpoint" in general; reason\n   about this one case\'s own expected_binding/existing_protection only.\n2. runtime_result: what actually happened when a non-owner NF instance (a second, unauthorized\n   instance of the same NF type, holding a validly-scoped OAuth2 token) fired the request against a\n   configured live free5GC lab — the deterministic oracle\'s verdict/reason, the HTTP status code, the\n   exact request body/params sent, the response body, the resource state before/after (a MongoDB\n   ownership binding, when applicable), resolved owner_id/attacker_id from the fixture, and filtered\n   AMF/SMF log excerpts. Fixture identities do not independently prove membership in an NF set.\n   Two extra structured\n   fields exist specifically to separate a technical test failure from a real spec-vs-runtime\n   finding — treat them as higher-confidence ground truth than free-text inference from the status\n   code alone:\n   - response.signature: a mechanical classification of the response body. kind=router_not_found\n     means the HTTP framework itself never matched any route for this path — this is a test-harness\n     bug (wrong path_template), never evidence about ownership enforcement. kind=empty_body on a 5xx\n     is the free5GC "unimplemented stub" signature. kind=problem_details carries a 3GPP-standardized\n     \'cause\' string you can compare directly against test_expectation\'s failure_causes.\n   - preflight_validation: when present with valid=false, the request was never sent at all (it\n     failed local validation against the 3GPP schema before the network call) — oracle_verdict in\n     this case reflects that non-event, not free5GC\'s behavior; classify as INCONCLUSIVE regardless\n     of what oracle_verdict says.\n   - token_error: when oracle_verdict is SETUP_FAILURE because no token could be obtained, this\n     shows why: reason=http_error with the NRF\'s own rejection body is a structural "this scope is\n     never registered" signal (closer to NO_SPEC_DATA/INCONCLUSIVE than a random environment hiccup);\n     reason=connection_error means the NRF was simply unreachable (a pure environment issue, tells\n     you nothing about free5GC\'s authorization logic).\n\nYour job is to compare the two and classify the result into EXACTLY one of these categories:\n\n- CHECK_CONFIRMED: an explicit resource-binding check was applicable and the cross-owner\n  request was denied (or the resource state stayed provably unchanged). A separate deterministic\n  protection_match field distinguishes whether this case\'s expected check or another observable\n  check caused the denial. This also applies when existing_protection.resource_binding is condition-scoped and\n  the response\'s failure cause/reason matches the spec\'s declared failure_causes for that check\n  (e.g. a 403 with cause "INVALID_GUAMI" against a spec that declares failure_causes:\n  ["INVALID_GUAMI"]) — that match is itself proof the condition-scoped check fired.\n- SPECIFICATION_GAP: no explicit resource-binding protection was identified for this operation (or\n  only operation-level/OAuth-scope protection exists), and the request succeeded with a proven side\n  effect. This is a gap in the standard itself, not a free5GC-specific bug.\n- IMPLEMENTATION_NONCONFORMANCE: the supplied spec analysis establishes a MANDATORY\n  resource-binding check applicable to this exact request, but the request violated that check\n  with a proven side effect.\n  An explicit description of a check does not, by itself, make its use mandatory.\n- OPTIONAL_CHECK_NOT_APPLIED: the supplied spec analysis establishes that applying this\n  resource-binding check is OPTIONAL, the request exercises the relation it would guard, and\n  the observed effect shows that the check did not prevent that access. Omitting this check is\n  permitted by the TS: this label is not IMPLEMENTATION_NONCONFORMANCE, SPECIFICATION_GAP or\n  proof that the implementation never applies the check in any other request/configuration.\n- UNEXPECTED_PROTECTION: no explicit protection was required by the spec for this request, yet it\n  was denied anyway — the implementation is stricter than the spec requires. Minor but worth\n  recording.\n- CONDITION_NOT_TRIGGERED: existing_protection.resource_binding is condition-scoped\n  (applies_when is non-empty), and based on the actual request body/params sent in runtime_result\n  you determine the triggering condition was NOT met by this specific request — so this run\n  neither confirms nor disproves that protection; it simply never exercised it. Prefer this over\n  SPECIFICATION_GAP/IMPLEMENTATION_NONCONFORMANCE whenever applies_when is non-empty and the sent\n  request doesn\'t match it — do not guess if the request body doesn\'t clearly show one way or the\n  other; use INCONCLUSIVE instead.\n- INCONCLUSIVE: the evidence is insufficient or genuinely ambiguous, or runtime_result already\n  reflects a run that did not complete meaningfully.\n\nRespond with this JSON only:\n{\n  "final_verdict": "<one of the categories above, exact spelling>",\n  "confidence": 0.0-1.0,\n  "reasoning": "one or two sentences, citing the specific evidence you relied on (status code, a\n    log line, a field in the request body, the applies_when condition text)"\n}\n\nRules:\n- Never invent evidence not present in runtime_result.\n- For explicit checks, determine normative force from mechanism, applies_when, coverage_notes\n  and any relevant TS quotations already present in execution_hint.evidence_used. Cite the\n  specific supplied text supporting your decision in reasoning. Do not infer a mandatory check\n  merely from coverage=\'explicit_binding_check\', expected_binding or a failure status code.\n- A parameter being optional in OpenAPI does not mean that applying its associated check is\n  optional; a check can be mandatory whenever that optional parameter is present. Conversely,\n  a described check can have optional enforcement. Interpret the requirement in context, not\n  by matching isolated words such as \'may\' or \'optional\'. If normative force is unclear, use\n  INCONCLUSIVE rather than guessing.\n- Assess the check against the request and the described owner/attacker fixture. Do not require\n  independent proof that every exceptional procedure mentioned by the TS was absent: an exception\n  being described is not evidence that it occurred in this run. Use the stated ordinary fixture\n  as the test baseline unless the supplied evidence identifies an exceptional or unresolved\n  procedural state; qualify that baseline as an assumption, not as an independently measured fact.\n  This does not override explicit setup limitations or prove a positive membership/role needed\n  by a guard. A request-provided set identifier alone does not establish the caller\'s set\n  membership: if that guarded relation is unknown, use INCONCLUSIVE. Do not infer that an optional\n  check is configured/enabled merely because a request supplies the parameter that it could use.\n- confidence must be low (<=0.4) whenever you had to guess about an unstated condition.\n- Do not second-guess oracles.py\'s underlying verdict (whether the request "succeeded" or was\n  "denied") — that is given to you as ground truth in runtime_result; your job is only to compare\n  it against test_expectation.\n'

def build_test_expectation(scenario: dict) -> dict:
    spec_analysis = scenario.get('spec_analysis')
    if spec_analysis:
        result = {'structured': True, 'expected_binding': spec_analysis.get('expected_binding'), 'existing_protection': spec_analysis.get('existing_protection'), 'confidence': spec_analysis.get('confidence')}
        if spec_analysis.get('case_id') is not None:
            result['case_id'] = spec_analysis['case_id']
            result['case_index'] = spec_analysis.get('case_index')
            result['case_count'] = spec_analysis.get('case_count')
        if spec_analysis.get('execution_hint'):
            result['execution_hint'] = spec_analysis['execution_hint']
        if spec_analysis.get('requester_compatibility'):
            result['requester_compatibility'] = spec_analysis['requester_compatibility']
        return result
    security_property = scenario.get('security_property', {}) or {}
    return {'structured': False, 'statement': security_property.get('statement', ''), 'expected_vulnerable': (scenario.get('verdict') or {}).get('expected_vulnerable')}

def build_runtime_result(evidence: dict, *, include_fixture_ids: bool=False) -> dict:
    attack = evidence.get('attack', {}) or {}
    ev = evidence.get('evidence', {}) or {}
    return {'oracle_verdict': evidence.get('verdict'), 'oracle_verdict_reason': evidence.get('verdict_reason'), 'security_findings': evidence.get('security_findings') or [], **({'owner_id': (evidence.get('resources') or {}).get('owner_id'), 'attacker_id': (evidence.get('resources') or {}).get('attacker_id')} if include_fixture_ids else {}), 'request': {'method': attack.get('request', {}).get('method'), 'url': attack.get('request', {}).get('url'), 'params': attack.get('request', {}).get('params'), 'body': attack.get('request', {}).get('body')}, 'response': {'status_code': attack.get('response', {}).get('status_code'), 'body': attack.get('response', {}).get('body'), 'signature': attack.get('response', {}).get('signature')}, 'preflight_validation': attack.get('preflight_validation'), 'token_error': (evidence.get('setup') or {}).get('token_error'), 'missing_token_control': (evidence.get('controls') or {}).get('missing_token'), 'binding_pre': (ev.get('pre') or {}).get('binding'), 'binding_post': (ev.get('post') or {}).get('binding'), 'ue_context_present_pre': (ev.get('pre') or {}).get('ue_context_present'), 'amf_logs_excerpt': evidence.get('evidence', {}).get('amf_logs_excerpt', ''), 'smf_logs_excerpt': evidence.get('evidence', {}).get('smf_logs_excerpt', '')}
_MISSING = object()

def _dotted_get(d, path: str):
    cur = d
    for part in path.split('.'):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur

def check_execution_hint_conformance(execution_hint: dict | None, body) -> list[str]:
    if not execution_hint or not isinstance(body, dict):
        return []
    violations = []
    for field in execution_hint.get('body_required_fields') or []:
        if _dotted_get(body, field) is _MISSING:
            violations.append(f"required field '{field}' is missing from the fired request body")
    for field, expected in (execution_hint.get('body_required_values') or {}).items():
        actual = _dotted_get(body, field)
        if actual is _MISSING:
            violations.append(f"field '{field}' must be present with value {expected!r} but is missing")
        elif actual != expected:
            violations.append(f"field '{field}' must equal {expected!r} but the fired request has {actual!r}")
    any_of = execution_hint.get('body_any_of_fields') or []
    if any_of and (not any((_dotted_get(body, f) is not _MISSING for f in any_of))):
        violations.append(f'at least one of {any_of} must be present, but none are in the fired request body')
    for field in execution_hint.get('body_absent_fields') or []:
        actual = _dotted_get(body, field)
        if actual is not _MISSING:
            violations.append(f"field '{field}' must be ABSENT — including it selects a different authorization case at this same endpoint — but the fired request body has it set to {actual!r}")
    return violations

def _protection_match(resource_binding: dict, runtime_result: dict) -> str | None:
    response = runtime_result.get('response') or {}
    observed_status = response.get('status_code')
    response_body = response.get('body') or {}
    observed_cause = response_body.get('cause') if isinstance(response_body, dict) else None
    expected_codes = resource_binding.get('failure_codes') or []
    expected_causes = resource_binding.get('failure_causes') or []
    has_expectation = bool(expected_codes or expected_causes)
    missing_signal = False
    if expected_codes:
        if observed_status is None:
            missing_signal = True
        else:
            normalized_codes = set()
            for code in expected_codes:
                try:
                    normalized_codes.add(int(code))
                except (TypeError, ValueError):
                    normalized_codes.add(code)
            if observed_status not in normalized_codes:
                return ALTERNATIVE_CHECK
    if expected_causes:
        if observed_cause is None:
            missing_signal = True
        elif observed_cause not in expected_causes:
            return ALTERNATIVE_CHECK
    if has_expectation and (not missing_signal):
        return EXPECTED_CHECK
    return None

def classify_deterministic(test_expectation: dict, runtime_result: dict) -> dict:
    oracle_verdict = runtime_result.get('oracle_verdict')
    cross_owner_accepted = 'CROSS_OWNER_REQUEST_ACCEPTED' in (runtime_result.get('security_findings') or [])
    skip_short_circuit = oracle_verdict == 'INCONCLUSIVE' and cross_owner_accepted
    if oracle_verdict in _NON_COMPARABLE_ORACLE_VERDICTS and (not skip_short_circuit):
        preflight = runtime_result.get('preflight_validation') or {}
        if preflight.get('valid') is False:
            reasoning = f"The attack request was never sent — runner.py's pre-flight validation rejected our own payload/query params against the 3GPP schema: {preflight.get('errors')}. This is a scenario-authoring bug, not evidence about free5GC's behavior."
        else:
            token_error = runtime_result.get('token_error') or {}
            if oracle_verdict == 'SETUP_FAILURE' and token_error.get('reason') == 'http_error':
                reasoning = f"No token could be obtained: the NRF itself rejected the scope request (HTTP {token_error.get('status')}: {token_error.get('body')}) — this NF never registers this OAuth2 scope in this free5GC build, so the request could not even reach the target's HTTP router, let alone an ownership check."
            else:
                reasoning = f"Upstream oracle verdict is '{oracle_verdict}' — the run did not complete meaningfully, no spec comparison is possible."
        return {'final_verdict': INCONCLUSIVE, 'confidence': 0.9, 'reasoning': reasoning}
    execution_hint = (test_expectation or {}).get('execution_hint') or {}
    if execution_hint.get('status') == 'requires_state_setup':
        return {'final_verdict': INCONCLUSIVE, 'confidence': 0.9, 'reasoning': 'The endpoint was probed, but this authorization case is marked requires_state_setup and the required TS procedural state was not established by the pipeline. The runtime response is retained as best-effort evidence, not as a case-specific security verdict.'}
    requester_compatibility = (test_expectation or {}).get('requester_compatibility') or {}
    requester_status = requester_compatibility.get('status')
    if requester_status in {'HINT_REQUESTER_MISMATCH', 'HINT_REQUESTER_UNSPECIFIED', 'UNSUPPORTED_IN_LAB', 'UNSUPPORTED_IN_LAB_FALLBACK'}:
        return {'final_verdict': INCONCLUSIVE, 'confidence': 0.9, 'requester_compatibility': requester_compatibility, 'reasoning': f'Requester compatibility is {requester_status}: {requester_compatibility.get('reason', '')} The request may still be useful as a best-effort probe, but it cannot support a case-specific authorization verdict.'}
    hint_violations = check_execution_hint_conformance((test_expectation or {}).get('execution_hint'), (runtime_result.get('request') or {}).get('body'))
    if hint_violations:
        return {'final_verdict': INCONCLUSIVE, 'confidence': 0.9, 'execution_hint_violation': hint_violations, 'reasoning': f"The fired request body doesn't conform to this scenario's own execution_hint — it likely tested a different (or malformed) authorization case than the one declared: {'; '.join(hint_violations)}. oracle_verdict ('{oracle_verdict}') is not trustworthy evidence about this case until the scenario's payload_example/FIELD_SEMANTICS substitution is fixed and re-run."}
    if not test_expectation.get('structured'):
        return {'final_verdict': NO_SPEC_DATA, 'confidence': 0.0, 'reasoning': 'Scenario has no spec_analysis block (no matching authorization-profile entry) — oracle verdict stands, no spec comparison performed.'}
    existing_protection = test_expectation.get('existing_protection') or {}
    resource_binding = existing_protection.get('resource_binding') or {}
    coverage = (resource_binding.get('coverage') or '').strip().lower()
    applies_when = resource_binding.get('applies_when') or []
    bypassed = oracle_verdict in _BYPASS_ORACLE_VERDICTS
    denied = oracle_verdict in _DENIED_ORACLE_VERDICTS
    if 'condition' in coverage or 'ambiguous' in coverage:
        failure_causes = resource_binding.get('failure_causes') or []
        response_body = (runtime_result.get('response') or {}).get('body') or {}
        response_cause = response_body.get('cause') if isinstance(response_body, dict) else None
        protection_match = _protection_match(resource_binding, runtime_result) if denied else None
        if denied and protection_match == EXPECTED_CHECK:
            return {'final_verdict': CHECK_CONFIRMED, 'protection_match': EXPECTED_CHECK, 'confidence': 0.85, 'reasoning': f"coverage='{coverage}' is condition-scoped, and the response's status/cause matches the spec's declared failure oracle exactly — the condition-scoped check fired as specified."}
        if denied and protection_match == ALTERNATIVE_CHECK:
            return {'final_verdict': CHECK_CONFIRMED, 'protection_match': ALTERNATIVE_CHECK, 'confidence': 0.4, 'cause_mismatch': True, 'reasoning': f"coverage='{coverage}' is condition-scoped and the request was denied, but the observed response status/cause does not match this case's declared failure_codes/failure_causes — a different check blocked the request."}
        if denied:
            return {'final_verdict': CHECK_CONFIRMED, 'protection_match': None, 'confidence': 0.5, 'reasoning': f"coverage='{coverage}' is condition-scoped and oracle_verdict='{oracle_verdict}' (denied), consistent with the check firing, but the response carried no failure cause matching the spec to confirm it precisely."}
        return {'final_verdict': CONDITION_NOT_TRIGGERED if applies_when else INCONCLUSIVE, 'confidence': 0.3, 'reasoning': f"coverage='{coverage}' is condition-scoped/ambiguous (applies_when={applies_when!r}) and oracle_verdict='{oracle_verdict}' (not denied) — whether this specific request triggered the condition can't be decided mechanically; use classify_with_ai to read the actual request body against applies_when."}
    explicit = 'explicit' in coverage
    no_check = 'not_identified' in coverage or 'operation_level' in coverage or 'procedural_eligibility_only' in coverage or (not coverage)
    protected_relation = resource_binding.get('protected_relation') or ''
    relation_suffix = f' (checked relation: {protected_relation})' if protected_relation else ''
    if explicit and denied:
        failure_causes = resource_binding.get('failure_causes') or []
        response_body = (runtime_result.get('response') or {}).get('body') or {}
        response_cause = response_body.get('cause') if isinstance(response_body, dict) else None
        protection_match = _protection_match(resource_binding, runtime_result)
        if protection_match == ALTERNATIVE_CHECK:
            return {'final_verdict': CHECK_CONFIRMED, 'protection_match': ALTERNATIVE_CHECK, 'confidence': 0.4, 'cause_mismatch': True, 'reasoning': f"coverage='{coverage}' (explicit) and oracle verdict is '{oracle_verdict}', but the observed status/cause does NOT match this case's declared failure_codes/failure_causes — the request WAS denied, but likely by a different check than the one this case describes {relation_suffix}. Treat as unconfirmed for this specific relation; verify against the actual denial mechanism before trusting this label."}
        confidence = 0.85 if failure_causes and response_cause in failure_causes else 0.7
        return {'final_verdict': CHECK_CONFIRMED, 'protection_match': protection_match, 'confidence': confidence, 'reasoning': f"coverage='{coverage}' (explicit) and oracle verdict is '{oracle_verdict}' — protection worked as specified{relation_suffix}."}
    if explicit and bypassed:
        return {'final_verdict': INCONCLUSIVE, 'confidence': 0.3, 'requires_normative_assessment': True, 'reasoning': f"coverage='{coverage}' (explicit) but oracle verdict is '{oracle_verdict}' — whether applying this check is mandatory or optional requires semantic assessment of the supplied spec analysis{relation_suffix}. Explicit coverage alone does not establish nonconformance."}
    if no_check and bypassed:
        return {'final_verdict': SPECIFICATION_GAP, 'confidence': 0.7, 'reasoning': f"coverage='{coverage or 'missing'}' (no check identified) and oracle verdict is '{oracle_verdict}' — a gap in the standard, not just the implementation."}
    if no_check and denied:
        return {'final_verdict': UNEXPECTED_PROTECTION, 'confidence': 0.5, 'reasoning': f"coverage='{coverage or 'missing'}' (no check required) but oracle verdict is '{oracle_verdict}' — implementation is stricter than the spec."}
    return {'final_verdict': INCONCLUSIVE, 'confidence': 0.2, 'reasoning': f"coverage='{coverage or 'missing'}' + oracle_verdict='{oracle_verdict}' did not match any rule in the truth table."}

def classify_with_ai(test_expectation: dict, runtime_result: dict, api_key: str, base_url: str='https://api.openai.com/v1', model: str=ai_client.DEFAULT_MODEL, completions_path: str='/chat/completions', normative_review: bool=False) -> dict:
    if not api_key:
        return {'final_verdict': None, 'confidence': 0.0, 'reasoning': 'No AI API key configured — deterministic classification stands.'}
    user_prompt = f'test_expectation:\n{json.dumps(test_expectation, indent=2, default=str)}\n\nruntime_result:\n{json.dumps(runtime_result, indent=2, default=str)}'
    try:
        return ai_client.call_chat_completion(system_prompt=SYSTEM_PROMPT if normative_review else _LEGACY_SYSTEM_PROMPT, user_prompt=user_prompt, api_key=api_key, base_url=base_url, model=model, completions_path=completions_path)
    except Exception as e:
        return {'final_verdict': None, 'confidence': 0.0, 'reasoning': f'AI classification error: {e} — deterministic classification stands.'}

def analyze(scenario: dict, evidence: dict, ai_config: dict) -> dict:
    test_expectation = build_test_expectation(scenario)
    runtime_result = build_runtime_result(evidence)
    deterministic = classify_deterministic(test_expectation, runtime_result)
    normative_review = deterministic.get('requires_normative_assessment', False)
    if normative_review:
        runtime_result = build_runtime_result(evidence, include_fixture_ids=True)
    non_comparable = runtime_result.get('oracle_verdict') in _NON_COMPARABLE_ORACLE_VERDICTS
    deterministic_needs_semantic_resolution = deterministic.get('final_verdict') in _AI_RESOLVABLE_DETERMINISTIC_VERDICTS
    hint_violated = 'execution_hint_violation' in deterministic
    state_setup_unverified = ((test_expectation or {}).get('execution_hint') or {}).get('status') == 'requires_state_setup'
    requester_mismatch = ((test_expectation or {}).get('requester_compatibility') or {}).get('status') in {'HINT_REQUESTER_MISMATCH', 'HINT_REQUESTER_UNSPECIFIED', 'UNSUPPORTED_IN_LAB', 'UNSUPPORTED_IN_LAB_FALLBACK'}
    cause_mismatch = deterministic.get('cause_mismatch', False)
    ai_result = None
    if ai_config.get('api_key') and deterministic_needs_semantic_resolution and (not non_comparable) and (not hint_violated) and (not cause_mismatch) and (not state_setup_unverified) and (not requester_mismatch):
        ai_result = classify_with_ai(test_expectation, runtime_result, api_key=ai_config.get('api_key', ''), base_url=ai_config.get('base_url', 'https://api.openai.com/v1'), completions_path=ai_config.get('completions_path', '/chat/completions'), normative_review=normative_review)
    if ai_result and ai_result.get('final_verdict') in _VALID_FINAL_VERDICTS:
        final_verdict, confidence, reasoning, source = (ai_result['final_verdict'], ai_result.get('confidence', 0.0), ai_result.get('reasoning', ''), 'ai')
    else:
        final_verdict, confidence, reasoning, source = (deterministic['final_verdict'], deterministic['confidence'], deterministic['reasoning'], 'deterministic')
    return {'test_expectation': test_expectation, 'runtime_result': runtime_result, 'deterministic': deterministic, 'ai': ai_result, 'final_verdict': final_verdict, 'protection_match': deterministic.get('protection_match') if final_verdict == CHECK_CONFIRMED else None, 'confidence': confidence, 'reasoning': reasoning, 'source': source}
