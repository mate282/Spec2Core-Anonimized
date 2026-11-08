import json
import requests
DEFAULT_MODEL = 'gpt-6-luna'
_usage_totals = {'calls': 0, 'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}

def get_usage_totals() -> dict:
    return dict(_usage_totals)

def reset_usage_totals() -> None:
    for k in _usage_totals:
        _usage_totals[k] = 0
SYSTEM_PROMPT = 'You are a security researcher specializing in 5G Core SBI vulnerabilities (resource-level authorization bypass).\n\nYou are given the metadata of an attack, including the fully-resolved OpenAPI JSON schema for the\nrequest body (types, required fields, enum values, patterns, nested objects/arrays) and, for GET/\nquery-filterable operations, the fully-resolved list of `in: query` parameters. You must produce:\n1. payload_example: a concrete HTTP body that semantically realizes the attack\n2. query_params_example: concrete query string parameters that make the request return real,\n   ownership-sensitive data instead of an empty/default response\n3. binary_parts_example: for operations whose schema declares "_unrepresentable_binary_parts",\n   the multipart/related binary parts actually needed to realize the attack (see MANDATORY BINARY\n   PARTS RULES below) — otherwise {}\n4. pre_checks: list of checks to perform BEFORE the attack\n5. post_checks: list of checks to perform AFTER the attack to prove its effect\n6. security_statement: one sentence describing which ownership invariant should be enforced\n\nMANDATORY PAYLOAD RULES (schema-driven — the schema is the source of truth, not prior examples):\n- USE ONLY THE FIELDS MARKED AS REQUIRED IN THE SCHEMA, PLUS THOSE NAMED BY AN EXECUTION HINT\n  SECTION BELOW (if one is present) — NOTHING ELSE. This is a hard limit, not a default: do NOT add\n  an optional field just because it seems relevant, realistic, or "essential to the attack\'s\n  narrative" in your own judgment. A field\'s presence in payload_example is decided ONLY by (a) the\n  schema\'s own "required" list and (b) an EXECUTION HINT\'s explicit field list — never by your\n  assessment of what a real attacker would plausibly send. This applies with no exception to fields\n  that carry an identity/instance-ID value (e.g. an NF instance ID, a GUAMI, a callback URI) even\n  though such a field looks directly relevant to an ownership-bypass test: an optional identity\n  field you invent a placeholder value for is *not* tested correctly, because nothing downstream\n  knows to substitute that placeholder with the actual attacker\'s runtime identity — it ships as a\n  fabricated, meaningless UUID/string instead, which corrupts the test rather than strengthening it.\n  Whether an optional field like that should be added, and how its value should be resolved, is a\n  decision for the execution hint / human review / the runtime field-semantics table to make\n  explicitly — never something to default into at draft time because it "seems essential"\n- If a user message includes an "EXECUTION HINT" section, treat its field list as ADDITIONAL to\n  this schema, never a replacement: the schema still governs every field\'s type/enum/pattern\n  (including any field the hint names), the hint only adds which optional fields must also be\n  included (and, where stated, exactly what value they must hold) or must be left out entirely\n- Match every field\'s JSON type EXACTLY as declared in the schema:\n    - a field typed "integer" or "number" must be a JSON number, never a quoted string\n    - a field typed "object" must be a JSON object with its own required sub-fields filled in\n      recursively (per this same schema), never a string or number standing in for it\n    - a field typed "boolean" must be a JSON boolean\n- If a schema node has an "enum" (directly or inside "anyOf"/"oneOf"), the value MUST be exactly\n  one of the listed strings — never invent a plausible-sounding value that isn\'t in the list\n- If a schema node has a "pattern", the value must match that regex (e.g. a fixed digit count)\n- Respect "minimum"/"maximum" bounds on numeric fields\n- Do NOT use the field name as its own value (e.g. do NOT write: imsVoPs: "imsVoPs")\n- The identifier already substituted into the path template (e.g. {supi}/{ueId}/{ueContextId}) is\n  handled separately at request time — do NOT invent an extra copy of it as a body field under a\n  different name just because it identifies the same resource. This is NOT a reason to omit a field\n  from the body, though: several real 3GPP operations legitimately declare a body property literally\n  named "supi", "pei", or similar (e.g. CancelPosInfo.supi, Amf3GppAccessRegistrationModification.pei)\n  that is distinct from the path identifier and must be included like any other field the schema\n  lists. The field\'s NAME is never grounds to include or exclude it — only the schema is\n- Some schema nodes represent a reference to out-of-band binary data (an object whose only\n  meaningful property is a "contentId" string — this is the 3GPP RefToBinaryData pattern, used\n  for NAS/NGAP messages normally carried in a multipart/related body part). These fields DO stay\n  inside payload_example as normal JSON objects (e.g. {"contentId": "n1sm_example"}) — the\n  "contentId" value you choose here MUST be reused verbatim as the "content_id" of the matching\n  entry in binary_parts_example (see MANDATORY BINARY PARTS RULES below), since that\'s how the\n  JSON side points at the out-of-band binary part.\n- If the schema has a top-level "_unrepresentable_binary_parts" list, those are real 3GPP fields\n  (named exactly as listed) that this operation requires as separate binary multipart/related body\n  parts — they are NOT part of the JSON schema shown and must NOT appear inside payload_example as\n  JSON fields. Build payload_example from the rest of the schema only; declare these parts in\n  binary_parts_example instead (see below). Never invent a substitute JSON field to stand in for a\n  missing binary part.\n- If the schema is empty ({}), say so plainly in "reasoning" (e.g. "no requestBody schema could be\n  resolved for this operation") and set confidence to 0.0 — do not invent a payload from the\n  endpoint name or test idea alone, and never repeat/nest a field name as its own value trying to\n  "fill" an unknown shape.\n- Base the payload strictly on the provided schema, not on field-name guessing\n\nMANDATORY BINARY PARTS RULES (only relevant when the schema has a top-level\n"_unrepresentable_binary_parts" list):\n- For each binary part actually needed to realize the attack (usually the ones referenced by a\n  RefToBinaryData "contentId" you placed in payload_example — not necessarily every part the\n  operation could ever declare, e.g. an optional part unrelated to this attack\'s fields), add an\n  entry to binary_parts_example keyed by the part\'s exact name:\n  "binary_parts_example": {"<partName>": {"content_id": "<string>", "placeholder_hex": "<hex bytes>"}}\n- "content_id" MUST exactly match the "contentId" string used inside payload_example\'s matching\n  RefToBinaryData object — this is how the JSON part references the binary part on the wire.\n- "placeholder_hex" does NOT need to decode to a real NAS/NGAP/PFCP/SMS message — a handful of\n  arbitrary bytes (e.g. "00" or "0001") are enough to satisfy the producer\'s "binary data must not\n  be empty" check. Do not attempt to fabricate a real protocol message.\n- Do NOT include "content_type" — that is filled in deterministically from the OpenAPI spec\'s\n  encoding block, not guessed by you.\n- Because the binary content itself is fake (not real protocol data), set "confidence" to at most\n  0.3 for this operation\'s payload and say so explicitly in "reasoning": this lets the request\n  reach the ownership check under test, but the result proves nothing about NAS/NGAP-level\n  correctness.\n- If the schema has no "_unrepresentable_binary_parts" list, return binary_parts_example: {}.\n\nMANDATORY QUERY PARAMS RULES (schema-driven, same posture as the payload rules above):\n- Include every query parameter listed as "required": true, plus any additional parameter that is\n  strictly necessary to make the endpoint return real, non-empty, ownership-sensitive data (e.g. a\n  parameter that selects which subset of a UE\'s data is returned, or that switches a response\n  between an empty default and a populated one) — omitting these produces a technically-successful\n  but evidentially-useless response, not proof of a bypass either way\n- Match each parameter\'s JSON type EXACTLY as declared in its "schema" (string/number/boolean/object/\n  array) — a query parameter whose schema is "type": "object" (e.g. a PLMN ID) must be produced as a\n  real JSON object in query_params_example, not a flattened string; the caller is responsible for\n  wire-level serialization\n- If a parameter\'s schema has an "enum" (directly or inside "anyOf"/"oneOf"), the value MUST be\n  exactly one of the listed strings\n- Do NOT invent a query parameter that isn\'t in the provided list\n- If the query parameter list is empty, return query_params_example: {} — do not invent one from the\n  endpoint name or test idea alone\n- Respond with valid JSON ONLY (no extra text before or after)\n\nSECURITY RULES:\n- Do NOT change who the owner is and who the attacker is\n- Do NOT change the required OAuth2 scope\n- Do NOT classify a bare HTTP 2xx as proof of vulnerability without a verifiable side effect\n'
VULN_CLASSIFIER_PROMPT = 'You are a security researcher analyzing 5G Core SBI resource-ownership attacks.\n\nYou are given free-text notes describing whether an endpoint has an ownership check, plus the\nattack\'s test idea and expected binding. Decide whether a resource-level authorization bypass is\nEXPECTED (a hypothesis to be confirmed experimentally, not a final verdict).\n\nRespond with this JSON only:\n{\n  "expected_vulnerable": true | false | null,\n  "confidence": 0.0-1.0,\n  "reasoning": ""\n}\n\nRules:\n- true  -> the text indicates no explicit ownership/ownership-binding check is performed\n- false -> the text indicates an explicit ownership check (e.g. matching GUAMI, serving AMF ID) is performed\n- null  -> the text is missing, is just "?", or is genuinely ambiguous — do not guess\n- confidence must be 0.0 if you returned null\n'

def call_chat_completion(system_prompt: str, user_prompt: str, api_key: str, base_url: str='https://api.openai.com/v1', model: str=DEFAULT_MODEL, completions_path: str='/chat/completions', temperature: float | None=None, timeout: int=30) -> dict:
    payload = {'model': model, 'messages': [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}], 'response_format': {'type': 'json_object'}}
    if temperature is not None:
        payload['temperature'] = temperature
    resp = requests.post(f'{base_url.rstrip('/')}/{completions_path.lstrip('/')}', headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}, json=payload, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    usage = body.get('usage') or {}
    _usage_totals['calls'] += 1
    _usage_totals['prompt_tokens'] += usage.get('prompt_tokens', 0)
    _usage_totals['completion_tokens'] += usage.get('completion_tokens', 0)
    _usage_totals['total_tokens'] += usage.get('total_tokens', 0)
    content = body['choices'][0]['message']['content']
    return json.loads(content)

def call_chat_completion_with_tools(messages: list[dict], api_key: str, base_url: str='https://api.openai.com/v1', model: str=DEFAULT_MODEL, completions_path: str='/chat/completions', tools: list[dict] | None=None, temperature: float | None=None, timeout: int=30) -> dict:
    payload = {'model': model, 'messages': messages}
    if temperature is not None:
        payload['temperature'] = temperature
    if tools:
        payload['tools'] = tools
        payload['tool_choice'] = 'auto'
        payload['reasoning_effort'] = 'none'
    resp = requests.post(f'{base_url.rstrip('/')}/{completions_path.lstrip('/')}', headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()['choices'][0]['message']

def classify_vulnerability_expectation(existing_protection: str, test_idea: str, expected_binding: str, api_key: str, base_url: str='https://api.openai.com/v1', model: str=DEFAULT_MODEL, completions_path: str='/chat/completions') -> dict:
    if not api_key:
        return {'expected_vulnerable': None, 'confidence': 0.0, 'reasoning': 'No AI API key configured — falling back to the deterministic text heuristic'}
    user_prompt = f'Existing protection: {existing_protection}\nTest idea: {test_idea}\nExpected binding: {expected_binding}'
    try:
        return call_chat_completion(system_prompt=VULN_CLASSIFIER_PROMPT, user_prompt=user_prompt, api_key=api_key, base_url=base_url, model=model, completions_path=completions_path)
    except Exception as e:
        return {'expected_vulnerable': None, 'confidence': 0.0, 'reasoning': f'AI classification error: {e} — falling back to the deterministic text heuristic'}

def enrich_with_ai(service: str, method: str, path_template: str, test_idea: str, expected_binding: str, existing_protection: str, openapi_schema: dict, api_key: str, base_url: str='https://api.openai.com/v1', model: str=DEFAULT_MODEL, completions_path: str='/chat/completions', query_params_schema: list | None=None, path_params_schema: list | None=None, header_params_schema: list | None=None, validation_feedback: dict | None=None, execution_hint: dict | None=None) -> dict:
    if not api_key:
        return _placeholder('No API key configured — add one with --ai-key')
    schema_json = json.dumps(openapi_schema, indent=2) if openapi_schema else '{}'
    query_params_json = json.dumps(query_params_schema, indent=2) if query_params_schema else '[]'
    path_params_block = ''
    if path_params_schema:
        path_params_block = f"\n\nPath parameters declared on this operation (fully resolved — name, required, schema). These are\nCONTEXT ONLY: the runtime test harness resolves their actual values (SUPI, smPolicyId,\nueContextId, ...), never you — do NOT add these as payload_example or query_params_example fields,\nand do NOT invent a value for them anywhere in your response. They're given so you understand the\nfull shape of the request this payload will be part of, and so a related body field (e.g. one that\nmust stay consistent with a path parameter's format) isn't drafted in isolation:\n{json.dumps(path_params_schema, indent=2)}"
    header_params_block = ''
    if header_params_schema:
        header_params_block = f'\n\nCustom header parameters declared on this operation (fully resolved — name, required, schema).\nSame CONTEXT ONLY rule as the path parameters above — these are set by the runtime HTTP layer\n(authentication, correlation IDs, ...), not by you; do not add them to payload_example or\nquery_params_example:\n{json.dumps(header_params_schema, indent=2)}'
    hint_block = ''
    if execution_hint:
        required_fields = execution_hint.get('body_required_fields') or []
        required_values = execution_hint.get('body_required_values') or {}
        any_of_fields = execution_hint.get('body_any_of_fields') or []
        absent_fields = execution_hint.get('body_absent_fields') or []
        query_required_fields = execution_hint.get('query_required_fields') or []
        query_required_values = execution_hint.get('query_required_values') or {}
        query_any_of_fields = execution_hint.get('query_any_of_fields') or []
        query_absent_fields = execution_hint.get('query_absent_fields') or []
        state_preconds = execution_hint.get('state_preconditions') or []
        variant = execution_hint.get('representative_variant') or ''
        lines = []
        if variant:
            lines.append(f'- Representative variant: {variant}')
        if required_fields:
            lines.append(f"- Fields that MUST be present in payload_example (additional to the schema's own required list — omitting these would select a DIFFERENT case at this same endpoint): {required_fields}")
        if required_values:
            lines.append(f'- Fields that MUST be present with EXACTLY these values (not just any value of the right type): {json.dumps(required_values)}')
        if any_of_fields:
            lines.append(f'- At least ONE of these fields must be present: {any_of_fields}')
        if absent_fields:
            lines.append(f'- Fields that MUST NOT appear in payload_example at all (including any of them would select a different authorization case): {absent_fields}')
        if query_required_fields:
            lines.append(f'- Query parameters that MUST be present in query_params_example: {query_required_fields}')
        if query_required_values:
            lines.append(f'- Query parameters that MUST have EXACTLY these values: {json.dumps(query_required_values)}')
        if query_any_of_fields:
            lines.append(f'- At least ONE of these query parameters must be present: {query_any_of_fields}')
        if query_absent_fields:
            lines.append(f'- Query parameters that MUST NOT appear in query_params_example (they select another case): {query_absent_fields}')
        if state_preconds:
            lines.append("- Runtime state this case additionally assumes (informational — this payload alone cannot create it, do not try to represent it as a body field unless it's already one of the fields listed above): " + '; '.join(state_preconds))
        if lines:
            hint_block = '\n\nEXECUTION HINT for this specific authorization case (additional to the MANDATORY PAYLOAD and QUERY PARAMS RULES):\n' + '\n'.join(lines)
    feedback_block = ''
    if validation_feedback:
        prev_payload = json.dumps(validation_feedback.get('payload_example') or {}, indent=2)
        prev_query = json.dumps(validation_feedback.get('query_params_example') or {}, indent=2)
        prev_binary_parts = json.dumps(validation_feedback.get('binary_parts_example') or {}, indent=2)
        errors = '\n'.join((f'- {e}' for e in validation_feedback.get('errors', [])))
        feedback_block = f"""\n\nYOUR PREVIOUS ATTEMPT FAILED VALIDATION. It was checked field-by-field against the exact schema\nabove (jsonschema Draft 7) and, when one was given, the EXECUTION HINT constraints — these\nviolations were found (a violation starting with "execution hint:" comes from the hint, not the\nJSON schema itself — the hint's constraint still stands even where the schema alone would allow the\nfield to be absent or optional):\n{errors}\n\nPrevious payload_example:\n{prev_payload}\n\nPrevious query_params_example:\n{prev_query}\n\nPrevious binary_parts_example:\n{prev_binary_parts}\n\nReturn a corrected payload_example/query_params_example/binary_parts_example that fixes EVERY\nviolation listed above — change only the value(s)/field(s) that were flagged (e.g. if a "pattern"\nmismatch was reported, produce a value that actually matches that regex, do not just approximate it;\nif binary_parts_example was reported missing/empty, add an entry per MANDATORY BINARY PARTS RULES\nabove for whichever of the listed part names your payload_example actually references via a\nRefToBinaryData "contentId" — not necessarily every one, do not return {{}} again, and do not add an\nentry for a part your payload_example never references), keep every other field exactly as it was in\nthe previous attempt."""
    user_prompt = f'Enrich this 5G SBI attack specification.\n\nService: {service}\nEndpoint: {method} {path_template}\nTest idea: {test_idea}\nExpected binding: {expected_binding}\nExisting protection: {existing_protection}\n\nrequestBody JSON schema (fully resolved from the 3GPP OpenAPI spec — types, required fields, enum\nvalues, patterns, nested objects/arrays; follow it exactly, see MANDATORY PAYLOAD RULES):\n{schema_json}\n\nQuery parameters declared on this operation (fully resolved — name, required, schema; follow them\nexactly, see MANDATORY QUERY PARAMS RULES):\n{query_params_json}{path_params_block}{header_params_block}{hint_block}{feedback_block}\n\nRespond with this JSON (all fields mandatory):\n{{\n  "payload_example": {{}},\n  "payload_description": "",\n  "query_params_example": {{}},\n  "binary_parts_example": {{}},\n  "pre_checks": [],\n  "post_checks": [],\n  "security_statement": "",\n  "confidence": 0.0,\n  "reasoning": ""\n}}'
    try:
        return call_chat_completion(system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, api_key=api_key, base_url=base_url, model=model, completions_path=completions_path)
    except Exception as e:
        return _placeholder(f'AI error: {e}')

def _placeholder(reason: str) -> dict:
    return {'payload_example': {}, 'payload_description': f'[{reason} — fill in manually in the review file]', 'query_params_example': {}, 'binary_parts_example': {}, 'pre_checks': [], 'post_checks': [], 'security_statement': '', 'confidence': 0.0, 'reasoning': reason}
