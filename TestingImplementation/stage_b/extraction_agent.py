from __future__ import annotations
import json
import re
import ai_client
MAX_ITERATIONS = 6
HISTORY_WINDOW = 4
TOOL_SPECS: list[dict] = [{'type': 'function', 'function': {'name': 'read_logs', 'description': "Read a core network function's log. Use this to find a value that only appears in a running NF's own log output (e.g. a resource reference generated at runtime that is never written verbatim to the database). Some NFs log frequent periodic noise (keepalives, usage/charging reports every few seconds) that, on a long-running instance, can push the line you actually need far further back than any small tail guess — if a first read doesn't show what you're looking for, set `grep` and OMIT `tail`: that reads the entire log (no line limit) and returns only matching lines, which is both more thorough AND cheaper than guessing an ever-larger tail number.", 'parameters': {'type': 'object', 'properties': {'target': {'type': 'string', 'description': "Adapter-defined log target — the bare 3GPP NF type in lowercase (e.g. 'smf', 'amf', 'pcf', 'udm'). The task description may refer to a specific FIXTURE ROLE using a numbered/hyphenated label such as 'AMF-1' or 'PCF-2' (which of possibly several same-type instances owns/attacks the resource) — that label describes a role, not this parameter's literal value; every adapter in this project maps every fixture role of a given NF type to the SAME bare target name with no numeric suffix (e.g. both 'AMF-1' and 'AMF-2' read from target 'amf'). If a target returns an error (e.g. 'no such container') or an unexpectedly empty log, retry with the plain lowercase NF-type name before trying anything else."}, 'tail': {'type': 'integer', 'description': 'Number of trailing log lines to read BEFORE any grep filtering. Omit this entirely when you also set `grep` — the log is then read in full, with no line limit. Only set `tail` for a quick, small, unfiltered look (defaults to 500 when both `tail` and `grep` are omitted).'}, 'grep': {'type': 'string', 'description': "Optional regular expression filter (Python `re` syntax, case-sensitive, matched anywhere in the line — not a plain substring): only lines matching it are returned. Filtering happens after `tail`, so a grep-friendly pattern (e.g. 'sm-contexts', 'urn:uuid', or 'smContext.*deleted') lets you effectively search much further back than an unfiltered `tail` of the same size would let you read. An invalid pattern is reported back as an error, not silently ignored."}}, 'required': ['target']}}}, {'type': 'function', 'function': {'name': 'list_db_collections', 'description': "List every collection/table name currently in the core's datastore — use this FIRST to discover what's queryable before calling get_structured_doc() or read_db_state(), instead of guessing a collection name.", 'parameters': {'type': 'object', 'properties': {}}}}, {'type': 'function', 'function': {'name': 'read_db_state', 'description': "Schema-agnostic search across the whole datastore: returns every document/row, in any collection/table, whose serialized form contains the given substring (e.g. a SUPI). Use this to discover which collection and field holds a value when you don't already know the exact schema.", 'parameters': {'type': 'object', 'properties': {'identifier': {'type': 'string', 'description': 'Substring to search for, e.g. the SUPI.'}}, 'required': ['identifier']}}}, {'type': 'function', 'function': {'name': 'get_structured_doc', 'description': 'Precise single-document/row lookup by exact collection/table name + key field + key value — call this once you already know the schema (e.g. from list_db_collections()/read_db_state()).', 'parameters': {'type': 'object', 'properties': {'collection': {'type': 'string'}, 'key_field': {'type': 'string'}, 'key_value': {'type': 'string'}}, 'required': ['collection', 'key_field', 'key_value']}}}, {'type': 'function', 'function': {'name': 'check_data_plane_alive', 'description': "Returns true if there is currently a live data-plane path (e.g. an active PDU session tunnel) for the test UE. Useful to confirm a session-scoped resource actually exists before concluding it can't be found.", 'parameters': {'type': 'object', 'properties': {}}}}, {'type': 'function', 'function': {'name': 'verify_candidate', 'description': "Tests a VALUE YOU HAVE CONSTRUCTED (e.g. by combining two other identifiers you found elsewhere, such as an owner ID and a session number) by firing a real, read-only GET request against the target resource, authenticated as the resource's LEGITIMATE OWNER — never an attacker. Completely safe, no side effects. Use this whenever the value you're trying to resolve looks like it might be COMPOSED from other values already available to you, rather than a value you can just read verbatim out of a log or database row: construct a candidate, then call this to confirm or refute it empirically instead of guessing from text alone. Only works for resource types that actually have a real GET operation defined in their 3GPP spec — if not, this tells you that plainly instead of returning a misleading result, so you'll know to rely on read_logs()/read_db_state() instead.", 'parameters': {'type': 'object', 'properties': {'candidate_value': {'type': 'string', 'description': 'The identifier value you want to test for existence.'}}, 'required': ['candidate_value']}}}, {'type': 'function', 'function': {'name': 'submit_answer', 'description': 'Call this EXACTLY ONCE, when you are done — either with the exact value you found, or to report that it cannot currently be resolved. Never call any other tool after this one.', 'parameters': {'type': 'object', 'properties': {'resolved': {'type': 'boolean', 'description': 'true only if you found the exact value via a real tool result.'}, 'value': {'type': ['string', 'null'], 'description': 'The exact resolved value, or null if resolved is false.'}, 'confidence': {'type': 'number', 'description': '0.0-1.0 — how sure you are this exact value is correct.'}, 'reasoning': {'type': 'string', 'description': "Which tool result(s) this value came from, or why it couldn't be resolved."}}, 'required': ['resolved', 'value', 'confidence', 'reasoning']}}}]
SYSTEM_PROMPT = 'You are a security-testing assistant. Your ONLY job is to resolve one precise runtime value needed to build an HTTP request against a 5G Core Service-Based Interface (SBI) — e.g. a URL path variable identifying a specific resource instance.\n\nYou do not have direct access to the core\'s database or logs yourself — you can only see them through the tools you are given. Use them to find the EXACT value. Never guess or fabricate a plausible-looking value: this value is substituted directly into a real HTTP request, so a wrong answer breaks the request exactly as badly as no answer at all, and is worse than admitting you could not resolve it.\n\nWork methodically: prefer list_db_collections()/read_db_state() to discover what exists before calling get_structured_doc() with a guessed collection/field name. If the value is described as something generated at runtime with no fixed formula, it most likely only appears in a log, not a database row — try read_logs() on the NF most likely to have produced it.\n\nA log is a HISTORY, not a snapshot of current state — the same identifier can appear multiple times across its whole lifecycle (created, modified, and eventually released/deleted/not-found), and older entries for a since-destroyed instance of the resource are still sitting right next to current ones in the same tail window. A line reporting that a value was deleted/released/"not found" is evidence that value is now STALE, never evidence linking it to the resource you\'re currently looking for — do not treat "this identifier appears near/with the subject" as sufficient on its own; prefer the MOST RECENT creation/allocation-type evidence over an older mention, and if a candidate\'s own surrounding log lines show it was already torn down, that is a reason to discard it and keep looking, not a reason to submit it with high confidence.\n\nKeyword greps (e.g. "created", "allocated", "new") only work if the NF happens to log that exact wording — many do not. Most NFs ALSO log their own inbound HTTP handling as one line per request (request method, response status, and the request path), independently of whatever wording they use for application-level events — and the identifier you\'re looking for is typically embedded directly in that path on every request that touches the resource, starting with the one that created it. If a semantic keyword grep comes up empty, try grepping for the resource\'s own URL PATH SHAPE instead (the same path template this request will use, or just the identifier\'s literal syntax/prefix, e.g. a UUID pattern) — this catches every request line touching any instance of this resource type, creation included, regardless of what application-level wording (if any) accompanies it. When you find candidates this way, a line paired with a successful (2xx) response status is stronger evidence of a currently-valid resource than a later line for the same value paired with an error status (4xx) — an error response on a request that would only fail for an already-gone resource is itself a "now STALE" signal, exactly like an explicit "deleted"/"not found" line.\n\nSome identifiers are not read verbatim from anywhere — they are COMPOSED by the target system from other, more basic values (e.g. an owner\'s own ID combined with a session number). If the description suggests this, or if plain log/database search keeps turning up nothing, consider whether the value might be a predictable combination of other identifiers you already know or can find (read_logs()/read_db_state() first, to gather candidate building blocks) — then construct a candidate and call verify_candidate() to test it empirically rather than submitting a guess you never actually confirmed.\n\nWhen you are confident you have found the exact value (from a real tool result, not from context alone), or have concluded after genuinely trying that it cannot currently be resolved, call `submit_answer` exactly once. Do not call it speculatively before you\'ve actually looked.'

def _verify_candidate(candidate: str, verify_ctx: dict) -> dict:
    import spec_evidence
    import resolvers
    scenario = verify_ctx['scenario']
    cfg = verify_ctx['cfg']
    adapter = verify_ctx['adapter']
    var_name = verify_ctx['var_name']
    known_vars = verify_ctx.get('known_path_vars', {})
    specs_dir = verify_ctx['specs_dir']
    service = scenario['target']['service']
    path_template = scenario['request']['path_template']
    if not spec_evidence.has_standard_get(specs_dir, service, path_template):
        return {'error': "No standard GET operation exists for this resource type in the 3GPP spec — a non-200 response here would be indistinguishable from 'wrong path entirely', so this tool cannot verify candidates for this resource type. Use read_logs()/read_db_state() instead."}
    try:
        url = resolvers.build_url(scenario, cfg, {**known_vars, var_name: candidate}, adapter)
    except Exception as e:
        return {'error': f'could not build a request URL for this candidate: {e}'}
    body = spec_evidence.read_via_standard_get(cfg, scenario, url, verify_ctx['owner_id'], verify_ctx['owner_role'], verify_ctx['actor_nf_type'])
    if body is None:
        return {'found': False, 'note': "A GET as the resource's real owner did NOT return 200 for this candidate — either it does not exist, or the owner's own read failed for an unrelated reason. Do not treat this alone as proof the candidate is wrong; try another candidate or gather more evidence first."}
    return {'found': True, 'note': "A GET as the resource's real owner returned 200 for this candidate — confirmed to refer to a real, existing resource.", 'body_preview': body}

def _execute_tool(name: str, args: dict, adapter, verify_ctx: dict | None=None) -> object:
    try:
        if name == 'read_logs':
            grep = args.get('grep')
            tail_arg = args.get('tail')
            if tail_arg is not None:
                tail = int(tail_arg)
            elif grep:
                tail = None
            else:
                tail = 500
            text = adapter.read_logs(args['target'], tail)
            if grep:
                pattern = re.compile(grep)
                total_lines = text.splitlines()
                matched = [line for line in total_lines if pattern.search(line)]
                if not matched and len(total_lines) <= 3:
                    return f"0 matching lines, but the target itself only returned {len(total_lines)} line(s) total before filtering — this usually means '{args['target']}' is not a valid log target (wrong name), not that the pattern has no real matches. Raw content: {text!r}"
                text = '\n'.join(matched)
            return text
        if name == 'list_db_collections':
            return adapter.list_db_collections()
        if name == 'read_db_state':
            return adapter.read_db_state(args['identifier'])
        if name == 'get_structured_doc':
            return adapter.get_structured_doc(args['collection'], args['key_field'], args['key_value'])
        if name == 'check_data_plane_alive':
            return adapter.check_data_plane_alive()
        if name == 'verify_candidate':
            if verify_ctx is None:
                return {'error': 'verify_candidate is not available for this identifier'}
            return _verify_candidate(args['candidate_value'], verify_ctx)
        return {'error': f'unknown tool {name!r}'}
    except Exception as e:
        return {'error': str(e)}

def _truncate(value: object, max_chars: int=4000) -> object:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if len(text) <= max_chars:
        return value
    return text[-max_chars:]

def _windowed_messages(messages: list[dict], window: int=HISTORY_WINDOW) -> list[dict]:
    tool_indices = [i for i, m in enumerate(messages) if m.get('role') == 'tool']
    keep = set(tool_indices[-window:]) if window > 0 else set()
    windowed = []
    for i, m in enumerate(messages):
        if m.get('role') == 'tool' and i not in keep:
            m = {**m, 'content': '[older tool result omitted to keep the request size bounded — call the tool again if you need to re-check it]'}
        windowed.append(m)
    return windowed

def _value_seen_in_trace(value: str, trace: list[dict]) -> bool:
    for entry in trace:
        for field in ('result', 'arguments'):
            data = entry.get(field)
            if data is None:
                continue
            text = data if isinstance(data, str) else json.dumps(data, default=str)
            if value in text:
                return True
    return False

def resolve_identifier(*, var_name: str, description: str, adapter, api_key: str, base_url: str='https://api.openai.com/v1', model: str=ai_client.DEFAULT_MODEL, completions_path: str='/chat/completions', max_iterations: int=MAX_ITERATIONS, history_window: int=HISTORY_WINDOW, timeout: int=30, verify_ctx: dict | None=None) -> dict:
    trace: list[dict] = []
    if not api_key:
        return {'resolved': False, 'value': None, 'confidence': 0.0, 'reasoning': 'No AI API key configured', 'trace': trace}
    messages = [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': f'Resolve the value for: {var_name}\n\nDescription: {description}'}]
    for _ in range(max_iterations):
        try:
            assistant_msg = ai_client.call_chat_completion_with_tools(messages=_windowed_messages(messages, history_window), api_key=api_key, base_url=base_url, model=model, completions_path=completions_path, tools=TOOL_SPECS, timeout=timeout)
        except Exception as e:
            return {'resolved': False, 'value': None, 'confidence': 0.0, 'reasoning': f'AI call error: {e}', 'trace': trace}
        tool_calls = assistant_msg.get('tool_calls') or []
        messages.append({'role': 'assistant', 'content': assistant_msg.get('content'), 'tool_calls': tool_calls})
        if not tool_calls:
            trace.append({'tool': None, 'arguments': None, 'result': assistant_msg.get('content')})
            return {'resolved': False, 'value': None, 'confidence': 0.0, 'reasoning': 'Model responded without calling submit_answer — treated as unresolved.', 'trace': trace}
        for call in tool_calls:
            fn = call.get('function', {})
            name = fn.get('name')
            try:
                args = json.loads(fn.get('arguments') or '{}')
            except json.JSONDecodeError:
                args = {}
            if name == 'submit_answer':
                value = args.get('value')
                resolved = bool(args.get('resolved'))
                if resolved and value and (not _value_seen_in_trace(str(value), trace)):
                    trace.append({'tool': name, 'arguments': args, 'result': 'REJECTED: value not found in any tool result observed this session — treated as ungrounded, not a real answer.'})
                    return {'resolved': False, 'value': None, 'confidence': 0.0, 'reasoning': f"Rejected ungrounded submit_answer ({value!r} never appeared in any tool result collected this session — likely fabricated, or the model relied on evidence collapsed out of its own view by the history window). Model's original reasoning: {args.get('reasoning', '')!r}", 'trace': trace}
                trace.append({'tool': name, 'arguments': args, 'result': None})
                return {'resolved': resolved, 'value': value, 'confidence': float(args.get('confidence') or 0.0), 'reasoning': args.get('reasoning', ''), 'trace': trace}
            result = _execute_tool(name, args, adapter, verify_ctx)
            trace.append({'tool': name, 'arguments': args, 'result': result})
            messages.append({'role': 'tool', 'tool_call_id': call.get('id'), 'content': json.dumps(_truncate(result), default=str)})
    return {'resolved': False, 'value': None, 'confidence': 0.0, 'reasoning': f'Exceeded max_iterations ({max_iterations}) without submit_answer.', 'trace': trace}
