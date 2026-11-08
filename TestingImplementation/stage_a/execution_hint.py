_MISSING = object()

def dotted_get(payload: dict, path: str):
    node = payload
    for segment in path.split('.'):
        if not isinstance(node, dict) or segment not in node:
            return _MISSING
        node = node[segment]
    return node

def check_conformance(payload: dict, hint: dict | None, query_params: dict | None=None) -> list[str]:
    if not hint:
        return []
    payload = payload if payload is not None else {}
    query_params = query_params or {}
    errors: list[str] = []
    for field in hint.get('body_required_fields') or []:
        if dotted_get(payload, field) is _MISSING:
            errors.append(f"execution hint: required field '{field}' is missing from payload_example (needed to select this authorization case, not just the OpenAPI schema's own required list)")
    for field, expected in (hint.get('body_required_values') or {}).items():
        actual = dotted_get(payload, field)
        if actual is _MISSING:
            errors.append(f"execution hint: field '{field}' must be present with value {expected!r} but is missing from payload_example")
        elif isinstance(actual, list):
            if expected != actual and expected not in actual:
                errors.append(f"execution hint: field '{field}' must include {expected!r} in its list value to select this authorization case, but payload_example has {actual!r}")
        elif actual != expected:
            errors.append(f"execution hint: field '{field}' must equal {expected!r} to select this authorization case, but payload_example has {actual!r}")
    any_of = hint.get('body_any_of_fields') or []
    if any_of and (not any((dotted_get(payload, field) is not _MISSING for field in any_of))):
        errors.append(f'execution hint: at least one of {any_of} must be present in payload_example, but none of them are')
    for field in hint.get('body_absent_fields') or []:
        if dotted_get(payload, field) is not _MISSING:
            errors.append(f"execution hint: field '{field}' must be ABSENT from payload_example — including it would select a different authorization case at this same endpoint")
    for field in hint.get('query_required_fields') or []:
        if field not in query_params:
            errors.append(f"execution hint: required query parameter '{field}' is missing from query_params_example (needed to select this authorization case)")
    for field, expected in (hint.get('query_required_values') or {}).items():
        if field not in query_params:
            errors.append(f"execution hint: query parameter '{field}' must be present with value {expected!r} but is missing from query_params_example")
            continue
        actual = query_params[field]
        if isinstance(actual, list):
            if expected != actual and expected not in actual:
                errors.append(f"execution hint: query parameter '{field}' must include {expected!r} but query_params_example has {actual!r}")
        elif actual != expected:
            errors.append(f"execution hint: query parameter '{field}' must equal {expected!r} but query_params_example has {actual!r}")
    query_any_of = hint.get('query_any_of_fields') or []
    if query_any_of and (not any((field in query_params for field in query_any_of))):
        errors.append(f'execution hint: at least one of query parameters {query_any_of} must be present in query_params_example, but none of them are')
    for field in hint.get('query_absent_fields') or []:
        if field in query_params:
            errors.append(f"execution hint: query parameter '{field}' must be ABSENT from query_params_example — including it would select a different authorization case at this same endpoint")
    return errors

def needs_state_setup(hint: dict | None) -> bool:
    return hint is not None and hint.get('status') != 'executable'
