from datetime import datetime
import jsonschema
NON_SCHEMA_KEYS = ('_unrepresentable_binary_parts', '_binary_parts_content_type')
_FORMAT_CHECKER = jsonschema.FormatChecker()

@_FORMAT_CHECKER.checks('date-time', raises=ValueError)
def _check_date_time(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    datetime.fromisoformat(instance.replace('Z', '+00:00'))
    return True
_VALID_JSON_TYPES = {'object', 'array', 'string', 'integer', 'number', 'boolean', 'null'}

def sanitize(node):
    if isinstance(node, list):
        return [sanitize(n) for n in node]
    if not isinstance(node, dict):
        return node
    node = dict(node)
    t = node.get('type')
    if isinstance(t, str) and t not in _VALID_JSON_TYPES:
        node.pop('type', None)
        node.pop('enum', None)
    if isinstance(node.get('properties'), dict):
        node['properties'] = {k: sanitize(v) for k, v in node['properties'].items()}
    if 'items' in node:
        node['items'] = sanitize(node['items'])
    for key in ('anyOf', 'oneOf', 'allOf'):
        if key in node:
            node[key] = [sanitize(n) for n in node[key]]
    if 'not' in node:
        node['not'] = sanitize(node['not'])
    return node

def schema_for_request_validation(schema: dict | None, operation: dict | None) -> dict | None:
    return schema

def validate_body(schema: dict | None, payload) -> list[str]:
    if not schema:
        return []
    clean_schema = {k: v for k, v in schema.items() if k not in NON_SCHEMA_KEYS}
    if not clean_schema:
        return []
    clean_schema = sanitize(clean_schema)
    try:
        validator = jsonschema.Draft7Validator(clean_schema, format_checker=_FORMAT_CHECKER)
        checked_payload = payload if payload is not None else {}
        errors = sorted(validator.iter_errors(checked_payload), key=lambda e: list(e.path))
    except Exception:
        return []
    messages = []
    for e in errors:
        location = '/'.join((str(p) for p in e.path)) or '<root>'
        messages.append(f'{location}: {e.message}')
    return messages

def validate_query_params(schema_list: list[dict] | None, params) -> list[str]:
    errors = []
    params = params or {}
    for param in schema_list or []:
        name = param.get('name')
        if param.get('required') and name and (name not in params):
            errors.append(f"query param '{name}': required but missing")
    return errors
