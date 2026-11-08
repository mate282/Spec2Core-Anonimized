from pathlib import Path
import openapi
import schema_validate

def _resolve_operation(specs_dir: Path, scenario: dict) -> tuple[dict | None, dict | None]:
    target = scenario.get('target', {})
    service = target.get('service')
    if not service:
        return (None, None)
    spec = openapi.resolve_spec(specs_dir, service)
    if spec is None:
        return (None, None)
    operation = openapi.find_operation(spec, target.get('method', ''), target.get('path_template', ''))
    if operation is None:
        return (None, None)
    return (spec, operation)

def get_request_content_type(specs_dir: Path, scenario: dict) -> str:
    _, operation = _resolve_operation(specs_dir, scenario)
    if operation is None:
        return 'application/json'
    return openapi.get_request_content_type(operation)

def body_is_required(specs_dir: Path, scenario: dict) -> bool:
    _, operation = _resolve_operation(specs_dir, scenario)
    if operation is None:
        return False
    return openapi.is_request_body_required(operation)

def body_default_empty_value(specs_dir: Path, scenario: dict) -> dict | list:
    body_schema, _ = load_operation_schema(specs_dir, scenario)
    if isinstance(body_schema, dict) and body_schema.get('type') == 'array':
        return []
    return {}

def load_operation_schema(specs_dir: Path, scenario: dict) -> tuple[dict | None, list[dict] | None]:
    spec, operation = _resolve_operation(specs_dir, scenario)
    if operation is None:
        return (None, None)
    body_schema = openapi.get_request_body_schema(spec, operation, specs_dir=specs_dir)
    query_schema = openapi.get_query_params_schema(spec, operation, specs_dir=specs_dir)
    body_schema = schema_validate.schema_for_request_validation(body_schema, operation)
    return (body_schema, query_schema)

def validate_request(specs_dir: Path, scenario: dict, payload, params) -> dict:
    body_schema, query_schema = load_operation_schema(specs_dir, scenario)
    if body_schema is None and query_schema is None:
        return {'valid': True, 'errors': [], 'schema_checked': False}
    errors = schema_validate.validate_body(body_schema, payload) + schema_validate.validate_query_params(query_schema, params)
    return {'valid': not errors, 'errors': errors, 'schema_checked': True}
