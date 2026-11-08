import re
from urllib.parse import urlsplit
from pathlib import Path
SERVICE_BUNDLE_ALIASES = {'Namf_Comm': 'Namf_Communication'}
_SPEC_FILE_CACHE: dict[tuple[str, str], Path | None] = {}
_SPEC_CACHE: dict[tuple[str, str], dict | None] = {}

def find_spec_file(specs_dir: Path, service: str) -> Path | None:
    cache_key = (str(specs_dir), service)
    if cache_key not in _SPEC_FILE_CACHE:
        bundle_service = SERVICE_BUNDLE_ALIASES.get(service, service)
        pattern = f'{bundle_service}_bundled.yaml'
        matches = sorted(specs_dir.rglob(pattern))
        _SPEC_FILE_CACHE[cache_key] = matches[0] if matches else None
    return _SPEC_FILE_CACHE[cache_key]

def resolve_spec(specs_dir: Path, service: str) -> dict | None:
    import yaml
    cache_key = (str(specs_dir), service)
    if cache_key not in _SPEC_CACHE:
        path = find_spec_file(specs_dir, service)
        if path is None:
            _SPEC_CACHE[cache_key] = None
        else:
            with open(path, encoding='utf-8') as f:
                _SPEC_CACHE[cache_key] = yaml.safe_load(f)
    return _SPEC_CACHE[cache_key]

def get_service_scope(spec: dict) -> str | None:
    servers = spec.get('servers', [])
    if not servers:
        return None
    url = servers[0].get('url', '')
    path = urlsplit(url).path or url
    static_part = _strip_uri_template_vars(path).strip('/')
    if not static_part:
        return None
    scope = re.sub('/v\\d+$', '', static_part)
    return scope or None

def find_operation(spec: dict, method: str, path_input: str) -> dict | None:
    path_normalized = _strip_base_path(spec, path_input)
    for spec_path, path_item in spec.get('paths', {}).items():
        if _paths_match_structurally(spec_path, path_normalized):
            op = path_item.get(method.lower())
            if op:
                return {'_path': spec_path, '_method': method.upper(), **op}
    return None

def get_request_body_schema(spec: dict, operation: dict, specs_dir: Path | None=None) -> dict:
    req_body = operation.get('requestBody', {})
    if not req_body:
        return {}
    content = req_body.get('content', {})
    if 'application/json' in content:
        schema = _resolve_schema(content['application/json'].get('schema', {}), spec, seen=frozenset(), specs_dir=specs_dir)
    elif 'application/merge-patch+json' in content:
        schema = _resolve_schema(content['application/merge-patch+json'].get('schema', {}), spec, seen=frozenset(), specs_dir=specs_dir)
    elif 'application/json-patch+json' in content:
        schema = _resolve_schema(content['application/json-patch+json'].get('schema', {}), spec, seen=frozenset(), specs_dir=specs_dir)
    elif 'multipart/related' in content:
        return _resolve_multipart_schema(content['multipart/related'], spec, specs_dir)
    else:
        return {}
    if 'multipart/related' in content:
        multipart_extra = _resolve_multipart_schema(content['multipart/related'], spec, specs_dir)
        for key in ('_unrepresentable_binary_parts', '_binary_parts_content_type'):
            if key in multipart_extra:
                schema[key] = multipart_extra[key]
    return schema

def _resolve_multipart_schema(multipart_content: dict, spec: dict, specs_dir: Path | None=None) -> dict:
    schema = multipart_content.get('schema', {})
    properties = schema.get('properties', {})
    encoding = multipart_content.get('encoding', {})
    binary_parts = [name for name, prop in properties.items() if isinstance(prop, dict) and prop.get('format') == 'binary']
    json_parts = {name: prop for name, prop in properties.items() if name not in binary_parts}
    if 'jsonData' in json_parts:
        resolved = _resolve_schema(json_parts['jsonData'], spec, seen=frozenset(), specs_dir=specs_dir)
    else:
        resolved = {'type': 'object', 'properties': {name: _resolve_schema(prop, spec, seen=frozenset(), specs_dir=specs_dir) for name, prop in json_parts.items()}}
    if binary_parts:
        resolved['_unrepresentable_binary_parts'] = binary_parts
        resolved['_binary_parts_content_type'] = {name: encoding.get(name, {}).get('contentType', 'application/octet-stream') for name in binary_parts}
    return resolved

def get_request_content_type(operation: dict) -> str:
    content = (operation.get('requestBody') or {}).get('content', {})
    if 'application/merge-patch+json' in content:
        return 'application/merge-patch+json'
    if 'application/json-patch+json' in content:
        return 'application/json-patch+json'
    return 'application/json'

def is_request_body_required(operation: dict) -> bool:
    return bool((operation.get('requestBody') or {}).get('required', False))

def _extract_params_by_location(spec: dict, operation: dict, location: str, specs_dir: Path | None=None) -> list[dict]:
    result = []
    for param in operation.get('parameters', []):
        param_spec = spec
        if isinstance(param, dict) and '$ref' in param:
            param, param_spec = _resolve_ref(param, spec, specs_dir)
        if not isinstance(param, dict) or param.get('in') != location:
            continue
        if 'schema' in param:
            schema_node = param['schema']
        else:
            schema_node = param.get('content', {}).get('application/json', {}).get('schema', {})
        result.append({'name': param.get('name'), 'required': bool(param.get('required', False)), 'schema': _resolve_schema(schema_node, param_spec, seen=frozenset(), specs_dir=specs_dir)})
    return result

def get_query_params_schema(spec: dict, operation: dict, specs_dir: Path | None=None) -> list[dict]:
    return _extract_params_by_location(spec, operation, 'query', specs_dir)

def get_path_params_schema(spec: dict, operation: dict, specs_dir: Path | None=None) -> list[dict]:
    return _extract_params_by_location(spec, operation, 'path', specs_dir)

def get_header_params_schema(spec: dict, operation: dict, specs_dir: Path | None=None) -> list[dict]:
    return _extract_params_by_location(spec, operation, 'header', specs_dir)
_SCHEMA_KEEP_KEYS = ('type', 'required', 'enum', 'pattern', 'format', 'minimum', 'maximum', 'minItems', 'maxItems', 'default', 'minProperties', 'maxProperties')

def _resolve_schema(node, spec: dict, seen: frozenset, depth: int=0, max_depth: int=16, specs_dir: Path | None=None) -> dict:
    if not isinstance(node, dict):
        return node
    if '$ref' in node:
        ref = node['$ref']
        if ref in seen or depth >= max_depth:
            return {'type': ref.rsplit('/', 1)[-1]}
        resolved, effective_spec = _resolve_ref(node, spec, specs_dir)
        return _resolve_schema(resolved, effective_spec, seen | {ref}, depth + 1, max_depth, specs_dir)
    result = {k: node[k] for k in _SCHEMA_KEEP_KEYS if k in node}
    for keyword in ('anyOf', 'oneOf', 'allOf'):
        if keyword in node:
            result[keyword] = [_resolve_schema(s, spec, seen, depth, max_depth, specs_dir) for s in node[keyword]]
    if 'not' in node:
        result['not'] = _resolve_schema(node['not'], spec, seen, depth, max_depth, specs_dir)
    if 'properties' in node:
        result['properties'] = {k: _resolve_schema(v, spec, seen, depth + 1, max_depth, specs_dir) for k, v in node['properties'].items()}
    if 'items' in node:
        result['items'] = _resolve_schema(node['items'], spec, seen, depth + 1, max_depth, specs_dir)
    if isinstance(node.get('additionalProperties'), dict):
        result['additionalProperties'] = _resolve_schema(node['additionalProperties'], spec, seen, depth + 1, max_depth, specs_dir)
    return result

def _strip_uri_template_vars(url: str) -> str:
    return re.sub('\\{[^}]+\\}', '', url)

def _strip_base_path(spec: dict, path: str) -> str:
    for server in spec.get('servers', []):
        raw_url = server.get('url', '')
        server_path = urlsplit(raw_url).path or raw_url
        static_base = _strip_uri_template_vars(server_path).rstrip('/')
        if static_base and path.startswith(static_base):
            return path[len(static_base):]
    if not path.startswith('/'):
        return '/' + path
    return path

def _paths_match_structurally(spec_path: str, query_path: str) -> bool:
    normalize = lambda p: re.sub('\\{[^}]+\\}', '{P}', p.rstrip('/'))
    return normalize(spec_path) == normalize(query_path)
_EXTERNAL_SPEC_CACHE: dict[str, dict] = {}

def _load_yaml_cached(path: Path) -> dict:
    import yaml
    key = str(path.resolve())
    if key not in _EXTERNAL_SPEC_CACHE:
        with open(path, encoding='utf-8') as f:
            _EXTERNAL_SPEC_CACHE[key] = yaml.safe_load(f) or {}
    return _EXTERNAL_SPEC_CACHE[key]

def _resolve_ref(obj: dict, spec: dict, specs_dir: Path | None=None) -> tuple[dict, dict]:
    if '$ref' not in obj:
        return (obj, spec)
    ref = obj['$ref']
    if ref.startswith('#/'):
        parts = ref.lstrip('#/').split('/')
        node = spec
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part, {})
        return (node if isinstance(node, dict) else {}, spec)
    if specs_dir is not None and '#/' in ref:
        filename, fragment = ref.split('#/', 1)
        matches = sorted(specs_dir.rglob(filename.strip()))
        if matches:
            ext_spec = _load_yaml_cached(matches[0])
            node = ext_spec
            for part in fragment.split('/'):
                if isinstance(node, dict):
                    node = node.get(part, {})
            return (node if isinstance(node, dict) else {}, ext_spec)
    return (obj, spec)
