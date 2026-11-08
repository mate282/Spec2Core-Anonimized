import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import yaml
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUNDLED_DIR = ROOT / '5GC_APIs-Rel-17' / 'bundled'
DEFAULT_CATEGORIZATION = ROOT / 'output' / 'identifiers_categorization.json'
DEFAULT_OUTPUT = ROOT / 'output' / 'selected_endpoint_list.json'
HTTP_METHODS = {'get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace'}
DEFAULT_SEEDS = [{'service': 'Nudm_UECM', 'method': 'PUT', 'endpoint': '/{ueId}/registrations/amf-3gpp-access'}, {'service': 'Nudm_UECM', 'method': 'PATCH', 'endpoint': '/{ueId}/registrations/amf-3gpp-access'}, {'service': 'Nudm_SDM', 'method': 'GET', 'endpoint': '/{supi}/am-data'}, {'service': 'Nudm_SDM', 'method': 'GET', 'endpoint': '/{supi}/sm-data'}, {'service': 'Namf_Comm', 'method': 'POST', 'endpoint': '/ue-contexts/{ueContextId}/release'}, {'service': 'Nsmf_PDUSession', 'method': 'POST', 'endpoint': '/sm-contexts/{smContextRef}/release'}, {'service': 'Npcf_SMPolicyControl', 'method': 'GET', 'endpoint': '/sm-policies/{smPolicyId}'}, {'service': 'Npcf_SMPolicyControl', 'method': 'POST', 'endpoint': '/sm-policies/{smPolicyId}/update'}]
SERVICE_ALIASES = {'Namf_Comm': ['Namf_Communication'], 'Namf_Communication': ['Namf_Comm']}

def load_json(path: Path) -> Any:
    with path.open('r') as handle:
        return json.load(handle)

def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open('r') as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f'Expected mapping in {path}')
    return data

def resolve_ref(spec: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
    if not ref.startswith('#/'):
        return None
    node: Any = spec
    for part in ref.lstrip('#/').split('/'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None

def schema_name(media_obj: Dict[str, Any]) -> str:
    schema = media_obj.get('schema', {})
    if '$ref' in schema:
        return schema['$ref'].split('/')[-1]
    return str(schema.get('type', ''))

def simplify_security(security: Any) -> List[str]:
    scopes: List[str] = []
    if isinstance(security, list):
        for entry in security:
            if not isinstance(entry, dict):
                continue
            for value in entry.values():
                if isinstance(value, list):
                    scopes.extend((str(scope) for scope in value))
    return list(dict.fromkeys(scopes))

def response_descriptions(spec: Dict[str, Any], operation: Dict[str, Any]) -> Dict[str, str]:
    descriptions: Dict[str, str] = {}
    for code, response in (operation.get('responses') or {}).items():
        resolved = response
        if isinstance(response, dict) and '$ref' in response:
            resolved = resolve_ref(spec, response['$ref']) or response
        if isinstance(resolved, dict):
            descriptions[str(code)] = str(resolved.get('description', '')).strip()
    return descriptions

def operation_metadata(bundled_dir: Path, spec_name: str, endpoint: str, method: str, spec_cache: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    if spec_name not in spec_cache:
        spec_cache[spec_name] = load_yaml(bundled_dir / spec_name)
    spec = spec_cache[spec_name]
    operation = spec.get('paths', {}).get(endpoint, {}).get(method.lower())
    if not isinstance(operation, dict):
        raise ValueError(f'Missing operation: {spec_name} {method} {endpoint}')
    request_body = operation.get('requestBody', {})
    content = request_body.get('content', {}) if isinstance(request_body, dict) else {}
    request_bodies = [{'content_type': content_type, 'schema': schema_name(media_obj)} for content_type, media_obj in content.items() if isinstance(media_obj, dict)]
    parameters = []
    path_item = spec.get('paths', {}).get(endpoint, {})
    for param in list(path_item.get('parameters', [])) + list(operation.get('parameters', [])):
        if not isinstance(param, dict):
            continue
        resolved = resolve_ref(spec, param['$ref']) if '$ref' in param else param
        if not isinstance(resolved, dict):
            continue
        parameters.append({'name': resolved.get('name', ''), 'in': resolved.get('in', ''), 'description': str(resolved.get('description', '')).strip()})
    external_docs = spec.get('externalDocs', {}) if isinstance(spec.get('externalDocs', {}), dict) else {}
    return {'title': spec.get('info', {}).get('title', ''), 'external_docs': {'description': external_docs.get('description', ''), 'url': external_docs.get('url', '')}, 'operationId': operation.get('operationId', ''), 'tags': operation.get('tags', []), 'summary': operation.get('summary', ''), 'description': operation.get('description', ''), 'scopes': simplify_security(operation.get('security', spec.get('security', []))), 'parameters': parameters, 'request_bodies': request_bodies, 'response_descriptions': response_descriptions(spec, operation)}

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        json.dump(data, handle, indent=2)
        handle.write('\n')

def build_category_map(categorization: Dict[str, List[str]]) -> Dict[str, str]:
    category_map: Dict[str, str] = {}
    for category, identifiers in categorization.items():
        for identifier in identifiers:
            category_map[identifier] = category
    return category_map

def service_candidates(service: str) -> List[str]:
    candidates = [service]
    candidates.extend(SERVICE_ALIASES.get(service, []))
    return list(dict.fromkeys(candidates))

def spec_service_name(path: Path, spec: Dict[str, Any]) -> str:
    title = str(spec.get('info', {}).get('title', '')).strip()
    if title:
        return re.sub('\\s+API$', '', title, flags=re.IGNORECASE)
    name = path.name
    if name.endswith('_bundled.yaml'):
        return name[:-len('_bundled.yaml')]
    return path.stem

def load_specs(bundled_dir: Path) -> List[Tuple[Path, Dict[str, Any], str]]:
    specs = []
    for path in sorted(bundled_dir.glob('*.yaml')):
        spec = load_yaml(path)
        specs.append((path, spec, spec_service_name(path, spec)))
    return specs

def path_shape(path: str) -> str:
    return re.sub('\\{[^}/]+\\}', '{}', path)

def path_params(path: str) -> List[str]:
    return re.findall('\\{([^}/]+)\\}', path)

def schema_type(schema: Optional[Dict[str, Any]], spec: Dict[str, Any]) -> str:
    if not isinstance(schema, dict):
        return ''
    if '$ref' in schema:
        return str(schema['$ref']).split('/')[-1]
    return str(schema.get('type', ''))

def operation_path_parameters(spec: Dict[str, Any], endpoint: str, method: str) -> List[Dict[str, str]]:
    path_item = spec.get('paths', {}).get(endpoint, {})
    operation = path_item.get(method.lower(), {}) if isinstance(path_item, dict) else {}
    params = []
    for param in list(path_item.get('parameters', [])) + list(operation.get('parameters', [])):
        if not isinstance(param, dict):
            continue
        resolved = resolve_ref(spec, param['$ref']) if '$ref' in param else param
        if not isinstance(resolved, dict) or resolved.get('in') != 'path':
            continue
        params.append({'name': str(resolved.get('name', '')), 'schema_type': schema_type(resolved.get('schema'), spec), 'description': str(resolved.get('description', '')).strip()})
    return params

def find_operation(specs: List[Tuple[Path, Dict[str, Any], str]], seed: Dict[str, str]) -> Tuple[Path, Dict[str, Any], str, str, List[str]]:
    service = seed['service']
    method = seed['method'].lower()
    endpoint = seed['endpoint']
    wanted_services = set(service_candidates(service))
    notes: List[str] = []
    service_specs = [(path, spec, spec_service) for path, spec, spec_service in specs if spec_service in wanted_services or path.stem.removesuffix('_bundled') in wanted_services]
    if not service_specs:
        raise ValueError(f'No OpenAPI spec found for service {service}')
    for path, spec, _ in service_specs:
        operation = spec.get('paths', {}).get(endpoint, {}).get(method)
        if isinstance(operation, dict):
            return (path, spec, endpoint, 'exact', notes)
    seed_shape = path_shape(endpoint)
    shape_matches = []
    for path, spec, _ in service_specs:
        for candidate, path_item in (spec.get('paths') or {}).items():
            if path_shape(candidate) != seed_shape or not isinstance(path_item, dict):
                continue
            if method in path_item and isinstance(path_item[method], dict):
                shape_matches.append((path, spec, candidate))
    if len(shape_matches) == 1:
        path, spec, canonical = shape_matches[0]
        notes.append(f'Path matched by structure, with parameter-name normalization: {endpoint} -> {canonical}')
        return (path, spec, canonical, 'path_shape', notes)
    if len(shape_matches) > 1:
        options = ', '.join((match[2] for match in shape_matches[:8]))
        raise ValueError(f'Ambiguous path-shape match for {service} {seed['method']} {endpoint}: {options}')
    raise ValueError(f'No operation found for {service} {seed['method']} {endpoint}')

def response_codes(metadata: Dict[str, Any]) -> List[str]:
    return list(metadata.get('response_descriptions', {}).keys())

def operation_methods(path_item: Dict[str, Any]) -> List[str]:
    return [method.upper() for method, operation in path_item.items() if method.lower() in HTTP_METHODS and isinstance(operation, dict)]

def method_allowed(method: str, allowed: Set[str]) -> bool:
    return not allowed or method.upper() in allowed

def service_allowed(service: str, allowed: Set[str]) -> bool:
    if not allowed:
        return True
    candidates = set(service_candidates(service))
    candidates.add(service)
    return bool(candidates & allowed)

def selected_by_resource_filter(resource_ids: List[str], resource_categories: List[str], identifiers: Set[str], categories: Set[str]) -> bool:
    if identifiers and (not set(resource_ids) & identifiers):
        return False
    if categories and (not set(resource_categories) & categories):
        return False
    return bool(identifiers or categories)

def enrich_operation(seed_service: str, spec_name: str, endpoint: str, method: str, metadata: Dict[str, Any], resource_params: List[Dict[str, str]], resource_categories: List[str], seed_endpoint: Optional[str]=None, match_type: str='filter', notes: Optional[List[str]]=None) -> Dict[str, Any]:
    return {'id': f'{seed_service} {method} {endpoint}', 'seed_service': seed_service, 'service': seed_service, 'spec': spec_name, 'seed_endpoint': seed_endpoint or endpoint, 'endpoint': endpoint, 'method': method, 'match_type': match_type, 'operationId': metadata['operationId'], 'tags': metadata['tags'], 'summary': metadata['summary'], 'description': metadata['description'], 'resource_ids': [param['name'] for param in resource_params if param['name']], 'resource_category': resource_categories, 'resource_parameters': resource_params, 'scopes': metadata['scopes'], 'parameters': metadata['parameters'], 'request_bodies': metadata['request_bodies'], 'response_codes': response_codes(metadata), 'response_descriptions': metadata['response_descriptions'], 'ts_hints': {'stage3': metadata['external_docs']}, 'selection_notes': notes or []}

def build_endpoint_list_from_seeds(seeds: Iterable[Dict[str, str]], bundled_dir: Path, categorization: Path) -> List[Dict[str, Any]]:
    specs = load_specs(bundled_dir)
    category_map = build_category_map(load_json(categorization))
    spec_cache: Dict[str, Dict[str, Any]] = {}
    rows = []
    for seed in seeds:
        spec_path, spec, endpoint, match_type, notes = find_operation(specs, seed)
        method = seed['method'].upper()
        spec_name = spec_path.name
        metadata = operation_metadata(bundled_dir, spec_name, endpoint, method, spec_cache)
        resource_params = operation_path_parameters(spec, endpoint, method)
        resource_ids = [param['name'] for param in resource_params if param['name']]
        resource_categories = list(dict.fromkeys((category_map.get(resource_id, 'UNCLASSIFIED') for resource_id in resource_ids)))
        rows.append(enrich_operation(seed['service'], spec_name, endpoint, method, metadata, resource_params, resource_categories, seed_endpoint=seed['endpoint'], match_type=match_type, notes=notes))
    return rows

def build_endpoint_list_from_resource_filters(bundled_dir: Path, categorization: Path, identifiers: Set[str], categories: Set[str], services: Set[str], methods: Set[str]) -> List[Dict[str, Any]]:
    specs = load_specs(bundled_dir)
    category_map = build_category_map(load_json(categorization))
    spec_cache: Dict[str, Dict[str, Any]] = {}
    rows = []
    for spec_path, spec, spec_service in specs:
        if not service_allowed(spec_service, services):
            continue
        for endpoint, path_item in sorted((spec.get('paths') or {}).items()):
            if not isinstance(path_item, dict):
                continue
            for method in operation_methods(path_item):
                if not method_allowed(method, methods):
                    continue
                resource_params = operation_path_parameters(spec, endpoint, method)
                resource_ids = [param['name'] for param in resource_params if param['name']]
                resource_categories = list(dict.fromkeys((category_map.get(resource_id, 'UNCLASSIFIED') for resource_id in resource_ids)))
                if not selected_by_resource_filter(resource_ids, resource_categories, identifiers, categories):
                    continue
                metadata = operation_metadata(bundled_dir, spec_path.name, endpoint, method, spec_cache)
                rows.append(enrich_operation(spec_service, spec_path.name, endpoint, method, metadata, resource_params, resource_categories, match_type='resource_filter'))
    return rows

def main() -> int:
    parser = argparse.ArgumentParser(description='Build an enriched endpoint list from OpenAPI filters.')
    parser.add_argument('--seed-list', help='JSON file containing exact seed entries with service/method/endpoint. Use --default-p1-seeds for the built-in curated endpoint list.')
    parser.add_argument('--default-p1-seeds', action='store_true', help='Use the built-in curated P1 endpoint list.')
    parser.add_argument('--identifier', action='append', default=[], help='Select operations whose path parameters include this identifier. Can be repeated.')
    parser.add_argument('--category', action='append', default=[], help='Select operations whose path parameters are in this identifier category. Can be repeated.')
    parser.add_argument('--service', action='append', default=[], help='Restrict selection to this OpenAPI service. Can be repeated.')
    parser.add_argument('--method', action='append', default=[], help='Restrict selection to this HTTP method. Can be repeated.')
    parser.add_argument('--bundled-dir', default=str(DEFAULT_BUNDLED_DIR))
    parser.add_argument('--categorization', default=str(DEFAULT_CATEGORIZATION))
    parser.add_argument('--output', default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    if args.seed_list and (args.identifier or args.category):
        raise ValueError('Use either --seed-list exact operation selection or resource filters, not both.')
    if args.default_p1_seeds and (args.seed_list or args.identifier or args.category):
        raise ValueError('Use --default-p1-seeds by itself, optionally with --service/--method only via a custom seed file.')
    if args.seed_list or args.default_p1_seeds:
        seeds = load_json(Path(args.seed_list)) if args.seed_list else DEFAULT_SEEDS
        endpoint_list = build_endpoint_list_from_seeds(seeds, Path(args.bundled_dir), Path(args.categorization))
    else:
        identifiers = set(args.identifier)
        categories = set(args.category)
        if not identifiers and (not categories):
            raise ValueError('Provide --seed-list, --default-p1-seeds, --identifier, or --category.')
        endpoint_list = build_endpoint_list_from_resource_filters(Path(args.bundled_dir), Path(args.categorization), identifiers, categories, set(args.service), {method.upper() for method in args.method})
    write_json(Path(args.output), endpoint_list)
    print(f'Wrote {len(endpoint_list)} enriched endpoints to {args.output}.')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
