import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, request
DEFAULT_OPENAI_BASE_URL = 'https://api.openai.com/v1'
ROOT = Path(__file__).resolve().parent.parent

def parse_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and (value[0] in {"'", '"'}):
        return value[1:-1]
    return re.split('\\s+#', value, maxsplit=1)[0].rstrip()

def load_env_file(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open('r') as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.startswith('export '):
                stripped = stripped[len('export '):].lstrip()
            key, separator, raw_value = stripped.partition('=')
            key = key.strip()
            if not separator or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key):
                raise ValueError(f'{path}:{line_no}: invalid .env assignment')
            if key not in os.environ:
                os.environ[key] = parse_env_value(raw_value)
    return True

def load_environment(env_file: Optional[str]=None) -> None:
    if env_file:
        path = Path(env_file).expanduser()
        if not load_env_file(path):
            raise FileNotFoundError(f'Environment file not found: {path}')
        return
    candidates = [Path.cwd() / '.env', ROOT / '.env']
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_env_file(path)

def parse_json_output(text: str) -> Dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith('```'):
        lines = stripped.splitlines()
        if lines and lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].startswith('```'):
            lines = lines[:-1]
        stripped = '\n'.join(lines).strip()
    data = json.loads(stripped)
    if not isinstance(data, dict):
        raise ValueError('response must be a JSON object')
    return data

def validate_evidence_retrieval(data: Dict[str, Any]) -> None:
    required = {'endpoint_id': str, 'useful_evidence': list, 'retrieval_gaps': list, 'recommended_next_queries': list, 'confidence': str}
    for key, expected_type in required.items():
        if key not in data:
            raise ValueError(f'missing required field: {key}')
        if not isinstance(data[key], expected_type):
            raise ValueError(f'{key} must be {expected_type.__name__}')
    for index, item in enumerate(data['useful_evidence'], start=1):
        if not isinstance(item, dict):
            raise ValueError(f'useful_evidence[{index}] must be an object')
        for key in ['evidence_id', 'context_id', 'evidence_type', 'label', 'relevance', 'quoted_text']:
            if key not in item:
                raise ValueError(f'useful_evidence[{index}] missing {key}')

def require_fields(data: Dict[str, Any], required: Dict[str, type]) -> None:
    for key, expected_type in required.items():
        if key not in data:
            raise ValueError(f'missing required field: {key}')
        if not isinstance(data[key], expected_type):
            raise ValueError(f'{key} must be {expected_type.__name__}')

def validate_evidence_used(data: Dict[str, Any]) -> None:
    evidence = data.get('evidence_used', [])
    if not isinstance(evidence, list):
        raise ValueError('evidence_used must be list')
    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            raise ValueError(f'evidence_used[{index}] must be an object')
        for key in ['context_id', 'evidence_role', 'quoted_text', 'rationale']:
            if key not in item:
                raise ValueError(f'evidence_used[{index}] missing {key}')

def validate_expected_binding(data: Dict[str, Any]) -> None:
    require_fields(data, {'endpoint_id': str, 'expected_binding': dict, 'evidence_used': list, 'assumptions': list, 'gaps': list, 'confidence': str})
    require_fields(data['expected_binding'], {'resource_instance': str, 'requester_nf_types': list, 'resource_identifiers': list, 'relation_type': str, 'relation_statement': str, 'strength': str, 'binding_rationale': str})
    if data['expected_binding']['strength'] not in {'explicit', 'implicit', 'ambiguous', 'not_identified'}:
        raise ValueError('expected_binding.strength has an unsupported value')
    if not all((isinstance(item, str) and item for item in data['expected_binding']['requester_nf_types'])):
        raise ValueError('expected_binding.requester_nf_types must contain non-empty strings')
    if not all((isinstance(item, str) and item for item in data['expected_binding']['resource_identifiers'])):
        raise ValueError('expected_binding.resource_identifiers must contain non-empty strings')
    validate_evidence_used(data)

def validate_existing_protection(data: Dict[str, Any]) -> None:
    require_fields(data, {'endpoint_id': str, 'existing_protection': dict, 'evidence_used': list, 'gaps': list, 'confidence': str})
    require_fields(data['existing_protection'], {'resource_binding': dict, 'operation_level_controls': list, 'procedural_or_contextual_controls': list, 'error_or_status_controls': list, 'limitations': list, 'protection_status': str})
    require_fields(data['existing_protection']['resource_binding'], {'coverage': str, 'mechanism': str, 'applies_when': list, 'failure_codes': list, 'failure_causes': list, 'protected_relation': str, 'coverage_notes': str})
    coverage = data['existing_protection']['resource_binding']['coverage']
    if coverage not in {'explicit_binding_check', 'condition_scoped', 'procedural_eligibility_only', 'operation_level_only', 'not_identified', 'ambiguous'}:
        raise ValueError('existing_protection.resource_binding.coverage has an unsupported value')
    failure_codes = data['existing_protection']['resource_binding']['failure_codes']
    if not all((isinstance(code, int) and (not isinstance(code, bool)) for code in failure_codes)):
        raise ValueError('existing_protection.resource_binding.failure_codes must contain integers')
    validate_evidence_used(data)

def schema_instruction(schema: str) -> str:
    instructions = {'evidence_retrieval': 'Return only strict JSON with this shape: {"endpoint_id": string, "useful_evidence": [{"evidence_id": string, "context_id": string, "evidence_type": string, "label": string, "relevance": string, "quoted_text": string}], "retrieval_gaps": [string], "recommended_next_queries": [string], "confidence": "high|medium|low"}.', 'expected_binding': 'Return only strict JSON with this shape: {"endpoint_id": string, "expected_binding": {"resource_instance": string, "requester_nf_types": [string], "resource_identifiers": [string], "relation_type": string, "relation_statement": string, "strength": "explicit|implicit|ambiguous|not_identified", "binding_rationale": string}, "evidence_used": [{"context_id": string, "evidence_role": string, "quoted_text": string, "rationale": string}], "assumptions": [string], "gaps": [string], "confidence": "high|medium|low"}.', 'existing_protection': 'Return only strict JSON with this shape: {"endpoint_id": string, "existing_protection": {"resource_binding": {"coverage": "explicit_binding_check|condition_scoped|procedural_eligibility_only|operation_level_only|not_identified|ambiguous", "mechanism": string, "applies_when": [string], "failure_codes": [integer], "failure_causes": [string], "protected_relation": string, "coverage_notes": string}, "operation_level_controls": [string], "procedural_or_contextual_controls": [string], "error_or_status_controls": [string], "limitations": [string], "protection_status": "explicit|partial|procedural_only|operation_level_only|not_identified|ambiguous"}, "evidence_used": [{"context_id": string, "evidence_role": string, "quoted_text": string, "rationale": string}], "gaps": [string], "confidence": "high|medium|low"}.'}
    return instructions[schema]

def system_message(schema: str) -> str:
    return 'You are a JSON-only 5G SBI specification analysis agent. Do not include markdown or prose outside the JSON object. ' + schema_instruction(schema)

def validate_agent_output(data: Dict[str, Any], schema: str) -> None:
    if schema == 'evidence_retrieval':
        validate_evidence_retrieval(data)
    elif schema == 'expected_binding':
        validate_expected_binding(data)
    elif schema == 'existing_protection':
        validate_existing_protection(data)

def extract_response_text(response_data: Dict[str, Any]) -> str:
    if isinstance(response_data.get('output_text'), str):
        return response_data['output_text']
    output_parts: List[str] = []
    for item in response_data.get('output', []):
        if not isinstance(item, dict):
            continue
        for content in item.get('content', []):
            if not isinstance(content, dict):
                continue
            text = content.get('text')
            if isinstance(text, str):
                output_parts.append(text)
    if output_parts:
        return '\n'.join(output_parts)
    raise ValueError('OpenAI response did not contain output text')

def call_openai_sdk(prompt: str, model: str, schema: str) -> Dict[str, Any]:
    try:
        from openai import OpenAI
    except ImportError:
        return call_openai_http(prompt, model, schema)
    if not os.environ.get('OPENAI_API_KEY'):
        raise RuntimeError('OPENAI_API_KEY is not set in the environment or .env')
    client = OpenAI()
    response = client.responses.create(model=model, input=[{'role': 'system', 'content': system_message(schema)}, {'role': 'user', 'content': prompt}])
    data = parse_json_output(response.output_text)
    validate_agent_output(data, schema)
    return data

def call_openai_http(prompt: str, model: str, schema: str) -> Dict[str, Any]:
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY is not set in the environment or .env')
    base_url = os.environ.get('OPENAI_BASE_URL', DEFAULT_OPENAI_BASE_URL).rstrip('/')
    payload = {'model': model, 'input': [{'role': 'system', 'content': system_message(schema)}, {'role': 'user', 'content': prompt}]}
    body = json.dumps(payload).encode('utf-8')
    http_request = request.Request(f'{base_url}/responses', data=body, headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}, method='POST')
    try:
        with request.urlopen(http_request, timeout=180) as response:
            response_data = json.loads(response.read().decode('utf-8'))
    except error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise RuntimeError(f'OpenAI API error {exc.code}: {error_body}') from exc
    except error.URLError as exc:
        raise RuntimeError(f'OpenAI API connection error: {exc.reason}') from exc
    data = parse_json_output(extract_response_text(response_data))
    validate_agent_output(data, schema)
    return data

def main() -> int:
    parser = argparse.ArgumentParser(description='Run one stdin prompt through OpenAI and print strict JSON.')
    parser.add_argument('--model', default='gpt-4.1-mini')
    parser.add_argument('--schema', required=True, choices=['evidence_retrieval', 'expected_binding', 'existing_protection'])
    parser.add_argument('--env-file', help='Optional .env path. Exported environment variables take precedence.')
    args = parser.parse_args()
    prompt = sys.stdin.read()
    try:
        load_environment(args.env_file)
        data = call_openai_sdk(prompt, args.model, args.schema)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(data))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
