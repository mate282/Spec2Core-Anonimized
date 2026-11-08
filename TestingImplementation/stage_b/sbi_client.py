import email
import json
import re
import requests
_token_cache: dict[tuple, str] = {}
_registered_allowed_types: dict[str, set] = {}

def _httpx_request(method: str, url: str, *, data=None, json_body=None, params=None, headers=None, timeout: int=10, cert: tuple[str, str] | None=None, verify: bool | str=True):
    import httpx
    try:
        with httpx.Client(http2=True, http1=False, cert=cert, verify=verify) as client:
            return client.request(method=method.upper(), url=url, data=data, json=json_body, params=params, headers=headers, timeout=timeout)
    except httpx.HTTPError:
        return None

def register_nf(nrf_url: str, nf_instance_id: str, nf_type: str, target_nf_type: str, amf_id: str='cafe01', cert: tuple[str, str] | None=None, verify: bool | str=True, http2: bool=False) -> bool:
    url = f'{nrf_url}/nnrf-nfm/v1/nf-instances/{nf_instance_id}'
    allowed = _registered_allowed_types.setdefault(nf_instance_id, set())
    allowed.add(target_nf_type)
    payload: dict = {'nfInstanceId': nf_instance_id, 'nfType': nf_type, 'nfStatus': 'REGISTERED', 'ipv4Addresses': ['127.0.0.1'], 'allowedNfTypes': sorted(allowed)}
    if nf_type == 'AMF':
        payload['amfInfo'] = {'amfSetId': '3f8', 'amfRegionId': 'ca', 'guamiList': [{'plmnId': {'mcc': '208', 'mnc': '93'}, 'amfId': amf_id}]}
    if http2:
        r = _httpx_request('PUT', url, json_body=payload, timeout=5, cert=cert, verify=verify)
        return r is not None and r.status_code in (200, 201, 204)
    try:
        r = requests.put(url, json=payload, timeout=5, cert=cert, verify=verify)
        return r.status_code in (200, 201, 204)
    except requests.RequestException:
        return False

def get_token(nrf_url: str, nf_instance_id: str, nf_type: str, target_nf_type: str, scope: str, force: bool=False, cert: tuple[str, str] | None=None, verify: bool | str=True, http2: bool=False) -> tuple[str | None, dict | None]:
    cache_key = (nf_instance_id, scope)
    if not force and cache_key in _token_cache:
        return (_token_cache[cache_key], None)
    url = f'{nrf_url}/oauth2/token'
    data = {'grant_type': 'client_credentials', 'nfInstanceId': nf_instance_id, 'nfType': nf_type, 'targetNfType': target_nf_type, 'scope': scope}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if http2:
        r = _httpx_request('POST', url, data=data, headers=headers, timeout=5, cert=cert, verify=verify)
        if r is None:
            return (None, {'reason': 'connection_error', 'detail': 'HTTP/2 request failed (see logs)'})
    else:
        try:
            r = requests.post(url, data=data, headers=headers, timeout=5, cert=cert, verify=verify)
        except requests.RequestException as e:
            return (None, {'reason': 'connection_error', 'detail': str(e)})
    if r.status_code != 200:
        try:
            body = r.json()
        except ValueError:
            body = r.text[:300]
        return (None, {'reason': 'http_error', 'status': r.status_code, 'body': body})
    try:
        response_body = r.json()
    except ValueError:
        return (None, {'reason': 'no_access_token', 'status': r.status_code, 'body': r.text[:300]})
    token = response_body.get('access_token')
    if not token:
        return (None, {'reason': 'no_access_token', 'status': r.status_code, 'body': response_body})
    _token_cache[cache_key] = token
    return (token, None)

def sbi_request(method: str, url: str, token: str | None=None, json_body: dict | None=None, params: dict | None=None, raw_body: bytes | None=None, content_type: str | None=None, timeout: int=10, cert: tuple[str, str] | None=None, verify: bool | str=True, http2: bool=False):
    headers: dict = {'Accept': 'application/json'}
    if raw_body is not None:
        headers['Content-Type'] = content_type
    elif json_body is not None:
        headers['Content-Type'] = content_type or 'application/json'
    if token:
        headers['Authorization'] = f'Bearer {token}'
    if http2:
        return _httpx_request(method, url, data=raw_body if raw_body is not None else None, json_body=json_body if raw_body is None else None, params=params, headers=headers, timeout=timeout, cert=cert, verify=verify)
    try:
        return requests.request(method=method.upper(), url=url, data=raw_body if raw_body is not None else None, json=json_body if raw_body is None else None, params=params, headers=headers, timeout=timeout, cert=cert, verify=verify)
    except (requests.ConnectionError, requests.Timeout):
        return None

def parse_json_response(resp):
    if resp is None or not resp.text.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        pass
    content_type = resp.headers.get('Content-Type', '')
    if 'multipart/related' in content_type:
        parsed = _parse_multipart_json_part(resp.content, content_type)
        if parsed is not None:
            return parsed
    return resp.text

def _parse_multipart_json_part(body: bytes, content_type: str):
    boundary_match = re.search('boundary="?([^";]+)"?', content_type)
    if not boundary_match:
        return None
    mime_bytes = f'Content-Type: {content_type}\r\n\r\n'.encode() + body
    message = email.message_from_bytes(mime_bytes)
    if not message.is_multipart():
        return None
    for part in message.walk():
        if part.get_content_type() == 'application/json':
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            try:
                return json.loads(payload)
            except ValueError:
                continue
    return None

def clear_token_cache() -> None:
    _token_cache.clear()

def redact_token(token: str | None) -> str:
    if not token:
        return '<none>'
    if len(token) <= 16:
        return '***'
    return f'{token[:8]}...{token[-8:]}'
