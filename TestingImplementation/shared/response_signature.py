_PROBLEM_DETAILS_MARKERS = ('cause', 'title', 'detail', 'invalidParams')

def classify(resp) -> dict:
    if resp is None:
        return {'kind': 'no_response'}
    text = getattr(resp, 'text', '') or ''
    stripped = text.strip()
    if not stripped:
        return {'kind': 'empty_body'}
    try:
        body = resp.json()
    except ValueError:
        body = None
    if body is None:
        if resp.status_code == 404:
            return {'kind': 'router_not_found'}
        return {'kind': 'non_json', 'raw': stripped[:200]}
    if isinstance(body, (dict, list)) and (not body):
        return {'kind': 'empty_body'}
    if isinstance(body, dict) and any((k in body for k in _PROBLEM_DETAILS_MARKERS)):
        return {'kind': 'problem_details', 'cause': body.get('cause'), 'status': body.get('status'), 'title': body.get('title'), 'detail': body.get('detail'), 'invalid_params': body.get('invalidParams')}
    return {'kind': 'json', 'shape': 'array' if isinstance(body, list) else 'object'}
