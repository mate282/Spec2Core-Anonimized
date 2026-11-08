import re
from pathlib import Path

def parse_attacks_list(path: Path) -> list[dict]:
    text = path.read_text(encoding='utf-8')
    return _parse_text(text)

def _parse_text(text: str) -> list[dict]:
    sections = _split_sections(text)
    return [_parse_section(num, title, body) for num, title, body in sections]

def _split_sections(text: str) -> list[tuple[int, str, str]]:
    pattern = re.compile('^### Section (\\d+): (.+)$', re.MULTILINE)
    matches = list(pattern.finditer(text))
    sections = []
    for i, match in enumerate(matches):
        num = int(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        sections.append((num, title, body))
    return sections

def _parse_section(num: int, title: str, body: str) -> dict:
    fields = _extract_bullet_fields(body)
    return {'section_number': num, 'attack_id': _title_to_attack_id(num, title), 'title': title, 'service': fields.get('Service', ''), 'endpoint_raw': fields.get('Endpoint', ''), 'resource': fields.get('Resource', ''), 'operation': fields.get('Operation', ''), 'nf_consumer': fields.get('NF consumer', ''), 'expected_binding': fields.get('Expected binding', ''), 'existing_protection': fields.get('Existing protection', ''), 'test_idea': fields.get('Test idea', ''), 'impact': fields.get('Impact', ''), '_source': 'AttacksList.md'}

def _extract_bullet_fields(body: str) -> dict[str, str]:
    pattern = re.compile('^\\*\\s+\\*\\*(.+?):\\*\\*\\s*(.+)$', re.MULTILINE)
    return {m.group(1).strip(): m.group(2).strip() for m in pattern.finditer(body)}

def _title_to_attack_id(num: int, title: str) -> str:
    slug = re.sub('[^a-zA-Z0-9]+', '_', title).strip('_').upper()
    return f'S{num:02d}_{slug}'
