import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from xml.etree import ElementTree
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = ROOT / 'output' / 'agent_pipeline'
DEFAULT_TS_RAW = ROOT / 'ts-corpus' / 'raw'
DEFAULT_RUN_TS_CORPUS = ROOT / 'ts-corpus' / 'extracted' / 'rel17'
HTTP_HEADERS = {'User-Agent': 'resource-testing-ts-retriever/1.0'}
DEFAULT_SEED_ENDPOINTS = ROOT / 'output' / 'seed_endpoint_list.json'
DEFAULT_SEED_PIPELINE_OUT = DEFAULT_OUT_DIR / 'seed_endpoints'
DEFAULT_SECTION_INDEX = DEFAULT_SEED_PIPELINE_OUT / '01_ts_section_index.jsonl'
DEFAULT_CONTEXT_PACKS = DEFAULT_SEED_PIPELINE_OUT / '02_operation_context_packs.jsonl'
DEFAULT_TS_MANIFEST = DEFAULT_SEED_PIPELINE_OUT / 'ts_manifest.json'
COMMON_TS_IDS = ['TS23502', 'TS29500', 'TS29501', 'TS29571', 'TS33501']
MAX_CONTEXT_TEXT_CHARS = 18000
MAX_EXTRACTED_LINE_CHARS = 10000
MAX_BINARY_TEXT_RATIO = 0.8
MIN_BINARY_TEXT_RATIO = 0.01
TS_SOURCE_POLICIES = {('TS29512', '17'): {'version': '17.11.0', 'archive_name': '29512-hb0.zip', 'document_member': '29512-hb0.doc', 'pdf_url': 'https://www.etsi.org/deliver/etsi_ts/129500_129599/129512/17.11.00_60/ts_129512v171100p.pdf', 'required_section_patterns': ['(?m)^\\s*4\\.2\\.4\\s+Npcf_SMPolicyControl_Update Service Operation\\s*$', '(?m)^\\s*5\\.3\\.3\\s+Resource:\\s+Individual SM Policy\\s*$']}}

def normalize_ts_id(text: str) -> str:
    compact = re.sub('[^A-Za-z0-9.]', '', str(text)).upper()
    match = re.search('(?:TS)?(\\d{2})\\.(\\d{3})', compact)
    if match:
        return f'TS{match.group(1)}{match.group(2)}'
    match = re.search('(?:TS)?(\\d{5})', compact)
    if match:
        return f'TS{match.group(1)}'
    return ''

def load_json(path: Path) -> Any:
    with path.open('r') as handle:
        return json.load(handle)

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        json.dump(data, handle, indent=2)
        handle.write('\n')

def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        for row in rows:
            handle.write(json.dumps(row) + '\n')

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open('r') as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}:{line_no}: invalid JSONL row: {exc}') from exc
    return rows

def item_id(record: Dict[str, Any]) -> str:
    if 'id' in record:
        return str(record['id'])
    service = record.get('service', '')
    method = record.get('method', '')
    endpoint = record.get('endpoint', record.get('path', ''))
    return f'{service} {method} {endpoint}'

def ts_id_to_archive_url(ts_id: str) -> str:
    match = re.fullmatch('TS(\\d{2})(\\d{3})', ts_id)
    if not match:
        raise ValueError(f'Unsupported TS id: {ts_id}')
    series, spec = match.groups()
    return f'https://www.3gpp.org/ftp/Specs/archive/{series}_series/{series}.{spec}/'

class HrefParser(HTMLParser):

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        if tag.lower() != 'a':
            return
        for key, value in attrs:
            if key.lower() == 'href' and value:
                self.hrefs.append(value)

def release_code(release: str) -> str:
    release_map = {'15': 'f', '16': 'g', '17': 'h', '18': 'i', '19': 'j', '20': 'k'}
    if release.lower() in release_map.values():
        return release.lower()
    if release not in release_map:
        raise ValueError(f'Unsupported release {release}; expected one of {', '.join(sorted(release_map))}')
    return release_map[release]

def latest_ts_zip_url(ts_id: str, timeout: int, release: str) -> str:
    archive_url = ts_id_to_archive_url(ts_id)
    request = urllib.request.Request(archive_url, headers=HTTP_HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        html = response.read().decode('utf-8', errors='ignore')
    parser = HrefParser()
    parser.feed(html)
    prefix = ts_id.removeprefix('TS').lower()
    wanted_release = release_code(release)
    candidates = [href for href in parser.hrefs if href.lower().endswith('.zip') and Path(href).name.lower().startswith(f'{prefix}-{wanted_release}')]
    if not candidates:
        raise ValueError(f'No TS Rel-{release} zip candidates found at {archive_url}')
    return urllib.request.urljoin(archive_url, sorted(candidates)[-1])

def download_url(url: str, out_path: Path, timeout: int) -> None:
    request = urllib.request.Request(url, headers=HTTP_HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        out_path.write_bytes(response.read())

def docx_text(path: Path) -> str:
    paragraphs: List[str] = []
    with zipfile.ZipFile(path) as archive:
        xml = archive.read('word/document.xml')
    root = ElementTree.fromstring(xml)
    namespace = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    for paragraph in root.findall('.//w:p', namespace):
        parts = [node.text or '' for node in paragraph.findall('.//w:t', namespace)]
        text = ''.join(parts).strip()
        if text:
            paragraphs.append(text)
    return '\n'.join(paragraphs)

def source_policy(ts_id: str, release: str) -> Dict[str, Any]:
    return dict(TS_SOURCE_POLICIES.get((ts_id, str(release)), {}))

def resolve_executable(configured: str, default: str) -> str:
    candidate = configured.strip() if configured else ''
    if candidate:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return ''
    return shutil.which(default) or ''

def antiword_text(path: Path, command: str, antiword_home: str='') -> str:
    executable = resolve_executable(command, 'antiword')
    if not executable:
        raise RuntimeError('legacy .doc conversion requires antiword or LibreOffice; install antiword or pass --antiword-command')
    environment = os.environ.copy()
    if antiword_home:
        environment['ANTIWORDHOME'] = antiword_home
    result = subprocess.run([executable, '-m', 'UTF-8.txt', '-w', '200', str(path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    if result.returncode != 0:
        stderr = result.stderr.decode('utf-8', errors='replace').strip()
        raise RuntimeError(f'antiword failed for {path}: {stderr or 'unknown error'}')
    return result.stdout.decode('utf-8', errors='strict')

def pdftotext_text(path: Path, command: str) -> str:
    executable = resolve_executable(command, 'pdftotext')
    if not executable:
        raise RuntimeError('PDF fallback requires pdftotext; install poppler-utils or pass --pdftotext-command')
    result = subprocess.run([executable, '-layout', str(path), '-'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        stderr = result.stderr.decode('utf-8', errors='replace').strip()
        raise RuntimeError(f'pdftotext failed for {path}: {stderr or 'unknown error'}')
    return result.stdout.decode('utf-8', errors='strict')

def normalize_extracted_text(text: str) -> str:
    normalized = text.replace('\r\n', '\n').replace('\r', '\n').replace('\x00', '')
    scope_match = re.search('(?mi)^\\s*1\\s*Scope\\s*$\\s*^The present document', normalized)
    if scope_match:
        normalized = normalized[scope_match.start():]
    normalized = '\n'.join((line.rstrip() for line in normalized.splitlines()))
    normalized = re.sub('\\n{4,}', '\n\n\n', normalized)
    return normalized.strip() + '\n'

def compact_context_text(text: str) -> str:
    compacted: List[str] = []
    previous_line_was_blank = False
    for line in text.splitlines():
        if not line.strip():
            if compacted and (not previous_line_was_blank):
                compacted.append('')
            previous_line_was_blank = True
            continue
        if line.lstrip().startswith('|'):
            line = '|'.join((cell.strip() for cell in line.strip().split('|')))
        compacted.append(line.rstrip())
        previous_line_was_blank = False
    while compacted and (not compacted[-1]):
        compacted.pop()
    return '\n'.join(compacted)

def assess_extracted_text(text: str, *, source_size: Optional[int]=None, binary_source: bool=False, required_section_patterns: Iterable[str]=()) -> tuple:
    encoded_size = len(text.encode('utf-8'))
    lines = text.splitlines()
    max_line_chars = max((len(line) for line in lines), default=0)
    long_line_count = sum((len(line) > 2000 for line in lines))
    ratio = encoded_size / source_size if source_size else None
    metrics = {'text_bytes': encoded_size, 'line_count': len(lines), 'max_line_chars': max_line_chars, 'lines_over_2000_chars': long_line_count, 'text_to_source_ratio': round(ratio, 6) if ratio is not None else None}
    errors: List[str] = []
    if encoded_size < 1000:
        errors.append(f'extracted text is implausibly small ({encoded_size} bytes)')
    if max_line_chars > MAX_EXTRACTED_LINE_CHARS:
        errors.append(f'maximum line length {max_line_chars} exceeds {MAX_EXTRACTED_LINE_CHARS}')
    if lines and long_line_count > max(10, len(lines) // 100):
        errors.append(f'{long_line_count} lines exceed 2000 characters in {len(lines)} lines')
    if binary_source and ratio is not None:
        if ratio < MIN_BINARY_TEXT_RATIO:
            errors.append(f'text/source ratio {ratio:.3f} is below {MIN_BINARY_TEXT_RATIO:.2f}')
        if ratio > MAX_BINARY_TEXT_RATIO:
            errors.append(f'text/source ratio {ratio:.3f} exceeds {MAX_BINARY_TEXT_RATIO:.2f}')
    if not re.search('(?mi)^\\s*1\\s*Scope\\s*$', text):
        errors.append("required top-level section '1 Scope' was not found")
    for pattern in required_section_patterns:
        if not re.search(pattern, text):
            errors.append(f'required section pattern was not found: {pattern}')
    return (metrics, errors)

def validate_extracted_text(text: str, *, source_label: str, source_size: Optional[int]=None, binary_source: bool=False, required_section_patterns: Iterable[str]=()) -> Dict[str, Any]:
    metrics, errors = assess_extracted_text(text, source_size=source_size, binary_source=binary_source, required_section_patterns=required_section_patterns)
    if errors:
        raise ValueError(f'{source_label} failed extraction quality gate: {'; '.join(errors)}')
    return metrics

def extract_ts_zip(zip_path: Path, extracted_dir: Path, ts_id: str, *, policy: Optional[Dict[str, Any]]=None, antiword_command: str='', antiword_home: str='', pdftotext_command: str='', timeout: int=60) -> Dict[str, Any]:
    extracted_dir.mkdir(parents=True, exist_ok=True)
    out_path = extracted_dir / f'{ts_id}.txt'
    metadata_path = extracted_dir / f'{ts_id}.source.json'
    policy = policy or {}
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        docx_names = [name for name in names if name.lower().endswith('.docx')]
        doc_names = [name for name in names if name.lower().endswith('.doc')]
        txt_names = [name for name in names if name.lower().endswith('.txt')]
        required_member = str(policy.get('document_member', ''))
        if required_member and required_member not in names:
            raise ValueError(f'{zip_path} does not contain locked member {required_member}')
        extractor = ''
        source_format = ''
        source_label = ''
        source_size = 0
        source_sha256 = ''
        if required_member:
            selected_names = [required_member]
        elif docx_names:
            selected_names = [sorted(docx_names)[0]]
        elif txt_names:
            selected_names = [sorted(txt_names)[0]]
        elif doc_names:
            selected_names = [sorted(doc_names)[0]]
        else:
            raise ValueError(f'{zip_path} does not contain a .docx, .doc, or .txt TS document')
        member = selected_names[0]
        member_bytes = archive.read(member)
        source_size = len(member_bytes)
        source_sha256 = hashlib.sha256(member_bytes).hexdigest()
        if member.lower().endswith('.docx'):
            source_format = 'docx'
            extractor = 'ooxml'
            with tempfile.TemporaryDirectory(prefix=f'{ts_id.lower()}-') as temp_dir:
                temp_docx = Path(temp_dir) / Path(member).name
                temp_docx.write_bytes(member_bytes)
                text = docx_text(temp_docx)
            source_label = f'{zip_path.name}:{member}'
        elif member.lower().endswith('.txt'):
            source_format = 'txt'
            extractor = 'utf8'
            text = member_bytes.decode('utf-8', errors='strict')
            source_label = f'{zip_path.name}:{member}'
        else:
            source_format = 'doc'
            with tempfile.TemporaryDirectory(prefix=f'{ts_id.lower()}-') as temp_dir:
                temp_doc = Path(temp_dir) / Path(member).name
                temp_doc.write_bytes(member_bytes)
                try:
                    text = antiword_text(temp_doc, antiword_command, antiword_home)
                    extractor = 'antiword'
                    source_label = f'{zip_path.name}:{member}'
                except RuntimeError as antiword_error:
                    pdf_url = str(policy.get('pdf_url', ''))
                    pdf_executable = resolve_executable(pdftotext_command, 'pdftotext')
                    if not pdf_url or not pdf_executable:
                        raise RuntimeError(f'{antiword_error}. No usable PDF fallback is available.') from antiword_error
                    pdf_name = Path(urllib.request.urlparse(pdf_url).path).name
                    pdf_path = zip_path.parent / pdf_name
                    if not pdf_path.exists():
                        download_url(pdf_url, pdf_path, timeout)
                    text = pdftotext_text(pdf_path, pdf_executable)
                    extractor = 'pdftotext-layout'
                    source_format = 'pdf'
                    source_size = pdf_path.stat().st_size
                    source_sha256 = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
                    source_label = pdf_url
    text = normalize_extracted_text(text)
    quality = validate_extracted_text(text, source_label=source_label, source_size=source_size, binary_source=source_format in {'doc', 'docx', 'pdf'}, required_section_patterns=policy.get('required_section_patterns', []))
    temp_output = out_path.with_suffix('.txt.tmp')
    temp_output.write_text(text, encoding='utf-8')
    temp_output.replace(out_path)
    metadata = {'ts': ts_id, 'version': policy.get('version', ''), 'archive': zip_path.name, 'document_member': member, 'source_format': source_format, 'extractor': extractor, 'source_label': source_label, 'source_bytes': source_size, 'source_sha256': source_sha256, 'text_path': str(out_path), 'quality': quality}
    write_json(metadata_path, metadata)
    return metadata

def ensure_ts_text(ts_id: str, raw_dir: Path, extracted_dir: Path, download: bool, timeout: int, release: str, antiword_command: str='', antiword_home: str='', pdftotext_command: str='') -> Dict[str, Any]:
    extracted_path = extracted_dir / f'{ts_id}.txt'
    metadata_path = extracted_dir / f'{ts_id}.source.json'
    policy = source_policy(ts_id, release)
    if extracted_path.exists():
        try:
            text = extracted_path.read_text(encoding='utf-8')
            metadata = load_json(metadata_path) if metadata_path.exists() else {}
            quality = validate_extracted_text(text, source_label=str(extracted_path), source_size=metadata.get('source_bytes'), binary_source=metadata.get('source_format') in {'doc', 'docx', 'pdf'}, required_section_patterns=policy.get('required_section_patterns', []))
            source_matches = not policy or (metadata.get('archive') == policy.get('archive_name') and metadata.get('version') == policy.get('version'))
            if source_matches:
                return {'ts': ts_id, 'status': 'present', 'version': metadata.get('version', ''), 'text_path': str(extracted_path), 'extractor': metadata.get('extractor', 'unknown'), 'quality': quality}
        except (UnicodeDecodeError, ValueError):
            pass
    if not download:
        return {'ts': ts_id, 'status': 'missing', 'text_path': str(extracted_path)}
    raw_dir.mkdir(parents=True, exist_ok=True)
    prefix = ts_id.removeprefix('TS').lower()
    archive_name = str(policy.get('archive_name', ''))
    zip_url = ''
    if archive_name:
        zip_path = raw_dir / archive_name
        if not zip_path.exists():
            zip_url = urllib.request.urljoin(ts_id_to_archive_url(ts_id), archive_name)
    else:
        release_letter = release_code(release)
        local_zips = sorted(raw_dir.glob(f'{prefix}-{release_letter}*.zip'))
        if local_zips:
            zip_path = local_zips[-1]
        else:
            zip_url = latest_ts_zip_url(ts_id, timeout, release)
            zip_path = raw_dir / Path(urllib.request.urlparse(zip_url).path).name
    if not zip_path.exists():
        download_url(zip_url, zip_path, timeout)
    existed_before = extracted_path.exists()
    metadata = extract_ts_zip(zip_path, extracted_dir, ts_id, policy=policy, antiword_command=antiword_command, antiword_home=antiword_home, pdftotext_command=pdftotext_command, timeout=timeout)
    result = {'ts': ts_id, 'status': 'regenerated' if existed_before else 'downloaded', 'release': f'Rel-{release}', 'version': metadata.get('version', ''), 'text_path': str(extracted_path), 'extractor': metadata['extractor'], 'source_format': metadata['source_format'], 'quality': metadata['quality']}
    if zip_url:
        result['zip_url'] = zip_url
    else:
        result['zip_path'] = str(zip_path)
    return result

def stage3_ts_id_from_record(record: Dict[str, Any]) -> str:
    ts_hints = record.get('ts_hints', {})
    stage3 = ts_hints.get('stage3', {}) if isinstance(ts_hints, dict) else {}
    if isinstance(stage3, dict):
        return normalize_ts_id(stage3.get('description', ''))
    return ''

def discover_needed_ts_from_endpoint_list(records: List[Dict[str, Any]]) -> List[str]:
    ts_ids: Set[str] = set()
    for record in records:
        ts_id = stage3_ts_id_from_record(record)
        if ts_id:
            ts_ids.add(ts_id)
    return sorted(ts_ids)

def slugify(value: str) -> str:
    slug = re.sub('[^A-Za-z0-9]+', '-', value).strip('-').lower()
    return slug or 'item'

def section_heading(line: str) -> Optional[tuple]:
    stripped = line.strip()
    annex = re.match('^((?:Annex\\s+[A-Z]|[A-Z]\\.\\d+(?:\\.\\d+)*))(\\s+|(?=[A-Z]))([A-Z][^\\n]{1,180})$', stripped)
    numeric = re.match('^(\\d+(?:\\.\\d+)*)(\\s+|(?=[A-Z]))([A-Z][^\\n]{1,180})$', stripped)
    match = annex or numeric
    if not match:
        return None
    number, separator, title = (match.group(1).replace('Annex ', ''), match.group(2), match.group(3).strip())
    if numeric and separator == '' and ('.' not in number):
        return None
    if numeric and '.' not in number and (int(number) > 20):
        return None
    if separator == '' and re.search('\\d$', title):
        return None
    if re.match('^(Table|Figure|NOTE|The|Upon|If)\\b', title):
        return None
    if title.endswith(':'):
        return None
    return (number, title)

def section_type(section_number: str, section_title: str, text: str) -> str:
    title = section_title.lower()
    body = text[:2000].lower()
    combined = f'{title}\n{body}'
    if section_number.startswith('A') and ('openapi:' in body or title.endswith(' api')):
        return 'openapi_annex'
    if 'resource standard method' in title or re.fullmatch('(get|put|post|patch|delete)', section_title.strip(), re.I):
        return 'resource standard methods'
    if 'resource definition' in title:
        return 'resource definition'
    if 'resources and methods overview' in combined or 'resources and applicable http methods' in combined:
        return 'resources and methods overview'
    if 'registration' in title and ('procedure' in combined or 'udm' in combined or 'serving amf' in combined):
        return 'procedure/cross-reference'
    if 'security' in combined or 'authorization' in combined or 'access token' in combined or ('oauth' in combined):
        return 'security'
    if 'error' in combined or 'problem details' in combined or 'response code' in combined or ('status code' in combined):
        return 'error responses'
    if 'resources and methods' in title or 'resource and method' in title or 'resources' == title.strip():
        return 'resources and methods overview'
    if 'service operation' in title or 'service operations' in title:
        return 'service operations overview'
    if 'procedure' in combined or 'figure' in combined or '3gpp ts 23.' in combined or ('see clause' in combined):
        return 'procedure/cross-reference'
    return 'other'

def index_ts_sections(ts_corpus: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(ts_corpus.glob('TS*.txt')):
        ts_id = normalize_ts_id(path.stem)
        if not ts_id:
            continue
        text = path.read_text(encoding='utf-8')
        required_patterns: List[str] = []
        for (policy_ts_id, _release), policy in TS_SOURCE_POLICIES.items():
            if policy_ts_id == ts_id:
                required_patterns.extend(policy.get('required_section_patterns', []))
        metadata_path = path.with_name(f'{ts_id}.source.json')
        metadata = load_json(metadata_path) if metadata_path.exists() else {}
        validate_extracted_text(text, source_label=str(path), source_size=metadata.get('source_bytes'), binary_source=metadata.get('source_format') in {'doc', 'docx', 'pdf'}, required_section_patterns=required_patterns)
        lines = text.splitlines()
        headings = []
        for index, line in enumerate(lines):
            parsed = section_heading(line)
            if parsed:
                headings.append((index, parsed[0], parsed[1]))
        for offset, (start_index, number, title) in enumerate(headings):
            end_index = headings[offset + 1][0] - 1 if offset + 1 < len(headings) else len(lines) - 1
            text = '\n'.join(lines[start_index:end_index + 1]).strip()
            section_id = f'{ts_id}:{number}:{slugify(title)}'
            rows.append({'section_id': section_id, 'ts_id': ts_id, 'section_number': number, 'section_title': title, 'section_type': section_type(number, title, text), 'line_start': start_index + 1, 'line_end': end_index + 1, 'text': text})
    return rows

def openapi_seed_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    return {'endpoint_id': record.get('id', item_id(record)), 'service': record.get('service', ''), 'spec': record.get('spec', ''), 'endpoint': record.get('endpoint', record.get('path', '')), 'method': record.get('method', ''), 'operationId': record.get('operationId', ''), 'tags': record.get('tags', []), 'summary': record.get('summary', ''), 'description': record.get('description', ''), 'resource_ids': record.get('resource_ids', []), 'resource_category': record.get('resource_category', record.get('resource_categories', [])), 'resource_parameters': record.get('resource_parameters', []), 'scopes': record.get('scopes', []), 'parameters': record.get('parameters', []), 'request_bodies': record.get('request_bodies', []), 'response_codes': record.get('response_codes', []), 'response_descriptions': record.get('response_descriptions', {}), 'ts_hints': record.get('ts_hints', {})}

def endpoint_stage3_ts(record: Dict[str, Any]) -> str:
    ts_id = stage3_ts_id_from_record(record)
    if ts_id:
        return ts_id
    hints = record.get('ts_hints', {})
    if isinstance(hints, dict):
        stage3 = hints.get('stage3', {})
        if isinstance(stage3, dict):
            return normalize_ts_id(f'{stage3.get('description', '')} {stage3.get('url', '')}')
    return ''

def is_nrf_nf_instance_endpoint(record: Dict[str, Any]) -> bool:
    values = [record.get('service', ''), ' '.join(record.get('resource_ids', [])), ' '.join(record.get('resource_category', record.get('resource_categories', [])))]
    combined = ' '.join((str(value) for value in values))
    return 'Nnrf' in combined or any((token in combined for token in ['nfInstanceId', 'nfInstanceID', 'NF_IDENTIFIER']))

def locally_present_ts_ids(section_rows: List[Dict[str, Any]]) -> Set[str]:
    return {row['ts_id'] for row in section_rows}

def selected_ts_ids_for_record(record: Dict[str, Any], present: Set[str], include_common: bool=False) -> tuple:
    selected: List[str] = []
    gaps: List[str] = []
    stage3 = endpoint_stage3_ts(record)
    if stage3:
        selected.append(stage3)
        if stage3 not in present:
            gaps.append(f'endpoint stage-3 TS {stage3} is not present in the local section index')
    if include_common:
        for ts_id in COMMON_TS_IDS:
            if ts_id in present and ts_id not in selected:
                selected.append(ts_id)
            elif ts_id not in present:
                gaps.append(f'common TS {ts_id} is not present locally')
    if is_nrf_nf_instance_endpoint(record):
        if 'TS29510' in present:
            selected.append('TS29510')
        else:
            gaps.append('NRF/NF-instance context suggests TS29510, but it is not present locally')
    return (selected, gaps)

def path_literals(endpoint: str) -> List[str]:
    return list(dict.fromkeys([endpoint] + endpoint_suffixes(endpoint)))

def endpoint_suffixes(endpoint: str) -> List[str]:
    parts = [part for part in endpoint.split('/') if part]
    suffixes = []
    for index, part in enumerate(parts):
        if part.startswith('{') and part.endswith('}'):
            continue
        suffixes.append('/'.join(parts[index:]))
        suffixes.append(part)
    return list(dict.fromkeys(suffixes))

def lower_terms(values: Iterable[str]) -> List[str]:
    terms: List[str] = []
    for value in values:
        if not value:
            continue
        for token in split_terms(str(value)):
            if token and token.lower() not in terms:
                terms.append(token.lower())
    return terms

def split_terms(value: str) -> List[str]:
    parts: List[str] = []
    for piece in re.split('[^A-Za-z0-9{}_-]+', value):
        if not piece:
            continue
        parts.append(piece)
        parts.extend(re.findall('[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+[A-Za-z]+|[A-Za-z]+[0-9]+', piece))
    return list(dict.fromkeys(parts))

def resource_specific_terms(record: Dict[str, Any]) -> List[str]:
    terms = []
    endpoint = record.get('endpoint', record.get('path', ''))
    terms.extend(endpoint_suffixes(endpoint))
    terms.append(endpoint)
    terms.append(record.get('operationId', ''))
    terms.extend((body.get('schema', '') for body in record.get('request_bodies', []) if isinstance(body, dict)))
    return list(dict.fromkeys((term.strip().lower() for term in terms if len(term.strip()) >= 4)))

def exact_resource_match(record: Dict[str, Any], section: Dict[str, Any]) -> bool:
    text = section['text'].lower()
    endpoint = record.get('endpoint', record.get('path', '')).lower()
    if endpoint and endpoint in text:
        return True
    for body in record.get('request_bodies', []):
        if isinstance(body, dict):
            schema = body.get('schema', '').lower()
            if schema and schema != 'object' and (schema in text):
                return True
    operation_id = record.get('operationId', '').lower()
    return bool(operation_id and operation_id in text)

def procedure_terms_for_record(record: Dict[str, Any]) -> List[str]:
    terms = []
    endpoint = record.get('endpoint', record.get('path', ''))
    summary = record.get('summary', '')
    method = record.get('method', '')
    if method:
        terms.append(f'{method} request')
        terms.append(f'{method} {endpoint}')
    terms.extend([summary, ' '.join(record.get('tags', []))])
    return [term.lower() for term in terms if term]

def semantic_tokens(text: str) -> List[str]:
    stop = {'a', 'an', 'and', 'as', 'for', 'in', 'of', 'on', 'the', 'to', 'with', 'eg', 'e', 'g', 'ue', 'this', 'that', 'service', 'operation', 'resource', 'resources', 'information'}
    tokens = []
    for token in split_terms(text):
        normalized = token.lower()
        if len(normalized) < 3 or normalized in stop:
            continue
        tokens.append(normalized)
    return list(dict.fromkeys(tokens))

def tag_summary_tokens(record: Dict[str, Any]) -> Set[str]:
    text = ' '.join([record.get('summary', ''), ' '.join(record.get('tags', []))])
    return set(semantic_tokens(text))

def token_overlap_ratio(left: Set[str], right_text: str) -> float:
    if not left:
        return 0.0
    right = set(semantic_tokens(right_text))
    if not right:
        return 0.0
    return len(left & right) / len(left)

def tag_summary_matches_section(record: Dict[str, Any], section: Dict[str, Any]) -> bool:
    anchors = tag_summary_tokens(record)
    if not anchors:
        return False
    action_tokens = {'create', 'delete', 'deregister', 'deregistration', 'get', 'modify', 'patch', 'release', 'retrieve', 'retrieval', 'update'}
    anchor_actions = anchors & action_tokens
    section_title = section.get('section_title', '')
    section_title_tokens = set(semantic_tokens(section_title))
    if anchor_actions and (not anchor_actions & section_title_tokens):
        return False
    title_ratio = token_overlap_ratio(anchors, section.get('section_title', ''))
    return title_ratio >= 0.45

def endpoint_leaf_tokens(record: Dict[str, Any]) -> Set[str]:
    endpoint = record.get('endpoint', record.get('path', ''))
    literals = [part for part in endpoint.split('/') if part and (not (part.startswith('{') and part.endswith('}')))]
    if not literals:
        return set()
    leaf = literals[-1]
    tokens = set(semantic_tokens(leaf))
    allowed_short = {'am', 'sm', 'n1', 'n2'}
    tokens.update((token.lower() for token in split_terms(leaf) if token.lower() in allowed_short))
    generic = {'data', 'release', 'update', 'registrations', 'contexts'}
    return {token for token in tokens if token not in generic}

def endpoint_leaf_matches_section(record: Dict[str, Any], section: Dict[str, Any]) -> bool:
    tokens = endpoint_leaf_tokens(record)
    if len(tokens) < 2:
        return True
    text_tokens = set(semantic_tokens(f'{section.get('section_title', '')} {section.get('text', '')[:1200]}'))
    text_tokens.update((token.lower() for token in split_terms(section.get('text', '')[:1200]) if token.lower() in {'am', 'sm'}))
    return len(tokens & text_tokens) / len(tokens) >= 0.5

def has_error_evidence(text: str) -> bool:
    return bool(re.search('\\b(401|403)\\b|forbidden|unauthorized|problemdetails|shall reject', text, re.I))

def error_window_section(section: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    lines = section['text'].splitlines()
    hit_indexes = [index for index, line in enumerate(lines) if has_error_evidence(line)]
    if not hit_indexes:
        return None
    start = max(0, hit_indexes[0] - 4)
    end = min(len(lines) - 1, hit_indexes[-1] + 4)
    clone = dict(section)
    clone['section_id'] = f'{section['section_id']}:error-window'
    clone['section_title'] = f'{section['section_title']} error response window'
    clone['section_type'] = 'error responses'
    clone['line_start'] = section['line_start'] + start
    clone['line_end'] = section['line_start'] + end
    clone['text'] = '\n'.join(lines[start:end + 1])
    return clone

def same_stage3_ts(record: Dict[str, Any], section: Dict[str, Any]) -> bool:
    return section.get('ts_id') == endpoint_stage3_ts(record)

def procedure_context_allowed(record: Dict[str, Any], section: Dict[str, Any]) -> bool:
    if section.get('section_type') != 'procedure/cross-reference':
        return True
    text = f'{section.get('section_title', '')}\n{section.get('text', '')}'.lower()
    title = section.get('section_title', '').lower()
    if title.startswith('type:'):
        return False
    if not endpoint_leaf_matches_section(record, section):
        return False
    endpoint = record.get('endpoint', record.get('path', '')).lower()
    method = record.get('method', '').lower()
    if '3gpp-access' in endpoint and 'non-3gpp' in text:
        return False
    if tag_summary_matches_section(record, section):
        return True
    if method and f'{method} request' in text:
        return True
    if method and f'{method} ' in text and any((term in text for term in resource_specific_terms(record))):
        return True
    return not method

def section_match_score(record: Dict[str, Any], section: Dict[str, Any]) -> tuple:
    endpoint = record.get('endpoint', record.get('path', ''))
    operation_id = record.get('operationId', '')
    resource_ids = [str(value) for value in record.get('resource_ids', [])]
    resource_categories = [str(value) for value in record.get('resource_category', record.get('resource_categories', []))]
    text = f'{section.get('section_title', '')}\n{section.get('text', '')}'.lower()
    specific_hits = [term for term in resource_specific_terms(record) if term in text]
    procedure_hits = [term for term in procedure_terms_for_record(record) if term in text]
    exact_path = bool(endpoint and endpoint.lower() in text)
    score = 0
    reasons: List[str] = []
    if section['section_type'] == 'openapi_annex':
        score -= 250
    if operation_id and operation_id.lower() in text:
        score += 120
        reasons.append('exact operationId match')
    op_terms = lower_terms([operation_id])
    op_hits = [term for term in op_terms if len(term) >= 3 and term in text]
    if op_hits:
        score += 12 * len(op_hits)
        reasons.append('split operationId term match')
    if exact_path:
        score += 100
        reasons.append('full path match')
    if specific_hits:
        score += 25 * len(specific_hits)
        reasons.append('resource-specific term match')
    path_hits = [term for term in path_literals(endpoint) if term.lower() in text]
    if path_hits:
        score += 15 * len(path_hits)
        reasons.append('path literal match')
    resource_hits = [term for term in lower_terms(resource_ids + resource_categories) if term in text]
    if resource_hits:
        score += 10 * len(resource_hits)
        reasons.append('resource identifier/category match')
    if section['section_type'] in {'security', 'error responses', 'resource definition', 'resource standard methods'} and (op_hits or path_hits or resource_hits):
        score += 20
        reasons.append(f'{section['section_type']} with endpoint terms')
    if section['section_type'] in {'resource definition', 'resource standard methods'} and (not exact_resource_match(record, section)):
        score -= 90
        reasons.append('penalized generic method/resource match')
    if section['section_type'] == 'procedure/cross-reference' and procedure_hits:
        score += 45 * len(procedure_hits)
        reasons.append('procedure query term match')
    if section['section_type'] == 'procedure/cross-reference' and tag_summary_matches_section(record, section):
        score += 120
        reasons.append('tag/summary subsection match')
    if section['section_type'] in {'service operations overview', 'resources and methods overview'}:
        score += 5
        reasons.append(f'{section['section_type']} overview')
    if record.get('method', '').lower() == section.get('section_title', '').lower():
        score += 60
        reasons.append('HTTP method section match')
    if section['ts_id'] == 'TS23502' and 'bmca' in text:
        score -= 200
        reasons.append('penalized unrelated BMCA context')
    return (score, '; '.join(dict.fromkeys(reasons)) or 'overview/context')

def context_item(endpoint_id: str, section: Dict[str, Any], priority: int, reason: str, source: str='section_index') -> Dict[str, Any]:
    text = compact_context_text(section['text'])
    if len(text) > MAX_CONTEXT_TEXT_CHARS:
        text = text[:MAX_CONTEXT_TEXT_CHARS].rstrip() + '\n[truncated]'
    return {'endpoint_id': endpoint_id, 'context_id': f'{endpoint_id}::{section['section_id']}', 'source': source, 'ts_id': section['ts_id'], 'section_id': section['section_id'], 'section_number': section['section_number'], 'section_title': section['section_title'], 'section_type': section['section_type'], 'priority': priority, 'selection_reason': reason, 'line_start': section['line_start'], 'line_end': section['line_end'], 'text': text}

def parent_section_number(section_number: str) -> str:
    parts = section_number.split('.')
    if len(parts) <= 1:
        return ''
    return '.'.join(parts[:-1])

def aggregate_parent_with_children(section_rows: List[Dict[str, Any]], child_section: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    parent_number = parent_section_number(child_section.get('section_number', ''))
    if not parent_number:
        return None
    ts_id = child_section['ts_id']
    parent = next((row for row in section_rows if row['ts_id'] == ts_id and row['section_number'] == parent_number), None)
    if parent is None:
        return None
    return aggregate_section_with_children(section_rows, parent)

def aggregate_section_with_children(section_rows: List[Dict[str, Any]], parent: Dict[str, Any], section_type_override: Optional[str]=None, section_id_suffix: str='with-children') -> Optional[Dict[str, Any]]:
    ts_id = parent['ts_id']
    parent_number = parent.get('section_number', '')
    prefix = f'{parent_number}.'
    children = [row for row in section_rows if row['ts_id'] == ts_id and row['section_number'].startswith(prefix)]
    children.sort(key=lambda row: row['line_start'])
    if not children:
        return None
    text_parts = [parent['text']] + [child['text'] for child in children]
    aggregate = dict(parent)
    aggregate['section_id'] = f'{parent['section_id']}:{section_id_suffix}'
    aggregate['section_type'] = section_type_override or parent['section_type']
    aggregate['line_start'] = min([parent['line_start']] + [child['line_start'] for child in children])
    aggregate['line_end'] = max((child['line_end'] for child in children))
    aggregate['text'] = '\n'.join((part for part in text_parts if part)).strip()
    return aggregate

def section_by_number(section_rows: List[Dict[str, Any]], ts_id: str, section_number: str) -> Optional[Dict[str, Any]]:
    return next((row for row in section_rows if row['ts_id'] == ts_id and row['section_number'] == section_number), None)

def ancestor_section_numbers(section_number: str) -> List[str]:
    parts = section_number.split('.')
    ancestors = []
    for end in range(len(parts) - 1, 0, -1):
        ancestors.append('.'.join(parts[:end]))
    return ancestors

def is_resource_parent(section: Dict[str, Any]) -> bool:
    return section.get('section_title', '').strip().lower().startswith('resource:')

def resource_parent_for_section(section_rows: List[Dict[str, Any]], child_section: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if is_resource_parent(child_section):
        return child_section
    for number in ancestor_section_numbers(child_section.get('section_number', '')):
        parent = section_by_number(section_rows, child_section['ts_id'], number)
        if parent and is_resource_parent(parent):
            return parent
    return None

def lower_text(section: Dict[str, Any]) -> str:
    return f'{section.get('section_title', '')}\n{section.get('text', '')}'.lower()

def endpoint_path_terms(endpoint: str, include_suffixes: bool=True, include_prefixes: bool=False) -> List[str]:
    terms = [endpoint]
    parts = [part for part in endpoint.split('/') if part]
    if include_prefixes:
        for end in range(2, len(parts)):
            terms.append('/' + '/'.join(parts[:end]))
    if include_suffixes:
        for suffix in endpoint_suffixes(endpoint):
            if '/' in suffix:
                terms.append(suffix)
                terms.append(f'/{suffix}')
            elif len(suffix) >= 6:
                terms.append(f'/{suffix}')
    return list(dict.fromkeys((term.lower() for term in terms if term)))

def first_matching_path_term(record: Dict[str, Any], section: Dict[str, Any], include_suffixes: bool=True, include_prefixes: bool=False) -> str:
    text = lower_text(section)
    endpoint = record.get('endpoint', record.get('path', ''))
    for term in endpoint_path_terms(endpoint, include_suffixes=include_suffixes, include_prefixes=include_prefixes):
        if term and term in text:
            return term
    return ''

def normalized_phrase(value: str) -> str:
    expanded = ' '.join(split_terms(value))
    return re.sub('[^a-z0-9]+', ' ', expanded.lower()).strip()

def phrase_matches_title_or_text(phrase: str, section: Dict[str, Any]) -> bool:
    if not phrase:
        return False
    raw = phrase.lower()
    text = lower_text(section)
    if raw in text:
        return True
    normalized = normalized_phrase(phrase)
    if not normalized:
        return False
    title_normalized = normalized_phrase(section.get('section_title', ''))
    return normalized in title_normalized

def phrase_matches_title(phrase: str, section: Dict[str, Any]) -> bool:
    if not phrase:
        return False
    title = section.get('section_title', '')
    if phrase.lower() in title.lower():
        return True
    normalized = normalized_phrase(phrase)
    title_normalized = normalized_phrase(title)
    return bool(normalized and normalized in title_normalized)

def operation_id_phrases(record: Dict[str, Any]) -> List[str]:
    operation_id = record.get('operationId', '')
    if not operation_id:
        return []
    pieces = [piece for piece in split_terms(operation_id) if piece != operation_id]
    phrases = [operation_id]
    if pieces:
        phrases.append(' '.join(pieces))
    return list(dict.fromkeys((phrase for phrase in phrases if phrase)))

def tag_summary_phrases(record: Dict[str, Any]) -> List[str]:
    phrases = []
    phrases.extend((str(tag) for tag in record.get('tags', []) if tag))
    if record.get('summary'):
        phrases.append(str(record['summary']))
    return list(dict.fromkeys(phrases))

def method_and_path_anchor(record: Dict[str, Any], section: Dict[str, Any]) -> str:
    method = record.get('method', '').lower()
    if not method or method not in lower_text(section):
        return ''
    text = lower_text(section)
    endpoint = record.get('endpoint', record.get('path', ''))
    term = endpoint.lower()
    if term and term in text:
        return f'{record.get('method', '')} + {term}'
    return ''

def method_and_leaf_anchor(record: Dict[str, Any], section: Dict[str, Any]) -> str:
    method = record.get('method', '').lower()
    if not method or method not in lower_text(section):
        return ''
    tokens = endpoint_leaf_tokens(record)
    if len(tokens) < 2:
        return ''
    text_tokens = set(semantic_tokens(lower_text(section)))
    overlap = tokens & text_tokens
    if len(overlap) / len(tokens) >= 0.67:
        return f'{record.get('method', '')} + endpoint leaf tokens {sorted(overlap)}'
    return ''

def operation_id_anchor(record: Dict[str, Any], section: Dict[str, Any]) -> str:
    for phrase in operation_id_phrases(record):
        if phrase_matches_title(phrase, section):
            return phrase
    return ''

def service_operation_title_anchor(record: Dict[str, Any], section: Dict[str, Any]) -> str:
    title = section.get('section_title', '')
    title_lc = title.lower()
    if 'service operation' not in title_lc:
        return ''
    service = str(record.get('service', '')).lower()
    service_compact = re.sub('[^a-z0-9]+', '', service)
    title_compact = re.sub('[^a-z0-9]+', '', title_lc)
    if service_compact and service_compact not in title_compact:
        return ''
    operation_terms = [term.lower() for term in split_terms(str(record.get('operationId', ''))) if len(term) >= 4]
    title_terms = set(semantic_tokens(title))
    title_terms.update((term.lower() for term in split_terms(title) if len(term) >= 4))
    operation_term_set = set(operation_terms)
    operation_modifiers = {'create', 'delete', 'notify', 'release', 'update', 'retrieve', 'read', 'get', 'registration', 'deregistration', 'context', 'policy'}
    unexpected_modifiers = (title_terms & operation_modifiers) - operation_term_set
    tolerated = {'context', 'policy'}
    if unexpected_modifiers - tolerated:
        return ''
    operation_terms = [term for term in operation_terms if term not in {'policy', 'context', 'session', 'data', 'service', 'operation'}]
    for term in operation_terms:
        if term in title_lc or term in title_compact:
            return f'service operation title + operationId term {term}'
    return ''

def tag_summary_anchor(record: Dict[str, Any], section: Dict[str, Any]) -> str:
    for phrase in tag_summary_phrases(record):
        if phrase_matches_title(phrase, section):
            return phrase
    return ''

def mapped_operation_terms_from_overview(record: Dict[str, Any], overview: Optional[Dict[str, Any]]) -> List[str]:
    if not overview:
        return []
    lines = overview.get('text', '').splitlines()
    path_terms = endpoint_path_terms(record.get('endpoint', record.get('path', '')), include_suffixes=False)
    hit_index = None
    for index, line in enumerate(lines):
        lower_line = line.lower()
        if any((term in lower_line for term in path_terms)):
            hit_index = index
            break
    if hit_index is None:
        return []
    ignored = {'resource name(archetype)', 'resource uri', 'http method or custom operation', 'description', 'get', 'put', 'post', 'patch', 'delete'}
    terms = []
    for line in lines[hit_index + 1:hit_index + 8]:
        value = line.strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in ignored or lowered.startswith('/') or lowered.startswith('{'):
            continue
        if re.fullmatch('(get|put|post|patch|delete|\\w+\\(post\\))', lowered):
            continue
        terms.append(value)
    return list(dict.fromkeys(terms))

def procedure_anchor_from_overview_terms(section: Dict[str, Any], overview_terms: List[str]) -> str:
    for term in overview_terms:
        if phrase_matches_title(term, section):
            return term
    return ''

def procedure_prefix_for_resource_parent(resource_parent: Optional[Dict[str, Any]]) -> str:
    if not resource_parent:
        return ''
    parts = resource_parent.get('section_number', '').split('.')
    if len(parts) < 2 or parts[0] != '6' or (not parts[1].isdigit()):
        return ''
    return f'5.{int(parts[1]) + 1}.'

def select_context_items(record: Dict[str, Any], section_rows: List[Dict[str, Any]], selected_ts_ids: List[str], max_items: int, include_openapi_annex: bool=False) -> tuple:
    endpoint_id = record.get('id', item_id(record))
    stage3_ts = endpoint_stage3_ts(record)
    stage3_rows = [row for row in section_rows if row['ts_id'] == stage3_ts]
    candidates = [row for row in section_rows if row['ts_id'] in selected_ts_ids]
    selected: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    selected_resource_parent: Optional[Dict[str, Any]] = None

    def add_section(section: Dict[str, Any], reason: str, source: str='section_index') -> None:
        if len(selected) >= max_items or section['section_id'] in seen:
            return
        selected.append(context_item(endpoint_id, section, len(selected) + 1, reason, source=source))
        seen.add(section['section_id'])

    def resource_specific_context() -> None:
        nonlocal selected_resource_parent
        matches = [row for row in stage3_rows if row['section_type'] != 'openapi_annex' and resource_parent_for_section(section_rows, row) is not None and first_matching_path_term(record, row, include_suffixes=True, include_prefixes=True)]
        scored_matches = []
        endpoint = record.get('endpoint', record.get('path', '')).lower()
        for row in matches:
            parent = resource_parent_for_section(section_rows, row)
            if not parent:
                continue
            text = lower_text(row)
            path_term = first_matching_path_term(record, row, include_suffixes=True, include_prefixes=True)
            score = 100
            if endpoint and endpoint in text:
                score += 500
                anchor = f'full endpoint path {endpoint}'
            else:
                score += 250
                anchor = f'path suffix {path_term}'
            score += min(len(path_term), 80)
            if row['section_type'] == 'resource definition':
                score += 140
            if 'operation:' in row.get('section_title', '').lower():
                score += 120
            if 'custom operation' in row.get('section_title', '').lower():
                score += 90
            if row['section_type'] == 'resources and methods overview':
                score -= 120
            scored_matches.append((score, row['line_start'], row, parent, anchor))
        scored_matches.sort(key=lambda item: (-item[0], item[1], item[2]['section_id']))
        if not scored_matches:
            return
        _score, _line, anchor_section, parent, anchor = scored_matches[0]
        aggregate = aggregate_section_with_children(section_rows, parent, section_type_override='resource specific context', section_id_suffix='resource-with-children')
        if aggregate:
            selected_resource_parent = parent
            reason = f'cascade_step=resource_specific_context; anchor={anchor} in {anchor_section['ts_id']} {anchor_section['section_number']} {anchor_section['section_title']}; parent={parent['section_number']} {parent['section_title']}'
            add_section(aggregate, reason, source='section_index_resource_subtree')

    def resources_overview_context() -> Optional[Dict[str, Any]]:
        endpoint = record.get('endpoint', record.get('path', '')).lower()
        matches = [row for row in stage3_rows if row['section_type'] == 'resources and methods overview' and endpoint and (endpoint in lower_text(row)) and (row['section_id'] not in seen)]
        matches.sort(key=lambda row: (row['line_start'], row['section_id']))
        if not matches:
            return None
        section = matches[0]
        reason = f'cascade_step=resources_and_methods_overview; anchor=full endpoint path {endpoint}'
        add_section(section, reason)
        return section

    def procedure_context(overview: Optional[Dict[str, Any]]) -> None:
        overview_terms = mapped_operation_terms_from_overview(record, overview)
        procedure_prefix = procedure_prefix_for_resource_parent(selected_resource_parent)
        procedure_rows = [row for row in stage3_rows if (row['section_number'].startswith('4.') or row['section_number'].startswith('5.')) and (row['section_number'].startswith('4.') or not procedure_prefix or row['section_number'].startswith(procedure_prefix)) and (row['section_type'] != 'openapi_annex') and (row['section_id'] not in seen) and (not row['section_title'].lower().startswith('type:'))]
        phases = [('service_operation_title', lambda row: service_operation_title_anchor(record, row)), ('method_path', lambda row: method_and_path_anchor(record, row)), ('operation_id_title', lambda row: operation_id_anchor(record, row)), ('tag_summary_title', lambda row: tag_summary_anchor(record, row)), ('method_resource_tokens', lambda row: method_and_leaf_anchor(record, row)), ('overview_mapped_operation', lambda row: procedure_anchor_from_overview_terms(row, overview_terms))]
        for phase_name, anchor_fn in phases:
            matches = []
            for row in procedure_rows:
                anchor = anchor_fn(row)
                if anchor:
                    matches.append((row['line_start'], row, anchor))
            if not matches:
                continue
            matches.sort(key=lambda item: (item[0], item[1]['section_id']))
            _line, section, anchor = matches[0]
            aggregate = aggregate_section_with_children(section_rows, section, section_type_override='procedure/cross-reference', section_id_suffix='procedure-with-children')
            selected_section = aggregate or dict(section)
            selected_section['section_type'] = 'procedure/cross-reference'
            reason = f'cascade_step=procedure; phase={phase_name}; anchor={anchor}'
            add_section(selected_section, reason, source='section_index_procedure_anchor')
            return

    def openapi_annex_fallback() -> None:
        endpoint = record.get('endpoint', record.get('path', '')).lower()
        operation_id = record.get('operationId', '').lower()
        matches = [row for row in candidates if row['section_type'] == 'openapi_annex' and row['section_id'] not in seen and (endpoint and endpoint in lower_text(row) or (operation_id and operation_id in lower_text(row)))]
        matches.sort(key=lambda row: (row['ts_id'] != stage3_ts, row['line_start'], row['section_id']))
        if matches:
            add_section(matches[0], 'cascade_step=openapi_annex_fallback; anchor=seed endpoint path or operationId')
    resource_specific_context()
    overview = resources_overview_context()
    procedure_context(overview)
    if include_openapi_annex:
        openapi_annex_fallback()
    required_types = ['resources and methods overview', 'resource specific context', 'procedure/cross-reference']
    gaps: List[str] = []
    present_types = {item['section_type'] for item in selected}
    for section_kind in required_types:
        if section_kind in present_types:
            continue
        gaps.append(f'no {section_kind} context selected')
    selected.sort(key=lambda item: (item['priority'], item['ts_id'], item['line_start']))
    return (selected, gaps)

def build_context_pack(record: Dict[str, Any], section_rows: List[Dict[str, Any]], max_items: int, include_common_context_ts: bool=False, include_openapi_annex: bool=False) -> Dict[str, Any]:
    present = locally_present_ts_ids(section_rows)
    selected_ts_ids, ts_gaps = selected_ts_ids_for_record(record, present, include_common=include_common_context_ts)
    selected_items, selection_gaps = select_context_items(record, section_rows, selected_ts_ids, max_items, include_openapi_annex=include_openapi_annex)
    return {'endpoint_id': record.get('id', item_id(record)), 'openapi_metadata': openapi_seed_metadata(record), 'selected_ts_ids': selected_ts_ids, 'selection_strategy': 'cascade_v1_stage3_resource_procedure_overview', 'context_items': selected_items, 'context_gaps': ts_gaps + selection_gaps}

def command_index_ts_sections(args: argparse.Namespace) -> int:
    rows = index_ts_sections(Path(args.ts_corpus))
    write_jsonl(Path(args.output), rows)
    print(f'Wrote {len(rows)} TS sections to {args.output}.')
    return 0

def command_ensure_ts_corpus(args: argparse.Namespace) -> int:
    records = load_json(Path(args.operations))
    ts_ids = set(discover_needed_ts_from_endpoint_list(records))
    if args.include_common_ts:
        ts_ids.update(COMMON_TS_IDS)
    manifest = [ensure_ts_text(ts_id, raw_dir=Path(args.ts_raw), extracted_dir=Path(args.ts_corpus), download=True, timeout=args.download_timeout, release=args.ts_release, antiword_command=args.antiword_command, antiword_home=args.antiword_home, pdftotext_command=args.pdftotext_command) for ts_id in sorted(ts_ids)]
    write_json(Path(args.output), manifest)
    statuses = {}
    for row in manifest:
        statuses[row['status']] = statuses.get(row['status'], 0) + 1
    status_text = ', '.join((f'{key}: {value}' for key, value in sorted(statuses.items()))) or 'none'
    print(f'Ensured {len(manifest)} TS text files in {args.ts_corpus} ({status_text}).')
    print(f'Wrote TS manifest to {args.output}.')
    return 0

def command_build_operation_context_packs(args: argparse.Namespace) -> int:
    records = load_json(Path(args.operations))
    section_rows = read_jsonl(Path(args.section_index))
    packs = [build_context_pack(record, section_rows, args.max_context_items, include_common_context_ts=args.include_common_context_ts, include_openapi_annex=args.include_openapi_annex) for record in records]
    write_jsonl(Path(args.output), packs)
    print(f'Wrote {len(packs)} operation context packs to {args.output}.')
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Prepare, index, and retrieve deterministic TS context packs.')
    subparsers = parser.add_subparsers(dest='command', required=True)
    ensure_corpus = subparsers.add_parser('ensure-ts-corpus', help='Download/extract missing TS text files needed by the endpoint list.')
    ensure_corpus.add_argument('--operations', default=str(DEFAULT_SEED_ENDPOINTS))
    ensure_corpus.add_argument('--ts-corpus', default=str(DEFAULT_RUN_TS_CORPUS))
    ensure_corpus.add_argument('--ts-raw', default=str(DEFAULT_TS_RAW))
    ensure_corpus.add_argument('--ts-release', default='17')
    ensure_corpus.add_argument('--download-timeout', type=int, default=60)
    ensure_corpus.add_argument('--antiword-command', default='', help='Path or command name for antiword when a TS archive contains legacy .doc.')
    ensure_corpus.add_argument('--antiword-home', default='', help='Optional directory containing antiword character-mapping files.')
    ensure_corpus.add_argument('--pdftotext-command', default='', help='Path or command name for pdftotext used by an official-PDF fallback.')
    ensure_corpus.add_argument('--include-common-ts', action='store_true')
    ensure_corpus.add_argument('--output', default=str(DEFAULT_TS_MANIFEST))
    ensure_corpus.set_defaults(func=command_ensure_ts_corpus)
    index_sections = subparsers.add_parser('index-ts-sections', help='Index local extracted TS text files into numbered sections.')
    index_sections.add_argument('--ts-corpus', default=str(DEFAULT_RUN_TS_CORPUS))
    index_sections.add_argument('--output', default=str(DEFAULT_SECTION_INDEX))
    index_sections.set_defaults(func=command_index_ts_sections)
    context_packs = subparsers.add_parser('build-operation-context-packs', help='Retrieve section-focused context packs for selected endpoints.')
    context_packs.add_argument('--operations', default=str(DEFAULT_SEED_ENDPOINTS))
    context_packs.add_argument('--section-index', default=str(DEFAULT_SECTION_INDEX))
    context_packs.add_argument('--output', default=str(DEFAULT_CONTEXT_PACKS))
    context_packs.add_argument('--max-context-items', type=int, default=16)
    context_packs.add_argument('--include-common-context-ts', action='store_true')
    context_packs.add_argument('--include-openapi-annex', action='store_true')
    context_packs.set_defaults(func=command_build_operation_context_packs)
    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)
if __name__ == '__main__':
    raise SystemExit(main())
