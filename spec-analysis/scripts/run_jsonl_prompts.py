import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open('r') as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                rows.append({'_jsonl_error': f'malformed prompt JSONL: {exc}', '_jsonl_line': line_no})
                continue
            if not isinstance(row, dict):
                rows.append({'_jsonl_error': 'prompt row must be a JSON object', '_jsonl_line': line_no})
                continue
            row['_jsonl_line'] = line_no
            rows.append(row)
    return rows

def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        for row in rows:
            clean_row = {key: value for key, value in row.items() if not key.startswith('_jsonl_')}
            handle.write(json.dumps(clean_row) + '\n')

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
        raise ValueError('model output must be a JSON object')
    return data

def prompt_text(row: Dict[str, Any]) -> str:
    if 'system' in row and 'user' in row:
        return f'System:\n{row['system']}\n\nUser:\n{row['user']}\n'
    if 'prompt' in row:
        return str(row['prompt'])
    return json.dumps({key: value for key, value in row.items() if not key.startswith('_')}, indent=2)

def run_command(command: str, prompt: str, timeout: int) -> Dict[str, Any]:
    result = subprocess.run(command, input=prompt, text=True, shell=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f'exit code {result.returncode}: {result.stderr.strip()}')
    return parse_json_output(result.stdout)

def output_path_from_dir(input_path: Path, output_dir: Path) -> Path:
    if '_prompts' in input_path.name:
        output_name = input_path.name.replace('_prompts', '_outputs', 1)
    else:
        output_name = f'{input_path.stem}_outputs.jsonl'
    return output_dir / output_name

def one_line_error(exc: Exception, limit: int=300) -> str:
    text = ' '.join(str(exc).split())
    return text if len(text) <= limit else text[:limit - 1] + '…'

def main() -> int:
    parser = argparse.ArgumentParser(description='Run prompt JSONL rows through a model command.')
    parser.add_argument('--input', required=True, help='Prompt JSONL input')
    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument('--output', help='Exact successful JSONL output path')
    output_group.add_argument('--output-dir', help="Model-specific output directory. The filename is derived from --input by replacing '_prompts' with '_outputs'.")
    parser.add_argument('--model-command', required=True, help='Command reading one prompt from stdin and printing JSON')
    parser.add_argument('--timeout', type=int, default=180, help='Per-row timeout in seconds')
    parser.add_argument('--start-index', type=int, default=0, help='Zero-based prompt row offset to start from')
    parser.add_argument('--limit', type=int, help='Maximum number of prompt rows to process')
    parser.add_argument('--resume', action='store_true', help='Keep existing output rows and skip already processed ids')
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else output_path_from_dir(input_path, Path(args.output_dir))
    errors_path = Path(f'{output_path}.errors.jsonl')
    outputs: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    processed_ids = set()
    if args.resume and output_path.exists():
        outputs = read_jsonl(output_path)
        processed_ids = {str(row.get('endpoint_id') or row.get('id')) for row in outputs if row.get('endpoint_id') or row.get('id')}
    rows = read_jsonl(input_path)
    end_index = len(rows) if args.limit is None else args.start_index + args.limit
    selected_rows = rows[args.start_index:end_index]
    print('JSONL prompt runner')
    print(f'  Input:       {input_path}')
    print(f'  Output:      {output_path}')
    print(f'  Errors:      {errors_path}')
    print(f'  Selected:    {len(selected_rows)} row(s) (start-index={args.start_index}, limit={(args.limit if args.limit is not None else 'all')})')
    print(f'  Resume:      {('yes' if args.resume else 'no')} ({len(processed_ids)} already completed)')
    print(f'  Timeout:     {args.timeout}s per row')
    print()
    started_at = time.monotonic()
    completed = 0
    skipped = 0
    for position, row in enumerate(selected_rows, start=1):
        line_no = row.get('_jsonl_line')
        endpoint_id = row.get('endpoint_id') or row.get('id') or f'line {line_no}'
        if '_jsonl_error' in row:
            errors.append({'line': line_no, 'error': row['_jsonl_error']})
            print(f'[{position}/{len(selected_rows)}] ERROR {endpoint_id}: {row['_jsonl_error']}', flush=True)
            continue
        if args.resume and endpoint_id and (str(endpoint_id) in processed_ids):
            skipped += 1
            print(f'[{position}/{len(selected_rows)}] SKIP  {endpoint_id} (already completed)', flush=True)
            continue
        print(f'[{position}/{len(selected_rows)}] RUN   {endpoint_id}', flush=True)
        row_started_at = time.monotonic()
        try:
            output = run_command(args.model_command, prompt_text(row), args.timeout)
            if endpoint_id and 'endpoint_id' not in output:
                output['endpoint_id'] = endpoint_id
            outputs.append(output)
            completed += 1
            elapsed = time.monotonic() - row_started_at
            print(f'[{position}/{len(selected_rows)}] OK    {endpoint_id} ({elapsed:.1f}s)', flush=True)
        except Exception as exc:
            errors.append({'line': line_no, 'id': row.get('id'), 'error': str(exc)})
            elapsed = time.monotonic() - row_started_at
            print(f'[{position}/{len(selected_rows)}] ERROR {endpoint_id} ({elapsed:.1f}s): {one_line_error(exc)}', flush=True)
    write_jsonl(output_path, outputs)
    write_jsonl(errors_path, errors)
    elapsed = time.monotonic() - started_at
    print()
    print('Run summary')
    print(f'  Completed now: {completed}')
    print(f'  Skipped:       {skipped}')
    print(f'  Failed:        {len(errors)}')
    print(f'  Total outputs: {len(outputs)}')
    print(f'  Elapsed:       {elapsed:.1f}s')
    print(f'  Output:        {output_path}')
    print(f'  Errors:        {errors_path}')
    return 1 if errors else 0
if __name__ == '__main__':
    raise SystemExit(main())
