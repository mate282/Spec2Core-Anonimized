import argparse
import json
import sys
from pathlib import Path
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'shared'))
import ai_client
import llm_analyst
import reporter
GREEN = '\x1b[92m'
RED = '\x1b[91m'
YELLOW = '\x1b[93m'
BLUE = '\x1b[94m'
RESET = '\x1b[0m'
SCENARIOS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'scenarios'
RESULTS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'results'
_VERDICT_COLOR = {llm_analyst.IMPLEMENTATION_NONCONFORMANCE: RED, llm_analyst.OPTIONAL_CHECK_NOT_APPLIED: YELLOW, llm_analyst.SPECIFICATION_GAP: RED, llm_analyst.CHECK_CONFIRMED: GREEN, llm_analyst.UNEXPECTED_PROTECTION: GREEN, llm_analyst.CONDITION_NOT_TRIGGERED: YELLOW, llm_analyst.NO_SPEC_DATA: YELLOW, llm_analyst.INCONCLUSIVE: YELLOW}

def _load_scenarios(scenario_filter: str | None, scenarios_dir: Path=SCENARIOS_DIR) -> list[dict]:
    files = sorted(scenarios_dir.glob('*.yaml'))
    if not files:
        print(f'{RED}No scenario found in {scenarios_dir}.{RESET}')
        print('Run: python stage_a/stage_a.py --finalize')
        sys.exit(1)
    scenarios = []
    for path in files:
        with open(path, encoding='utf-8') as f:
            spec = yaml.safe_load(f)
        if scenario_filter and scenario_filter not in spec.get('attack_id', ''):
            continue
        scenarios.append(spec)
    if scenario_filter and (not scenarios):
        print(f"{RED}Scenario '{scenario_filter}' not found.{RESET}")
        sys.exit(1)
    return scenarios

def _load_evidence(scenario_id: str, results_dir: Path) -> dict | None:
    code = reporter.scenario_folder_name(scenario_id)
    path = results_dir / code / 'evidence.json'
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding='utf-8'))

def _write_analysis(scenario_id: str, results_dir: Path, analysis: dict) -> Path:
    code = reporter.scenario_folder_name(scenario_id)
    run_dir = results_dir / code
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'stage_c_analysis.json').write_text(json.dumps(analysis, indent=2, default=str, ensure_ascii=False), encoding='utf-8')
    case_id = analysis['test_expectation'].get('case_id')
    lines = [f'# Stage C — Specification Comparison — {scenario_id}', '', f'**Final verdict:** `{analysis['final_verdict']}`  (source: `{analysis['source']}`, confidence: `{analysis['confidence']}`)', '']
    if analysis.get('protection_match'):
        lines += [f'**Protection match:** `{analysis['protection_match']}`', '']
    if analysis['final_verdict'] == llm_analyst.OPTIONAL_CHECK_NOT_APPLIED:
        lines += ['The TS permits omitting this check. This assessment is not a mandatory-check implementation nonconformance; the Stage B runtime outcome remains separate.', '']
    if case_id is not None:
        case_index = analysis['test_expectation'].get('case_index')
        case_count = analysis['test_expectation'].get('case_count')
        lines += [f'**Authorization case:** `{case_id}` ({(case_index or 0) + 1} of {case_count} for this endpoint)', '']
    lines += [f'> {analysis['reasoning']}', '', '## Deterministic classification', '', f'- Verdict: `{analysis['deterministic']['final_verdict']}`', f'- Protection match: `{analysis['deterministic'].get('protection_match')}`', f'- Confidence: `{analysis['deterministic']['confidence']}`', f'- Reasoning: {analysis['deterministic']['reasoning']}', '']
    if analysis.get('ai'):
        lines += ['## AI classification', '', f'- Verdict: `{analysis['ai'].get('final_verdict')}`', f'- Confidence: `{analysis['ai'].get('confidence')}`', f'- Reasoning: {analysis['ai'].get('reasoning')}', '']
    lines += ['## test_expectation', '', '```json', json.dumps(analysis['test_expectation'], indent=2, default=str, ensure_ascii=False), '```', '', '## runtime_result', '', '```json', json.dumps(analysis['runtime_result'], indent=2, default=str, ensure_ascii=False), '```', '']
    (run_dir / 'stage_c_analysis.md').write_text('\n'.join(lines), encoding='utf-8')
    return run_dir

def main() -> None:
    parser = argparse.ArgumentParser(description='5G Core Security Tester — Stage C: Specification-vs-Runtime Analysis', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="\nExamples:\n  python stage_c/stage_c.py                          # analyze every scenario that has a Stage B result\n  python stage_c/stage_c.py --scenario S02           # only scenarios with 'S02' in the ID\n  python stage_c/stage_c.py --ai-key sk-...         # enable AI-assisted comparison\n  python stage_c/stage_c.py -v                       # verbose\n        ")
    parser.add_argument('--scenario', default=None, help='Filter by scenario ID (partial match)')
    parser.add_argument('--results-dir', type=Path, default=RESULTS_DIR, help=f'Stage B results directory to read/write (default: {RESULTS_DIR})')
    parser.add_argument('--scenarios-dir', type=Path, default=SCENARIOS_DIR, help=f'Directory to read scenarios/*.yaml from (default: {SCENARIOS_DIR}) — must match whatever --scenarios-dir Stage B was run with for the same batch.')
    parser.add_argument('--ai-key', default='', help='AI provider API key')
    parser.add_argument('--ai-base-url', default='https://api.openai.com/v1', help='API base URL (e.g. https://api.mistral.ai/v1 for Mistral)')
    parser.add_argument('--ai-path', default='/chat/completions', help='Completions endpoint path relative to base-url')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    scenarios = _load_scenarios(args.scenario, args.scenarios_dir)
    ai_config = {'api_key': args.ai_key, 'base_url': args.ai_base_url, 'completions_path': args.ai_path}
    print(f'{'=' * 70}')
    print(f'  5G Core Security Tester — Stage C')
    print(f'  Scenarios: {len(scenarios)}  |  AI: {('enabled (' + ai_client.DEFAULT_MODEL + ')' if args.ai_key else 'not configured')}')
    print(f'{'=' * 70}\n')
    analyzed, skipped = (0, 0)
    for scenario in scenarios:
        sid = scenario['attack_id']
        evidence = _load_evidence(sid, args.results_dir)
        if evidence is None:
            print(f'  {YELLOW}[SKIP]{RESET} {sid}: no Stage B result found (run: python stage_b/stage_b.py --scenario {sid})')
            skipped += 1
            continue
        analysis = llm_analyst.analyze(scenario, evidence, ai_config)
        run_dir = _write_analysis(sid, args.results_dir, analysis)
        color = _VERDICT_COLOR.get(analysis['final_verdict'], RESET)
        print(f'  {color}[{analysis['final_verdict']}]{RESET} {sid}')
        if args.verbose:
            print(f'      source={analysis['source']} confidence={analysis['confidence']}')
            print(f'      {analysis['reasoning']}')
        print(f'      -> {run_dir}/stage_c_analysis.md')
        analyzed += 1
    print(f'\n{'=' * 70}')
    print(f'  Analyzed: {analyzed}  |  Skipped (no Stage B result): {skipped}')
    print(f'{'=' * 70}\n')
    summary_path = reporter.write_summary(args.results_dir, args.scenarios_dir)
    print(f'Summary updated: {summary_path}\n')
    for batch_path in reporter.write_batch_summaries(args.results_dir, args.scenarios_dir):
        print(f'Batch summary updated: {batch_path}')
if __name__ == '__main__':
    main()
