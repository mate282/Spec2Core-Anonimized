import argparse
import json
import sys
from pathlib import Path
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'shared'))
import reporter
import runner
import ai_client
GREEN = '\x1b[92m'
RED = '\x1b[91m'
YELLOW = '\x1b[93m'
BLUE = '\x1b[94m'
RESET = '\x1b[0m'
SCENARIOS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'scenarios'
CONFIGS_DIR = PROJECT_ROOT / 'configs'
RESULTS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'results'
_VERDICT_COLOR = {'CONFIRMED_VULNERABILITY': RED, 'SECURE': GREEN, 'ROBUSTNESS_BUG': YELLOW, 'NOT_IMPLEMENTED': YELLOW, 'SETUP_FAILURE': YELLOW, 'INCONCLUSIVE': YELLOW}

def _load_config(config_path: Path) -> dict:
    with open(config_path, encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    identities_name = config_path.stem.replace('lab', 'identities', 1) + '.yaml'
    cfg['_paths'] = {'identities_file': config_path.parent / identities_name}
    return cfg

def _load_scenarios(scenario_filter: str | None, scenarios_dir: Path=SCENARIOS_DIR, batch_filters: list[str] | None=None) -> list[dict]:
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
        batch_id = (spec.get('source_provenance') or {}).get('authorization_profile_batch')
        if batch_filters and batch_id not in batch_filters:
            continue
        hint_status = spec.get('spec_analysis', {}).get('execution_hint', {}).get('status')
        if hint_status == 'requires_state_setup':
            print(f'  {YELLOW}[BEST EFFORT]{RESET} {spec.get('attack_id', path.stem)}: the TS procedure needs state this pipeline does not establish; the request will still be attempted, but a case-specific security conclusion cannot be drawn from it')
        scenarios.append(spec)
    if (scenario_filter or batch_filters) and (not scenarios):
        selected = scenario_filter or ', '.join(batch_filters or [])
        print(f"{RED}Scenario/batch '{selected}' not found.{RESET}")
        sys.exit(1)
    return scenarios

def _has_existing_result(scenario: dict, results_dir: Path) -> bool:
    sid = scenario.get('attack_id')
    fingerprint = (scenario.get('source_provenance') or {}).get('authorization_profile_fingerprint')
    for evidence_path in results_dir.glob('*/evidence.json'):
        try:
            evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            continue
        if evidence.get('scenario_id') != sid:
            continue
        old_scenario = evidence.get('scenario') or {}
        old_fingerprint = (old_scenario.get('source_provenance') or {}).get('authorization_profile_fingerprint')
        if not fingerprint or not old_fingerprint or fingerprint == old_fingerprint:
            return True
    return False

def _print_banner(scenario: dict) -> None:
    sid = scenario['attack_id']
    title = scenario.get('title', '')
    svc = scenario.get('target', {}).get('service', '?')
    meth = scenario.get('target', {}).get('method', '?')
    print(f'\n{'=' * 70}')
    print(f'  {BLUE}{sid}{RESET}')
    print(f'  {title}')
    print(f'  {svc} {meth}')
    print(f'{'=' * 70}')

def _print_verdict(verdict: str, reason: str) -> None:
    color = _VERDICT_COLOR.get(verdict, RESET)
    print(f'\n  {color}[{verdict}]{RESET}')
    print(f'  {reason}')

def _print_summary(summary: list[dict]) -> None:
    print(f'\n{'=' * 70}')
    print(f'  SUMMARY')
    print(f'{'=' * 70}')
    for s in summary:
        color = _VERDICT_COLOR.get(s['verdict'], RESET)
        tag = s['verdict'][:5].ljust(5)
        print(f'  {color}[{tag}]{RESET}  {s['scenario_id']:<45}  run: {s['run_id']}')
    confirmed = sum((1 for s in summary if s['verdict'] == 'CONFIRMED_VULNERABILITY'))
    secure = sum((1 for s in summary if s['verdict'] == 'SECURE'))
    other = len(summary) - confirmed - secure
    print(f'\n  {RED}CONFIRMED_VULNERABILITY : {confirmed}{RESET}')
    print(f'  {GREEN}SECURE                  : {secure}{RESET}')
    print(f'  {YELLOW}OTHER                   : {other}{RESET}')
    print()

def main() -> None:
    parser = argparse.ArgumentParser(description='5G Core Security Tester — Stage B: Scenario Execution', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="\nExamples:\n  python stage_b/stage_b.py                          # every scenario\n  python stage_b/stage_b.py -v                       # verbose step-by-step\n  python stage_b/stage_b.py --scenario S01           # only scenarios with 'S01' in the ID\n  python stage_b/stage_b.py --scenario S06 -v        # S06 with verbose output\n  python stage_b/stage_b.py --list                   # list scenarios without running them\n  python stage_b/stage_b.py --output-dir /tmp/runs   # custom output\n        ")
    parser.add_argument('--scenario', default=None, help='Filter by scenario ID (partial match)')
    parser.add_argument('--batch', action='append', default=[], help='Run only scenarios belonging to this authorization-profile batch; repeatable.')
    parser.add_argument('--skip-existing', action='store_true', help='Skip scenarios that already have evidence for the same profile revision.')
    parser.add_argument('--config', type=Path, default=CONFIGS_DIR / 'lab.yaml', help='Lab manifest to run against (default: configs/lab.yaml — free5GC). E.g. --config configs/lab_open5gs.yaml')
    parser.add_argument('--output-dir', type=Path, default=RESULTS_DIR, help=f'Report output directory (default: {RESULTS_DIR})')
    parser.add_argument('--scenarios-dir', type=Path, default=SCENARIOS_DIR, help=f'Directory to read scenarios/*.yaml from (default: {SCENARIOS_DIR}). Point this at a separate directory to run an isolated batch of scenarios without touching the main scenarios/ set.')
    parser.add_argument('--list', action='store_true', help='List available scenarios without running them')
    parser.add_argument('-v', '--verbose', action='store_true', help='Step-by-step output during execution')
    parser.add_argument('--resolution-mode', choices=['static', 'compare', 'agent'], default='static', help="Path-variable resolution strategy (prototype — see resolvers.py::resolve_path_variables()/extraction_agent.py). 'static' (default): unchanged behavior, the hand-written per-variable tables/regexes only. 'compare': also runs the LLM tool-calling extraction agent alongside the static resolver and records both in evidence.json/report.md, but still fires the request with the static value. 'agent': fires the request with the agent's value when it reports resolved=True. Requires --ai-key for 'compare'/'agent' to do anything; currently only affects the 'smContextRef' path variable.")
    parser.add_argument('--ai-key', default='', help='AI provider API key (for --resolution-mode compare/agent)')
    parser.add_argument('--ai-base-url', default='https://api.openai.com/v1', help='AI provider base URL (OpenAI-compatible — e.g. https://api.mistral.ai/v1)')
    parser.add_argument('--ai-path', default='/chat/completions', help='Path (relative to --ai-base-url) for the chat completions endpoint')
    parser.add_argument('--ai-max-iterations', type=int, default=None, help="Override extraction_agent's tool-calling loop budget (default: extraction_agent.MAX_ITERATIONS, currently 6). Raise this if a live run's extraction_agent trace shows it exhausting max_iterations while still making forward progress (e.g. it found the right value in a tool result but ran out of turns before verifying/submitting it).")
    parser.add_argument('--ai-history-window', type=int, default=None, help="Override extraction_agent's sliding-window size (default: extraction_agent.HISTORY_WINDOW, currently 4) — how many of the most recent tool results are sent to the model in full each turn; older ones are collapsed to a placeholder so a long loop's per-turn payload stays bounded instead of growing with every turn. Lower this if a provider's per-minute token budget is still tight even with the default; raise it if the agent seems to 'forget' something it read only a few turns ago.")
    parser.add_argument('--ai-timeout', type=int, default=None, help="Override extraction_agent's per-HTTP-call timeout in seconds (default: 30). Raise this for a larger/slower model — observed live: a 30s default was too tight for a larger hosted Mistral model and every turn failed with a read timeout before the agent could make any progress.")
    args = parser.parse_args()
    ai_ctx = {'api_key': args.ai_key, 'base_url': args.ai_base_url, 'completions_path': args.ai_path}
    if args.ai_max_iterations is not None:
        ai_ctx['max_iterations'] = args.ai_max_iterations
    if args.ai_history_window is not None:
        ai_ctx['history_window'] = args.ai_history_window
    if args.ai_timeout is not None:
        ai_ctx['timeout'] = args.ai_timeout
    scenarios = _load_scenarios(args.scenario, args.scenarios_dir, args.batch)
    if args.list:
        print(f'\nAvailable scenarios in {args.scenarios_dir}:\n')
        for s in scenarios:
            sid = s['attack_id']
            title = s.get('title', '')
            svc = s.get('target', {}).get('service', '?')
            meth = s.get('target', {}).get('method', '?')
            res_t = s.get('resource', {}).get('type', '?')
            vuln = s.get('verdict', {}).get('expected_vulnerable')
            vuln_str = 'VULN?' if vuln else 'SECURE?' if vuln is False else '?'
            print(f'  {BLUE}{sid}{RESET}')
            print(f'    {title} | {svc} {meth} | resource: {res_t} | expected: {vuln_str}')
        print()
        return
    if args.skip_existing:
        before = len(scenarios)
        scenarios = [s for s in scenarios if not _has_existing_result(s, args.output_dir)]
        print(f'  Existing compatible results skipped: {before - len(scenarios)}')
    cfg = _load_config(args.config)
    print(f'{'=' * 70}')
    print(f'  5G Core Security Tester — Stage B')
    print(f'  Scenarios: {len(scenarios)}  |  Output: {args.output_dir}')
    if args.resolution_mode != 'static':
        ai_status = f'enabled ({ai_client.DEFAULT_MODEL})' if args.ai_key else 'NOT CONFIGURED — falls back to static'
        print(f'  Resolution mode: {args.resolution_mode}  |  AI: {ai_status}')
    print(f'{'=' * 70}')
    summary = []
    for scenario in scenarios:
        _print_banner(scenario)
        result, run_dir = runner.run_and_report(scenario=scenario, cfg=cfg, results_dir=args.output_dir, verbose=args.verbose, resolution_mode=args.resolution_mode, ai_ctx=ai_ctx)
        verdict = result['verdict']
        reason = result['verdict_reason']
        _print_verdict(verdict, reason)
        print(f'\n  Report: {run_dir}')
        summary.append({'scenario_id': result['scenario_id'], 'verdict': verdict, 'reason': reason, 'run_id': result['run_id']})
    _print_summary(summary)
    summary_path = reporter.write_summary(args.output_dir, args.scenarios_dir)
    print(f'  Summary updated: {summary_path}\n')
    for batch_path in reporter.write_batch_summaries(args.output_dir, args.scenarios_dir):
        print(f'  Batch summary updated: {batch_path}')
if __name__ == '__main__':
    main()
