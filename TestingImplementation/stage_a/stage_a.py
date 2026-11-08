import argparse
import sys
from pathlib import Path
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'shared'))
import parser as attack_parser
import authorization_profiles
import enricher
import review as review_gate
import ai_client
REPO_ROOT = PROJECT_ROOT.parent
ATTACKS_LIST = REPO_ROOT / 'manual-attacks' / 'AttacksList.md'
AUTHORIZATION_PROFILES = PROJECT_ROOT / 'input' / 'authorization_profiles.json'
SPECS_DIR = REPO_ROOT / 'docs' / 'specs'
REVIEW_DIR = PROJECT_ROOT / 'runs' / 'main' / 'review'
SCENARIOS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'scenarios'
LAB_CONFIG = PROJECT_ROOT / 'configs' / 'lab.yaml'

def configured_fixture_nf_types(config_path: Path) -> set[str]:
    with open(config_path, encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}
    services = config.get('services') or {}
    if not isinstance(services, dict):
        raise ValueError(f"{config_path}: 'services' must be an object")
    owners = {role[:-2].upper() for role in services if isinstance(role, str) and role.endswith('_1')}
    attackers = {role[:-2].upper() for role in services if isinstance(role, str) and role.endswith('_2')}
    return owners & attackers

def run_pipeline(attacks_list: Path, profiles: Path | None, specs_dir: Path, ai_config: dict, verbose: bool, review_dir: Path=REVIEW_DIR, lab_config: Path=LAB_CONFIG, incremental: bool=False) -> None:
    print('=' * 60)
    print('  Stage A — Spec Enrichment')
    print('=' * 60)
    if profiles is not None:
        print(f'\n[A1] Parsing {profiles.name} (authorization-profiles JSON) ...')
        partials = authorization_profiles.parse_authorization_profiles(profiles)
    else:
        print(f'\n[A1] Parsing {attacks_list.name} ...')
        partials = attack_parser.parse_attacks_list(attacks_list)
    print(f'     {len(partials)} attacks found:')
    for p in partials:
        print(f'     - {p['attack_id']}: {p['title']}')
    fixture_nf_types = configured_fixture_nf_types(lab_config)
    print(f'     Lab fixture pairs ({lab_config.name}): {', '.join(sorted(fixture_nf_types)) or 'none'}')
    print(f'\n[A2] Enrichment ...')
    ai_active = bool(ai_config.get('api_key'))
    if ai_active:
        print(f'     AI: {ai_client.DEFAULT_MODEL} @ {ai_config.get('base_url')}')
    else:
        print(f'     AI: not configured (use --ai-key to enable it)')
    enriched_list = []
    for partial in partials:
        if incremental and review_gate.existing_review_matches(partial, review_dir):
            print(f'     {partial['attack_id']}: [PRESERVED — unchanged profile]')
            continue
        enriched = enricher.enrich(partial, specs_dir=specs_dir, ai_config=ai_config, fixture_nf_types=fixture_nf_types)
        enriched_list.append(enriched)
        status = 'NEEDS REVIEW' if enriched['needs_review'] else 'OK'
        print(f'     {partial['attack_id']}: [{status}]')
        if verbose and enriched['review_reasons']:
            for reason in enriched['review_reasons']:
                print(f'       !{reason}')
    print(f'\n[A3] Generating review files ...')
    for enriched in enriched_list:
        path = review_gate.write_review_file(enriched, review_dir)
        print(f'     Written: {(path.relative_to(PROJECT_ROOT) if path.is_relative_to(PROJECT_ROOT) else path)}')
    print()
    print(f'Done. Review the files in {review_dir} and then run:')
    print(f'  python stage_a/stage_a.py --finalize --review-dir {review_dir} --scenarios-dir <...>')
    print()

def finalize(review_dir: Path=REVIEW_DIR, scenarios_dir: Path=SCENARIOS_DIR) -> None:
    print('=' * 60)
    print(f'  Stage A — Finalize: approved ({review_dir}) -> {scenarios_dir}')
    print('=' * 60)
    approved = review_gate.load_approved_reviews(review_dir)
    if not approved:
        print()
        print('No approved file found.')
        print(f"Set 'approved: true' in the {review_dir} files and re-run.")
        return
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    for record in approved:
        spec = record['enriched_spec']
        attack_id = spec['attack_id']
        out_path = scenarios_dir / f'{attack_id}.yaml'
        with open(out_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)
        print(f'  {(out_path.relative_to(PROJECT_ROOT) if out_path.is_relative_to(PROJECT_ROOT) else out_path)}')
    print()
    print(f'{len(approved)} scenario(s) written to {scenarios_dir}')
    print('Stage A complete. Ready for Stage B.')

def main() -> None:
    parser = argparse.ArgumentParser(description='5G Core Security Tester — Stage A: Spec Enrichment', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExamples:\n  python stage_a/stage_a.py                           # deterministic rules only, default JSON input\n  python stage_a/stage_a.py -v                        # verbose output with review reasons\n  python stage_a/stage_a.py --ai-key sk-...           # enable AI (model: ai_client.DEFAULT_MODEL)\n  python stage_a/stage_a.py --attacks-list manual-attacks/AttacksList.md  # retired input, still supported\n  python stage_a/stage_a.py --finalize                # copy approved specs into scenarios/\n        ')
    parser.add_argument('--attacks-list', type=Path, default=None, help=f'Path to AttacksList.md — retired as the default A1 input (was: {ATTACKS_LIST}); pass this explicitly to still use it. Ignored if --profiles is given.')
    parser.add_argument('--profiles', type=Path, nargs='?', const=AUTHORIZATION_PROFILES, default=None, help=f'Path to a JSON authorization-profiles file (schema: specs-analysis/output/template_authorization_profiles.json) — the default A1 input (default: {AUTHORIZATION_PROFILES}) unless --attacks-list is given explicitly.')
    parser.add_argument('--specs-dir', type=Path, default=SPECS_DIR, help=f'Directory holding the 3GPP OpenAPI YAML files (default: {SPECS_DIR})')
    parser.add_argument('--config', type=Path, default=LAB_CONFIG, help=f'Lab manifest used to select a configured owner/attacker NF pair (default: {LAB_CONFIG}). Use the same manifest passed to Stage B.')
    parser.add_argument('--ai-key', default='', help='AI provider API key')
    parser.add_argument('--ai-base-url', default='https://api.openai.com/v1', help='API base URL (e.g. https://api.mistral.ai/v1 for Mistral)')
    parser.add_argument('--ai-path', default='/chat/completions', help='Completions endpoint path relative to base-url (OpenAI-compatible, e.g. /chat/completions for Mistral too)')
    parser.add_argument('--finalize', action='store_true', help='Copy specs with approved:true from review/ to scenarios/')
    parser.add_argument('--review-dir', type=Path, default=REVIEW_DIR, help=f"Where review/*.yaml files are written (A3) / read from (--finalize) (default: {REVIEW_DIR}). Point this at a separate directory to keep a new input catalog's review files from mixing with an existing run's.")
    parser.add_argument('--scenarios-dir', type=Path, default=SCENARIOS_DIR, help=f"Where --finalize writes scenarios/*.yaml (default: {SCENARIOS_DIR}). Point this at a separate directory to keep a new input catalog's scenarios from mixing with — or overwriting IDs in — an existing run's.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Detailed output')
    parser.add_argument('--incremental', action='store_true', help='Preserve matching existing reviews and enrich only new or changed profile cases.')
    args = parser.parse_args()
    if args.finalize:
        finalize(review_dir=args.review_dir, scenarios_dir=args.scenarios_dir)
        return
    if args.profiles is None and args.attacks_list is None:
        args.profiles = AUTHORIZATION_PROFILES
    ai_config = {'api_key': args.ai_key, 'base_url': args.ai_base_url, 'completions_path': args.ai_path}
    run_pipeline(attacks_list=args.attacks_list, profiles=args.profiles, specs_dir=args.specs_dir, ai_config=ai_config, verbose=args.verbose, review_dir=args.review_dir, lab_config=args.config, incremental=args.incremental)
if __name__ == '__main__':
    main()
