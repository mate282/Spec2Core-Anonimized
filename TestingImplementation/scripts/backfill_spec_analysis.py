import argparse
from pathlib import Path
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
import spec_lookup
REPO_ROOT = PROJECT_ROOT.parent
AUTHORIZATION_PROFILES = PROJECT_ROOT / 'input' / 'authorization_profiles.json'
SCENARIOS_DIR = PROJECT_ROOT / 'runs' / 'main' / 'scenarios'
REVIEW_DIR = PROJECT_ROOT / 'runs' / 'main' / 'review'

def _backfill_dir(directory: Path, spec_key: str, catalog: list[dict], dry_run: bool, verbose: bool) -> tuple[int, int]:
    matched, unmatched = (0, 0)
    for path in sorted(directory.glob('*.yaml')):
        with open(path, encoding='utf-8') as f:
            record = yaml.safe_load(f)
        if not record:
            continue
        node = record if spec_key == 'target' else record.get('enriched_spec', {})
        if not node or 'spec_analysis' in node:
            continue
        target = node.get('target') or {}
        profile, reason = spec_lookup.find_profile(target, catalog)
        if profile is None:
            unmatched += 1
            print(f'  [NO MATCH] {path.name}: {reason}')
            continue
        matched += 1
        if verbose:
            print(f'  [OK] {path.name}: {reason}')
        if dry_run:
            continue
        node['spec_analysis'] = spec_lookup.build_spec_analysis(profile)
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(record, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)
    return (matched, unmatched)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profiles', type=Path, default=AUTHORIZATION_PROFILES, help=f'authorization-profiles JSON catalog (default: {AUTHORIZATION_PROFILES})')
    parser.add_argument('--dry-run', action='store_true', help='report matches, write nothing')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    catalog = spec_lookup.load_catalog(args.profiles)
    print(f'Loaded {len(catalog)} catalog entries from {args.profiles}\n')
    print('scenarios/:')
    s_matched, s_unmatched = _backfill_dir(SCENARIOS_DIR, 'target', catalog, args.dry_run, args.verbose)
    print(f'  {s_matched} matched, {s_unmatched} unmatched\n')
    print('review/:')
    r_matched, r_unmatched = _backfill_dir(REVIEW_DIR, 'enriched_spec', catalog, args.dry_run, args.verbose)
    print(f'  {r_matched} matched, {r_unmatched} unmatched\n')
    if args.dry_run:
        print('Dry run — no files written.')
    else:
        print('Done. spec_analysis added where a catalog match was found.')
if __name__ == '__main__':
    main()
