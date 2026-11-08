import argparse
import sys
from pathlib import Path
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'stage_b'))
import resource_provisioner
CONFIGS_DIR = PROJECT_ROOT / 'configs'

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--force', action='store_true', help='Re-probe/re-create every identifier, ignoring prior results.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Per-row progress.')
    parser.add_argument('--config', type=Path, default=CONFIGS_DIR / 'lab.yaml', help='Lab manifest to provision against (default: configs/lab.yaml).')
    args = parser.parse_args()
    with open(args.config, encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    cfg['_config_path'] = str(args.config)
    try:
        results = resource_provisioner.run(cfg, force=args.force, verbose=args.verbose)
    except RuntimeError as e:
        print(str(e))
        sys.exit(1)
    from collections import Counter
    counts = Counter((r['status'] for r in results.values()))
    print(f'\n{len(results)} identifiers processed -> {resource_provisioner.OUTPUT_FILE}')
    for status, n in counts.most_common():
        print(f'  {status:>28}: {n}')
if __name__ == '__main__':
    main()
