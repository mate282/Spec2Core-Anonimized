import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
import yaml
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'stage_b'))
import adapters
CONFIGS_DIR = PROJECT_ROOT / 'configs'
_NON_SERVICE_KEYS = {'nrf', 'mongodb'}

def _nf_type_from_role(role: str) -> str:
    return role.rsplit('_', 1)[0].upper()

def _identities_file_for(config_path: Path) -> Path:
    return config_path.parent / (config_path.stem.replace('lab', 'identities', 1) + '.yaml')

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--force', action='store_true', help='Overwrite the identities file if it already exists')
    parser.add_argument('--config', type=Path, default=CONFIGS_DIR / 'lab.yaml', help='Lab manifest to resolve identities for (default: configs/lab.yaml — free5GC).')
    args = parser.parse_args()
    identities_file = _identities_file_for(args.config)
    if identities_file.exists() and (not args.force):
        print(f'{identities_file} already exists — pass --force to overwrite.')
        sys.exit(1)
    with open(args.config, encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    adapter = adapters.get_adapter(cfg)
    services: dict = {}
    for role, svc in cfg.get('services', {}).items():
        if role in _NON_SERVICE_KEYS:
            continue
        nf_type = _nf_type_from_role(role)
        print(f'Resolving {role} ({nf_type})...', end=' ', flush=True)
        instance_id = adapter.resolve_identity(cfg, nf_type, role)
        if instance_id:
            services[role] = {'nf_instance_id': instance_id, 'nf_type': nf_type}
            print(instance_id)
        else:
            print('NOT FOUND — skipped (adapter.get_identity() will fall back to a live lookup for this role)')
    out = {'resolved_at': datetime.now(timezone.utc).isoformat(), 'services': services}
    with open(identities_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(out, f, sort_keys=False)
    print(f'\nWrote {len(services)} identities to {identities_file}')
if __name__ == '__main__':
    main()
