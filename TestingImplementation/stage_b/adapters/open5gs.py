from __future__ import annotations
import subprocess
from datetime import datetime, timezone
from .base import CoreAdapter, MongoEvidenceMixin
_DISCOVERY_TIMEOUT = 5.0
_DISCOVERY_REQUESTER_TYPE = 'AMF'

def _httpx_client():
    import httpx
    return httpx.Client(http2=True, http1=False, timeout=_DISCOVERY_TIMEOUT)

class Open5GSAdapter(MongoEvidenceMixin, CoreAdapter):

    def check_health(self, cfg: dict) -> dict:
        containers = {svc['container'] for svc in cfg['services'].values() if 'container' in svc}
        details: dict[str, str] = {}
        for name in containers:
            try:
                r = subprocess.run(['docker', 'inspect', '--format', '{{.State.Status}}', name], capture_output=True, text=True, timeout=5)
                details[name] = r.stdout.strip() or 'unknown'
            except Exception as e:
                details[name] = f'error: {e}'
        healthy = all((s == 'running' for s in details.values()))
        return {'healthy': healthy, 'details': details}

    def lifecycle(self, action: str, target: str) -> bool:
        if action not in ('restart', 'stop', 'start'):
            return False
        try:
            r = subprocess.run(['docker', action, target], capture_output=True, timeout=30)
            return r.returncode == 0
        except Exception:
            return False

    def check_data_plane_alive(self) -> bool:
        try:
            r = subprocess.run(['docker', 'exec', 'ue', 'ip', 'addr', 'show', 'uesimtun0'], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def resolve_identity(self, cfg: dict, nf_type: str, fixture_role: str) -> str | None:
        if fixture_role not in cfg['services']:
            return None
        nrf = cfg['services'].get('nrf')
        if not nrf:
            return None
        try:
            with _httpx_client() as client:
                r = client.get(f'http://{nrf['host']}:{nrf['port']}/nnrf-disc/v1/nf-instances', params={'target-nf-type': nf_type.upper(), 'requester-nf-type': _DISCOVERY_REQUESTER_TYPE})
                if r.status_code != 200:
                    return None
                instances = r.json().get('nfInstances', [])
                return instances[0]['nfInstanceId'] if instances else None
        except Exception:
            return None

    def discover_service_base_path(self, cfg: dict, scope: str, producer_nf_type: str, fixture_role: str) -> str | None:
        nrf = cfg['services'].get('nrf')
        if not nrf:
            return None
        try:
            with _httpx_client() as client:
                r = client.get(f'http://{nrf['host']}:{nrf['port']}/nnrf-disc/v1/nf-instances', params={'target-nf-type': producer_nf_type.upper(), 'requester-nf-type': _DISCOVERY_REQUESTER_TYPE})
                if r.status_code != 200:
                    return None
                instances = r.json().get('nfInstances', [])
        except Exception:
            return None
        for inst in instances:
            for svc in inst.get('nfServices', []):
                if svc.get('serviceName') == scope:
                    versions = svc.get('versions') or []
                    if versions and versions[0].get('apiVersionInUri'):
                        return f'{scope}/{versions[0]['apiVersionInUri']}'
        return None

    def get_structured_doc(self, collection: str, key_field: str, key_value: str) -> dict | None:
        return self.mongo_get_structured_doc(self._cfg, collection, key_field, key_value)

    def read_db_state(self, identifier: str) -> list:
        return self.mongo_read_db_state(self._cfg, identifier)

    def list_db_collections(self) -> list[str]:
        return self.mongo_list_collections(self._cfg)

    def provision_subscriber(self, cfg: dict) -> dict:
        supi = cfg['fixture']['supi']
        imsi = supi.removeprefix('imsi-')
        plmn = cfg['fixture']['plmn']
        slice_ = cfg['fixture']['slice']
        dnn = cfg['fixture']['dnn']
        result: dict = {'ok': False, 'amf1_instance_id': None, 'error': None}
        try:
            db = self._open_mongo(cfg)
            ambr = {'downlink': {'value': 1, 'unit': 3}, 'uplink': {'value': 1, 'unit': 3}}
            doc = {'imsi': imsi, 'subscribed_rau_tau_timer': 12, 'network_access_mode': 0, 'subscriber_status': 0, 'operator_determined_barring': 0, 'access_restriction_data': 32, 'security': {'k': '8baf473f2f8fd09487cccbd7097c6862', 'op': None, 'opc': '8e27b6af0e692e750f32667a3b14605d', 'amf': '8000'}, 'ambr': ambr, 'slice': [{'sst': slice_['sst'], 'sd': slice_.get('sd'), 'default_indicator': True, 'session': [{'name': dnn, 'type': 3, 'qos': {'index': 9, 'arp': {'priority_level': 8, 'pre_emption_capability': 1, 'pre_emption_vulnerability': 1}}, 'ambr': ambr, 'pcc_rule': []}]}]}
            db['subscribers'].update_one({'imsi': imsi}, {'$set': doc}, upsert=True)
            _ = plmn
            result['amf1_instance_id'] = self.resolve_identity(cfg, 'AMF', 'amf_1')
            result['ok'] = True
        except Exception as e:
            result['error'] = f'Provisioning error: {e}'
        return result

    def restore_uecm_binding(self, cfg: dict, amf1_id: str) -> bool:
        return False

    def restore_amf_non3gpp_binding(self, cfg: dict, amf1_id: str) -> bool:
        return False

    def restore_smf_registration(self, cfg: dict, owner_id: str) -> bool:
        return False

    def _resolve_container_name(self, target: str) -> str:
        services = self._cfg.get('services') or {}
        for role, svc in services.items():
            nf_type = role.split('_')[0]
            if nf_type == target.lower() and svc.get('container'):
                return svc['container']
        return target

    def read_logs(self, target: str, tail: int | None=None) -> str:
        cmd = ['docker', 'logs', self._resolve_container_name(target)]
        if tail is not None:
            cmd += ['--tail', str(tail)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.stdout + r.stderr
        except Exception as e:
            return f'<log error: {e}>'

    def __init__(self, cfg: dict | None=None):
        self._cfg = cfg or {}
