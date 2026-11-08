from __future__ import annotations
import subprocess
from datetime import datetime, timezone
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from .base import CoreAdapter, MongoEvidenceMixin

class Free5GCAdapter(MongoEvidenceMixin, CoreAdapter):

    def check_health(self, cfg: dict) -> dict:
        required = [svc['container'] for svc in cfg['services'].values() if 'container' in svc]
        details: dict[str, str] = {}
        for name in required:
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

    def _open_db(self, cfg: dict):
        m = cfg['services']['mongodb']
        client = MongoClient(f'mongodb://{m['host']}:{m['port']}', serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
        return client[m['database']]

    def _get_amf_instance_id(self, cfg: dict, amf_id_hex: str) -> str | None:
        try:
            db = self._open_db(cfg)
            profile = db['NfProfile'].find_one({'nfType': 'AMF', 'amfInfo.guamiList.amfId': amf_id_hex}, {'nfInstanceId': 1})
            if profile:
                return profile['nfInstanceId']
            if amf_id_hex == cfg['services']['amf_1']['amf_id']:
                other = cfg['services']['amf_2']['amf_id']
                profile = db['NfProfile'].find_one({'nfType': 'AMF', 'amfInfo.guamiList.amfId': {'$ne': other}}, {'nfInstanceId': 1})
                return profile['nfInstanceId'] if profile else None
        except (ConnectionFailure, ServerSelectionTimeoutError):
            pass
        except Exception:
            pass
        return None

    def _nf_profile_query(self, cfg: dict, nf_type: str, fixture_role: str) -> dict | None:
        try:
            if nf_type.upper() == 'AMF':
                return {'nfType': 'AMF', 'amfInfo.guamiList.amfId': cfg['services'][fixture_role]['amf_id']}
            container = cfg['services'][fixture_role]['container']
        except KeyError:
            return None
        return {'nfType': nf_type.upper(), 'ipv4Addresses': f'{container}.free5gc.org'}

    def resolve_identity(self, cfg: dict, nf_type: str, fixture_role: str) -> str | None:
        query = self._nf_profile_query(cfg, nf_type, fixture_role)
        if query is None:
            return None
        try:
            db = self._open_db(cfg)
            profile = db['NfProfile'].find_one(query, {'nfInstanceId': 1})
            return profile['nfInstanceId'] if profile else None
        except (ConnectionFailure, ServerSelectionTimeoutError):
            return None
        except Exception:
            return None

    def discover_service_base_path(self, cfg: dict, scope: str, producer_nf_type: str, fixture_role: str) -> str | None:
        query = self._nf_profile_query(cfg, producer_nf_type, fixture_role)
        if query is None:
            return None
        try:
            db = self._open_db(cfg)
            profile = db['NfProfile'].find_one(query, {'nfServices': 1})
        except Exception:
            return None
        if not profile:
            return None
        for svc in profile.get('nfServices', []):
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
        amf1_hex = cfg['services']['amf_1']['amf_id']
        plmn = cfg['fixture']['plmn']
        result: dict = {'ok': False, 'amf1_instance_id': None, 'error': None}
        try:
            db = self._open_db(cfg)
            amf1_id = self._get_amf_instance_id(cfg, amf1_hex)
            if not amf1_id:
                result['error'] = 'AMF-1 not found in MongoDB — is the lab up?'
                return result
            db['subscriptionData.authenticationData.authenticationSubscription'].delete_many({'ueId': supi})
            db['subscriptionData.authenticationData.authenticationSubscription'].insert_one({'ueId': supi, 'authenticationMethod': '5G_AKA', 'encPermanentKey': '8baf473f2f8fd09487cccbd7097c6862', 'protectionParameterId': '8baf473f2f8fd09487cccbd7097c6862', 'sequenceNumber': {'sqnScheme': 'NON_TIME_BASED', 'lastIndexes': {'ausf': 0}, 'indLength': 5, 'difSign': 'POSITIVE', 'sqn': '000000000000', 'ausf': {'sqn': 0, 'ind': 0}}, 'authenticationManagementField': '8000', 'encOpcKey': '8e27b6af0e692e750f32667a3b14605d', 'vectorGenerationInHss': False, 'rgAuthenticationInd': False, 'supi': supi})
            db['subscriptionData.contextData.amf3gppAccess'].update_one({'ueId': supi}, {'$set': {'amfInstanceId': amf1_id, 'guami.amfId': amf1_hex, 'guami.plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}, 'purgeFlag': False, 'registrationTime': datetime.now(timezone.utc).isoformat()}, '$setOnInsert': {'ueId': supi, 'supportedFeatures': '1', 'ratType': 'NR', 'imsVoPs': 'HOMOGENEOUS_NON_SUPPORT', 'deregCallbackUri': f'http://amf:8000/namf-comm/v1/ue-contexts/{supi}/deregistration', 'amfServiceNameDereg': 'namf-comm', 'pei': None, 'contextInfo': None}}, upsert=True)
            result.update({'ok': True, 'amf1_instance_id': amf1_id})
            if cfg.get('capabilities', {}).get('oauth2', True):
                try:
                    import resolvers
                    import sbi_client
                    tls = resolvers.tls_kwargs(cfg)
                    scheme = 'https' if cfg.get('capabilities', {}).get('mtls_required') else 'http'
                    nrf_svc = cfg['services']['nrf']
                    nrf_url = f'{scheme}://{nrf_svc['host']}:{nrf_svc['port']}'
                    token, _err = sbi_client.get_token(nrf_url=nrf_url, nf_instance_id=amf1_id, nf_type='AMF', target_nf_type='UDM', scope='nudm-uecm', **tls)
                    if token:
                        udm_svc = cfg['services']['udm_1']
                        udm_url = f'{scheme}://{udm_svc['host']}:{udm_svc['port']}/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access'
                        sbi_client.sbi_request('PUT', udm_url, token=token, json_body={'amfInstanceId': amf1_id, 'deregCallbackUri': f'http://amf:8000/namf-comm/v1/ue-contexts/{supi}/deregistration', 'guami': {'plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}, 'amfId': amf1_hex}, 'ratType': 'NR'}, **tls)
                        try:
                            non3gpp_url = f'{scheme}://{udm_svc['host']}:{udm_svc['port']}/nudm-uecm/v1/{supi}/registrations/amf-non-3gpp-access'
                            sbi_client.sbi_request('PUT', non3gpp_url, token=token, json_body={'amfInstanceId': amf1_id, 'imsVoPs': 'HOMOGENEOUS_NON_SUPPORT', 'deregCallbackUri': f'http://amf:8000/namf-comm/v1/ue-contexts/{supi}/deregistration', 'guami': {'plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}, 'amfId': amf1_hex}, 'ratType': 'WLAN'}, **tls)
                        except Exception:
                            pass
                except Exception:
                    pass
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            result['error'] = f'MongoDB unreachable: {e}'
        except Exception as e:
            result['error'] = f'Provisioning error: {e}'
        return result

    def restore_uecm_binding(self, cfg: dict, amf1_id: str) -> bool:
        supi = cfg['fixture']['supi']
        plmn = cfg['fixture']['plmn']
        amf1_hex = cfg['services']['amf_1']['amf_id']
        try:
            db = self._open_db(cfg)
            db['subscriptionData.contextData.amf3gppAccess'].update_one({'ueId': supi}, {'$set': {'amfInstanceId': amf1_id, 'guami.amfId': amf1_hex, 'guami.plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}, 'purgeFlag': False, 'registrationTime': datetime.now(timezone.utc).isoformat()}}, upsert=True)
            return True
        except Exception:
            return False

    def restore_amf_non3gpp_binding(self, cfg: dict, amf1_id: str) -> bool:
        supi = cfg['fixture']['supi']
        plmn = cfg['fixture']['plmn']
        amf1_hex = cfg['services']['amf_1']['amf_id']
        try:
            db = self._open_db(cfg)
            db['subscriptionData.contextData.amfNon3gppAccess'].update_one({'ueId': supi}, {'$set': {'amfInstanceId': amf1_id, 'guami.amfId': amf1_hex, 'guami.plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}, 'purgeFlag': False}}, upsert=True)
            return True
        except Exception:
            return False

    def restore_smf_registration(self, cfg: dict, owner_id: str) -> bool:
        supi = cfg['fixture']['supi']
        plmn = cfg['fixture']['plmn']
        pdu_sess = cfg['fixture']['pdu_session_id']
        slice_ = cfg['fixture']['slice']
        try:
            db = self._open_db(cfg)
            db['subscriptionData.contextData.smfRegistrations'].update_one({'ueId': supi, 'pduSessionId': pdu_sess}, {'$set': {'ueId': supi, 'pduSessionId': pdu_sess, 'smfInstanceId': owner_id, 'singleNssai': {'sst': slice_['sst'], 'sd': slice_['sd']}, 'plmnId': {'mcc': plmn['mcc'], 'mnc': plmn['mnc']}}}, upsert=True)
            return True
        except Exception:
            return False

    def read_logs(self, target: str, tail: int | None=None) -> str:
        cmd = ['docker', 'logs', target]
        if tail is not None:
            cmd += ['--tail', str(tail)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.stdout + r.stderr
        except Exception as e:
            return f'<log error: {e}>'

    def __init__(self, cfg: dict | None=None):
        self._cfg = cfg or {}
