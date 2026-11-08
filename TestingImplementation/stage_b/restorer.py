import time
import operation_strategy

def restore_after_scenario(scenario: dict, cfg: dict, resources: dict, adapter) -> dict:
    resource_type = scenario['resource']['type']
    method = scenario['target']['method']
    if method == 'GET':
        return {'strategy': 'no_restore_needed', 'success': True, 'reason': 'GET — no persistent side effect'}
    if operation_strategy.for_scenario(scenario) == operation_strategy.AMF_3GPP_REGISTRATION and method in ('PUT', 'PATCH'):
        return _restore_supi_write(cfg, resources, adapter)
    if resource_type == 'AMF non-3GPP registration' and method in ('PUT', 'PATCH'):
        return _restore_amf_non3gpp_write(cfg, resources, adapter)
    if resource_type == 'SMF registration' and method in ('PUT', 'PATCH', 'DELETE'):
        return _restore_smf_registration_write(cfg, resources, adapter)
    if resource_type in ('UE context', 'SM context'):
        wait_secs = cfg.get('fixture', {}).get('ue_restart_wait_seconds', 15)
        return _restore_ue_session(adapter, wait_secs=wait_secs)
    return {'strategy': 'unknown', 'success': False, 'error': f"No strategy for resource.type='{resource_type}' method='{method}'"}

def _restore_supi_write(cfg: dict, resources: dict, adapter) -> dict:
    amf1_id = resources.get('amf1_id')
    if not amf1_id:
        return {'strategy': 'mongo_restore', 'success': False, 'error': 'amf1_id not available in resources'}
    ok = adapter.restore_uecm_binding(cfg, amf1_id)
    return {'strategy': 'mongo_restore', 'success': ok}

def _restore_amf_non3gpp_write(cfg: dict, resources: dict, adapter) -> dict:
    amf1_id = resources.get('amf1_id')
    if not amf1_id:
        return {'strategy': 'mongo_restore', 'success': False, 'error': 'amf1_id not available in resources'}
    ok = adapter.restore_amf_non3gpp_binding(cfg, amf1_id)
    return {'strategy': 'mongo_restore', 'success': ok}

def _restore_smf_registration_write(cfg: dict, resources: dict, adapter) -> dict:
    owner_id = resources.get('owner_id')
    if not owner_id:
        return {'strategy': 'mongo_restore', 'success': False, 'error': 'owner_id not available in resources'}
    ok = adapter.restore_smf_registration(cfg, owner_id)
    return {'strategy': 'mongo_restore', 'success': ok}

def _restore_ue_session(adapter, wait_secs: int=15, ue_target: str='ue') -> dict:
    try:
        restarted = adapter.lifecycle('restart', ue_target)
        time.sleep(wait_secs)
        tunnel_alive = adapter.check_data_plane_alive()
        return {'strategy': 'ue_restart', 'success': restarted and tunnel_alive, 'wait_secs': wait_secs, 'tunnel_up': tunnel_alive}
    except Exception as e:
        return {'strategy': 'ue_restart', 'success': False, 'error': str(e)}
