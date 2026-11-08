GENERIC = 'generic'
AMF_3GPP_REGISTRATION = 'amf_3gpp_registration'
_SPECIALIZED_OPERATIONS = {('nudm_uecm', '3gppregistration'): AMF_3GPP_REGISTRATION, ('nudm_uecm', 'update3gppregistration'): AMF_3GPP_REGISTRATION, ('nudr_dr', 'amfcontext3gpp'): AMF_3GPP_REGISTRATION, ('nudr_dr', 'createamfcontext3gpp'): AMF_3GPP_REGISTRATION}

def for_operation(service: str | None, operation_id: str | None) -> str:
    key = ((service or '').strip().lower(), (operation_id or '').strip().lower())
    return _SPECIALIZED_OPERATIONS.get(key, GENERIC)

def for_scenario(scenario: dict) -> str:
    resource = scenario.get('resource') or {}
    explicit = resource.get('runtime_strategy')
    if explicit:
        return explicit
    target = scenario.get('target') or {}
    return for_operation(target.get('service'), target.get('operation_id'))
