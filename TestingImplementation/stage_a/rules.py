import re
KNOWN_NF_TYPES = {'AMF', 'SMF', 'AUSF', 'UDM', 'UDR', 'UDSF', 'PCF', 'AF', 'NRF', 'NEF', 'NSSF', 'NWDAF', 'CHF', 'BSF', 'SEPP', 'SCP', 'LMF', 'GMLC', 'SMSF', 'N3IWF', 'TNGF', 'TWIF', 'NSSAAF', 'TSCTSF', 'DCCF', 'NSACF', 'EASDF'}
LAB_FIXTURE_NF_SUBSTITUTES = {'GMLC': 'AMF', 'SMSF': 'AMF'}
RAW_CONSUMER_NF_ALIASES = {'SMS-SC': 'AMF', 'HSS': 'AMF'}
RESOURCE_TO_RESOLVER = {'SUPI': 'SUPI_DIRECT', 'UE context': 'SUPI_DIRECT', 'SM context': 'LOG_PARSE', 'SM Policy': 'SM_POLICY_DIRECT', 'SMF registration': 'SUPI_DIRECT', 'AMF non-3GPP registration': 'SUPI_DIRECT'}
RESOURCE_PRECONDITIONS = {'SUPI': ['uecm_binding_active'], 'UE context': ['ue_registered', 'active_ue_context'], 'SM context': ['active_pdu_session', 'sm_context_ref_resolved'], 'SM Policy': ['active_pdu_session'], 'SMF registration': ['active_pdu_session'], 'AMF non-3GPP registration': ['uecm_binding_active']}

def get_producer_nf(service: str) -> tuple[str | None, str]:
    match = re.match('^N([A-Za-z]+)', service.strip())
    if not match:
        return (None, f"'{service}' does not follow the 'N<nf-type>_<Service>' naming convention")
    prefix = match.group(1).upper()
    if prefix in KNOWN_NF_TYPES:
        return (prefix, 'derived_from_service_prefix')
    return (None, f"prefix '{prefix}' extracted from '{service}' is not a recognized 3GPP NF type — either a typo in the service name or a new NF type missing from KNOWN_NF_TYPES")

def validate_nf_consumer(nf_consumer: str) -> tuple[str | None, str]:
    value = (nf_consumer or '').strip().upper()
    if not value:
        return (None, "no NF consumer value found for this attack — required to select the owner/attacker fixture pair (see the TS 29.5xx clause for this operation, e.g. 'the NF service consumer (e.g. AMF) ...', or expected_binding.requester_nf_types)")
    if value in KNOWN_NF_TYPES:
        return (value, 'validated against KNOWN_NF_TYPES')
    return (None, f"'{value}' is not a recognized 3GPP NF type — check spelling or add it to KNOWN_NF_TYPES")

def is_known_resource_type(resource_type: str) -> bool:
    return resource_type in RESOURCE_TO_RESOLVER

def get_default_preconditions(resource_type: str) -> list[str]:
    preconditions = ['normal_lab_baseline', 'subscriber_provisioned']
    preconditions.extend(RESOURCE_PRECONDITIONS.get(resource_type, []))
    return preconditions
RESOURCE_IDENTIFIER_TO_TYPE = {'ueid': 'SUPI', 'supi': 'SUPI', 'supiorsuci': 'SUPI', 'gpsi': 'SUPI', 'uecontextid': 'UE context', 'smcontextref': 'SM context', 'smcontextid': 'SM context', 'smpolicyid': 'SM Policy'}

def get_resource_type_from_identifiers(identifiers: list[str], path: str='') -> tuple[str, str]:
    if not identifiers:
        return ('UNKNOWN', 'expected_binding.resource_identifiers is empty — no resource identifier to classify')
    normalized = [i.strip().lower() for i in identifiers]
    if normalized[0] == 'ueid' and 'pdusessionid' in normalized[1:]:
        return ('SMF registration', "derived from resource identifiers ['ueId', ..., 'pduSessionId'] — a distinct bound document from the plain SUPI/amf3gppAccess binding (see this function's docstring)")
    if normalized[0] == 'ueid' and 'amf-non-3gpp-access' in (path or '').lower():
        return ('AMF non-3GPP registration', "derived from resource identifier ['ueId'] on an amf-non-3gpp-access path — a distinct bound document (amfNon3gppAccess) from the plain SUPI/amf3gppAccess binding (see this function's docstring)")
    key = normalized[0]
    resource_type = RESOURCE_IDENTIFIER_TO_TYPE.get(key)
    if resource_type:
        return (resource_type, f"derived from resource identifier '{identifiers[0]}'")
    return ('UNKNOWN', f"resource identifier '{identifiers[0]}' is not in RESOURCE_IDENTIFIER_TO_TYPE — add an entry mapping it to a resource type, and a matching row in RESOURCE_TO_RESOLVER/RESOURCE_PRECONDITIONS if this is a genuinely new resource class")

def classify_coverage(coverage: str) -> tuple[bool | None, str]:
    value = (coverage or '').strip().lower()
    if not value:
        return (None, 'existing_protection.resource_binding.coverage is missing — needs manual investigation')
    if 'condition' in value or 'procedural' in value or 'ambiguous' in value:
        return (None, f"coverage='{coverage}' — conditional/procedural/ambiguous, needs manual investigation")
    if 'explicit' in value:
        return (False, f"coverage='{coverage}' — an explicit resource-instance binding check is specified")
    if 'not_identified' in value or 'operation_level' in value:
        return (True, f"coverage='{coverage}' — no resource-instance binding check identified")
    return (None, f"coverage='{coverage}' is not a recognized value — needs manual investigation")

def detect_vulnerability_expectation(existing_protection: str) -> tuple[bool | None, str]:
    text = existing_protection.strip()
    if text == '?':
        return (None, "'Existing protection' is '?' — needs manual investigation")
    VULN_SIGNALS = ['NO explicit', 'no explicit']
    for signal in VULN_SIGNALS:
        if signal in text:
            return (True, f"Contains '{signal}' → no ownership check identified")
    SECURE_SIGNALS = ['Explicit GUAMI', 'GUAMI match', 'Explicit']
    for signal in SECURE_SIGNALS:
        if signal in text:
            return (False, f"Contains '{signal}' → an ownership check is present")
    return (None, 'Could not be determined automatically — needs manual review')
