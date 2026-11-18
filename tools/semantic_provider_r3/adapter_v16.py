"""Compare the public D-053 adapter observation to its independent authorities."""
from tools.semantic_provider_operation.authorization import require
from tools.semantic_provider_routes.routes import Held


INPUT = 'adapter/configProjection'
PROFILE = 'installationProfile'
PROJECTION = 'R3_ADAPTER_PROJECTION_INVALID'
SOURCE = 'R3_ADAPTER_CONFIG_SOURCE_MISMATCH'
PROFILE_PIN = 'R3_ADAPTER_INSTALLATION_PROFILE_MISMATCH'
MISSING = 'R3_ADAPTER_PROVIDER_FLOW_MISSING'
AMBIGUOUS = 'R3_ADAPTER_PROVIDER_FLOW_AMBIGUOUS'
ENDPOINT = 'R3_ADAPTER_PROVIDER_ENDPOINT_MISMATCH'
CIDRS = 'R3_ADAPTER_PROVIDER_CIDRS_MISMATCH'
NAMESPACES = 'R3_ADAPTER_PROVIDER_NAMESPACES_MISMATCH'


def check(data, files, contract):
    projection = data[INPUT]
    require(projection.keys() == {'source', 'sha256', 'bytes', 'provider'}, PROJECTION)
    provider = projection['provider']
    require(type(provider) is dict and provider.keys() == {'endpoint', 'allowed_cidrs', 'namespace_prefixes'},
            PROJECTION)
    launch = contract.source_entry(data['adapter/launch'], require, SOURCE)
    policy = contract.source_entry(data['adapter/policy'], require, SOURCE)
    require(launch == policy and (projection['source'], projection['sha256']) ==
            (launch['source'], launch['sha256']) and type(projection['bytes']) is int
            and 0 < projection['bytes'] <= launch['maxBytes'], SOURCE)

    accepted = data['acceptance']
    require(type(accepted.get('generation')) is int and accepted['generation'] >= 7
            and accepted.get('profile') == {'path': contract.PROFILE_PATH,
                                            'sha256': contract.sha(files[PROFILE])}
            and data[PROFILE].get('installationRef') == accepted.get('installationRef')
            and data[PROFILE].get('entityRef') == accepted.get('entityRef'), PROFILE_PIN)
    try:
        declared = contract.declaration(data[PROFILE])
    except Held:
        require(False, NAMESPACES)

    kernel = data['coordinator']['kernel']
    require(type(kernel.get('generation')) is int and kernel['generation'] == 2, MISSING)
    nics = [nic for nic in data['adapter/historicalTemplate']['candidate']['networkBindings']
            if nic.get('bindingRef') == 'adapter-egress']
    require(nics, MISSING)
    require(len(nics) == 1, AMBIGUOUS)
    # Count all flows for this egress IP before matching the declared reference.
    flows = [flow for flow in kernel['providerFlows'] if flow['source'] == nics[0]['ipv4']]
    require(flows, MISSING)
    require(len(flows) == 1, AMBIGUOUS)
    flow = flows[0]
    require(flow.get('endpointRef') == declared['endpointRef'], MISSING)
    try:
        expected = contract.endpoint(flow['endpoint'])
    except Held:
        require(False, ENDPOINT)
    actual = provider['endpoint']
    require(type(actual) is dict and type(actual.get('port')) is int and actual == expected, ENDPOINT)
    require(provider['allowed_cidrs'] == flow.get('allowedPrivateAddresses') == [], CIDRS)
    require(provider['namespace_prefixes'] == declared['namespacePrefixes'], NAMESPACES)
