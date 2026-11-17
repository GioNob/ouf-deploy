"""Versioned, pure lease compiler. No installation or generation migration.

Missing generation/providerFlowMatch selects the historical compiler verbatim.
Explicit profiles are (1, CURRENT_TUPLE) and (2, ORIGINAL_TUPLE). The profile
belongs in the kernel JSON, so the existing canonical kernel digest binds it.
All address, scope and limit validation remains owned by the frozen compiler.
"""
from urllib.parse import urlsplit

from . import materialize_southbound_kernel as historical

fields = historical.fields


def profile(configuration):
    if not isinstance(configuration, dict):
        raise ValueError('explicit exact kernel configuration required')
    keys = {'generation', 'providerFlowMatch'} & configuration.keys()
    if not keys:
        return 1, 'CURRENT_TUPLE'
    if keys != {'generation', 'providerFlowMatch'}:
        raise ValueError('paired explicit kernel generation and providerFlowMatch required')
    generation = configuration['generation']
    match = configuration['providerFlowMatch']
    if type(generation) is not int or (generation, match) not in (
            (1, 'CURRENT_TUPLE'), (2, 'ORIGINAL_TUPLE')):
        raise ValueError('unsupported kernel generation/providerFlowMatch profile')
    return generation, match


def materialize(config, *, empty_provider_sets=False):
    generation, match = profile(config)
    legacy = {k: v for k, v in config.items()
              if k not in ('generation', 'providerFlowMatch')}
    plan = historical.materialize(legacy, empty_provider_sets=empty_provider_sets)
    if generation == 1:
        return plan

    rules = plan['nftRules']
    for index, flow in enumerate(legacy['providerFlows']):
        source = historical.ip(flow['source'])
        family = 'ip' if source.version == 4 else 'ip6'
        endpoint = urlsplit(flow['endpoint'])
        port = endpoint.port if endpoint.port is not None else 443
        target = '@provider_' + str(index)
        original = (f'ct original {family} saddr {source} '
                    f'ct original {family} daddr {target} '
                    f'ct original protocol tcp ct original proto-dst {port}')
        replacements = (
            (f'{family} saddr {source} {family} daddr {target} tcp dport {port} '
             'ct state { new, established } counter accept',
             f'ct direction original {original} ct state {{ new, established }} counter accept'),
            (f'{family} saddr {target} {family} daddr {source} tcp sport {port} '
             'ct state established counter accept',
             f'ct direction reply {original} ct state established counter accept'),
        )
        for old, new in replacements:
            # One exact line in each family. Fail closed if the frozen emitter
            # ever drifts; never patch arbitrary fragments or static flows.
            old_line = '  ' + old + '\n'
            if rules.count(old_line) != 2:
                raise ValueError('historical provider rule shape drift')
            rules = rules.replace(old_line, '  ' + new + '\n')
    plan.update(schema='ouf.southbound-kernel-plan.v2', generation=generation,
                providerFlowMatch=match, nftRules=rules)
    plan['requirements'].append('NATIVE_BRIDGE_CONNTRACK_REQUIRED')
    return plan
