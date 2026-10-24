"""Decode only the two explicit frozen-response identity spellings.

No reference, configuration content, checksum or state is translated. Mixed
spellings are ambiguous even if their values happen to agree.
"""
import copy
from .core import require

IDENTITY = {'source_id': 'sourceId', 'onboarding_version_id': 'onboardingVersionId',
            'configuration_hash': 'configurationHash'}


def normalize(value):
    require(type(value) is dict, 'SAME_FROZEN_CONFIGURATION_REQUIRED')
    snake = set(IDENTITY); camel = set(IDENTITY.values())
    require(not (snake & set(value) and camel & set(value)), 'AMBIGUOUS_FROZEN_RESPONSE_IDENTITY_FORMAT')
    if camel <= set(value): return copy.deepcopy(value)
    require(snake <= set(value), 'SAME_FROZEN_CONFIGURATION_REQUIRED')
    result = copy.deepcopy(value)
    for source, target in IDENTITY.items(): result[target] = result.pop(source)
    return result


def schema(value):
    normalize(value)
    return 'snake_case' if 'source_id' in value else 'camelCase'
