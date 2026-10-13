"""Secret-response and registration guards; no credential or IAM effects.

Only the dedicated client-secret regeneration endpoint is proposed. A generic
client PUT may alter unrelated configuration. These guards do not authorize a
rotation, establish custody, prove target policy or resolve an ambiguous POST.
"""
import copy
import hmac
import re
import iam_binding_candidate as binding

ROTATION_ATTRIBUTES=frozenset({'client.secret.rotation.enabled','client.secret.expiration.time',
    'client.secret.rotated','client.secret.rotated.creation.time','client.secret.rotated.expiration.time',
    'client.secret.remaining.expiration.time'})
CREATED='client.secret.creation.time'

def secret_value(response):
    binding.require(type(response)is dict and set(response)<={'type','value','temporary'}
        and response.get('type')=='secret' and response.get('temporary',False)is False,
        'EXACT_CLIENT_SECRET_RESPONSE_REQUIRED')
    secret=response.get('value')
    binding.require(type(secret)is str and 32<=len(secret)<=4096 and secret.isascii()
        and not any(c.isspace()or ord(c)<33 or ord(c)>126 for c in secret)
        and '${' not in secret,'DIRECT_BOUNDED_NEW_CLIENT_SECRET_REQUIRED')
    return secret

def stable_registration(value):
    binding.require(type(value)is dict and value.get('enabled')is True
        and value.get('serviceAccountsEnabled')is True and value.get('publicClient')is False
        and value.get('protocol')=='openid-connect' and value.get('clientAuthenticatorType')=='client-secret'
        and type(value.get('id'))is str and re.fullmatch('[0-9a-fA-F-]{36}',value['id'])
        and type(value.get('clientId'))is str and 0<len(value['clientId'])<=128,
        'EXACT_CONFIDENTIAL_SERVICE_REGISTRATION_REQUIRED')
    result=copy.deepcopy(value);result.pop('secret',None)
    attributes=result.get('attributes',{})
    binding.require(type(attributes)is dict and not (set(attributes)&ROTATION_ATTRIBUTES),
        'ROTATION_OR_OVERLAP_POLICY_REQUIRES_SEPARATE_REVIEW')
    if CREATED in attributes:
        timestamp=attributes.pop(CREATED)
        binding.require(type(timestamp)is str and re.fullmatch('[0-9]{1,12}',timestamp),
            'SECRET_CREATION_TIMESTAMP_UNPROVEN')
    result['attributes']=attributes
    return result

def verify_reestablishment(before,after,issued,readback,previous_secret):
    binding.require(stable_registration(before)==stable_registration(after),
        'REGISTRATION_CHANGED_OUTSIDE_SECRET_REESTABLISHMENT')
    new=secret_value(issued);current=secret_value(readback)
    binding.require(type(previous_secret)is str and 0<len(previous_secret)<=4096,
        'PREVIOUS_OWNER_SECRET_COMPARISON_REQUIRED')
    binding.require(hmac.compare_digest(new.encode(),current.encode())
        and not hmac.compare_digest(new.encode(),previous_secret.encode()),
        'NEW_ISSUER_SECRET_AND_READBACK_NOT_PROVEN')
    return new
