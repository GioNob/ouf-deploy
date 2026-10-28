"""Resolve only the selected THS registration from the retained owner overlay.

Configuration values may include credentials. Return only client/provider/issuer
metadata; never retain the raw overlay or expose other properties. IAM bindings
and emitted token scopes are distinct evidence gates.
"""
import re
from urllib.parse import urlsplit
from tools.managed_csv_recovery.retained_inputs import require, decode
from tools.managed_profile_ths_scopes.overlay import owner_json_overlay, additional_location
from tools.managed_profile_ths_scopes.contract import scope_patch

REGISTRATION_PREFIX='spring.security.oauth2.client.registration.ouf-ths.'

def oauth_properties(obj):
    result={}
    def walk(value,prefix=()):
        require(type(value)is dict,'OAUTH_PROPERTY_OBJECT_REQUIRED')
        for key,item in value.items():
            require(type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',key),'OAUTH_PROPERTY_KEY_REQUIRED')
            parts=prefix+tuple(key.split('.'))
            require(all(parts),'OAUTH_EMPTY_PROPERTY_SEGMENT')
            canonical=[re.sub('[^a-z0-9]','',s.lower())for s in parts]
            # Registration/provider map keys are case-sensitive literal keys.
            if canonical[:5]in (['spring','security','oauth2','client','registration'],['spring','security','oauth2','client','provider'])and len(parts)>5:canonical[5]=parts[5]
            name='.'.join(canonical)
            if type(item)is dict:walk(item,parts);continue
            require(not any(name==old or name.startswith(old+'.')or old.startswith(name+'.')for old in result),'AMBIGUOUS_OAUTH_PROPERTY')
            result[name]=item
    walk(obj);return result

def selected_overlay(actual,retained):
    # The successful native update already classified the lower-priority loader
    # and pinned this one overlay. This helper neither discovers nor adopts files.
    scope_patch(actual)
    env=dict(row.split('=',1)for row in actual['Config']['Env'])
    require(not env.get('_JAVA_OPTIONS')and not any(a.startswith('@')for a in(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])),'UNREVIEWED_ADDITIONAL_JVM_OVERRIDE')
    require(not any(re.sub('[^a-z0-9]','',k.lower())in ('springconfigimport','springconfiglocation')for k in env),'UNREVIEWED_CONFIG_LOADER_OVERRIDE')
    target=additional_location(env.get('SPRING_CONFIG_ADDITIONAL_LOCATION'))
    require(type(retained)is dict and set(retained)>={'binding','target'}and retained['target']==target,'EXACT_RETAINED_OWNER_OVERLAY_TARGET_REQUIRED')
    mounts=[v for v in actual['Mounts']if v.get('Destination')==target]
    require(len(mounts)==1 and mounts[0].get('Type')=='bind'and mounts[0].get('RW')is False and mounts[0].get('Source')==retained['binding']['path'],'EXACT_SELECTED_READ_ONLY_OWNER_OVERLAY_REQUIRED')
    high=oauth_properties(decode(env['SPRING_APPLICATION_JSON']))
    require(not any(k.startswith(('spring.config.','spring.profiles.','loader.'))for k in high),'UNREVIEWED_JSON_LOADER_OVERRIDE')
    return target,high

def client_metadata(actual,raw,retained):
    target,high=selected_overlay(actual,retained)
    owner_json_overlay(raw)  # Reuse the qualified closed literal JSON verifier.
    low=oauth_properties(decode(raw));effective={**low,**high}
    prefix=REGISTRATION_PREFIX
    def key(s):
        parts=s.split('.');return '.'.join(re.sub('[^a-z0-9]','',p.lower())if i!=5 else p for i,p in enumerate(parts))
    client=effective.get(key(prefix+'client-id'))
    require(type(client)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',client),'LITERAL_EFFECTIVE_THS_CLIENT_ID_REQUIRED')
    provider=effective.get(key(prefix+'provider'),'ouf-ths')
    require(type(provider)is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',provider),'LITERAL_THS_PROVIDER_REQUIRED')
    provider_prefix='spring.security.oauth2.client.provider.'+provider+'.'
    issuer=effective.get(key(provider_prefix+'issuer-uri'))
    require(type(issuer)is str and len(issuer)<=2048,'EXPLICIT_LITERAL_THS_ISSUER_REQUIRED')
    url=urlsplit(issuer)
    require(url.scheme=='https'and bool(url.hostname)and not url.username and not url.password and not url.query and not url.fragment
            and re.fullmatch('/realms/[A-Za-z0-9_.-]{1,128}',url.path)and issuer==url.geturl(),'EXACT_HTTPS_REALM_ISSUER_REQUIRED')
    require(not any(key(provider_prefix+suffix)in effective for suffix in ('authorization-uri','token-uri','userinfo-uri','jwk-set-uri')),'EXPLICIT_PROVIDER_ENDPOINT_OVERRIDE_REQUIRES_REVIEW')
    grant=effective.get(key(prefix+'authorization-grant-type'))
    require(grant in (None,'authorization_code'),'THS_BROWSER_AUTHORIZATION_CODE_REQUIRED')
    return {'registrationId':'ouf-ths','clientId':client,'clientIdOrigin':'SPRING_APPLICATION_JSON'if key(prefix+'client-id')in high else 'RETAINED_MOUNTED_OWNER_OVERLAY',
            'providerId':provider,'providerIdExplicit':key(prefix+'provider')in effective,'issuer':issuer,'realm':url.path.split('/')[-1],
            'authorizationGrantTypeConfigured':grant,'selectedMountTarget':target,'fileSelectionAndPrecedenceVerified':True,
            'rawOverlayPersisted':False,'credentialValuesPrinted':False,'iamBindingObserved':False,'browserTokenInspected':False}
