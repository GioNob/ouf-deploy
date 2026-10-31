"""Exact pure overlay verifiers reused from source_revision_update/configuration.py."""
import hashlib,json,re
from pathlib import Path
from tools.managed_csv_recovery.retained_inputs import require

def owner_json_overlay(raw):
    """Closed JSON owner/OAuth configuration; no Spring loading/migration channels."""
    def unique(rows):
        value={}
        for key,item in rows:
            require(key not in value,'DUPLICATE_OWNER_OVERLAY_KEY');value[key]=item
        return value
    try:
        value=json.loads(raw,object_pairs_hook=unique,
            parse_constant=lambda _:require(False,'NONFINITE_OWNER_OVERLAY'))
    except (ValueError,TypeError,RecursionError):require(False,'STRICT_OWNER_JSON_REQUIRED')
    require(type(value)is dict and bool(value),'OWNER_JSON_OBJECT_REQUIRED')
    found=set();nodes=0;session={}
    session_fields={'server.servlet.session.cookie.httponly':bool,'server.servlet.session.cookie.secure':bool,
        'server.servlet.session.cookie.samesite':str,'server.servlet.session.timeout':str}
    def visit(obj,prefix=(),depth=0):
        nonlocal nodes
        require(type(obj)is dict and bool(obj) and depth<=16,'BOUNDED_OWNER_JSON_OBJECT')
        for key,item in obj.items():
            nodes+=1;require(nodes<=512 and type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',key),'OWNER_JSON_KEY_SCHEMA')
            parts=prefix+tuple(key.split('.'))
            require(all(parts),'OWNER_JSON_EMPTY_SEGMENT')
            canonical=tuple(re.sub('[^a-z0-9]','',part.lower()) for part in parts)
            require(all(canonical),'OWNER_JSON_EMPTY_CANONICAL_SEGMENT')
            if type(item)is dict:visit(item,parts,depth+1);continue
            name='.'.join(canonical)
            require(not any(name==old or name.startswith(old+'.') or old.startswith(name+'.') for old in found),'AMBIGUOUS_OWNER_JSON_PROPERTY');found.add(name)
            owner=canonical[:1]==('ouf',) and not ''.join(canonical).startswith('oufonbdb')
            oauth=canonical[:5]==('spring','security','oauth2','client','registration') or canonical[:5]==('spring','security','oauth2','client','provider')
            require(owner or oauth or name in session_fields,'UNREVIEWED_OWNER_JSON_NAMESPACE')
            if name in session_fields:
                require(type(item)is session_fields[name],'SESSION_PROPERTY_TYPE_CHANGED')
                session[name]=item
            if oauth:
                require(len(parts)==7 and (parts[5]=='ouf-ths' if canonical[4]=='registration' else re.fullmatch('[A-Za-z0-9_-]{1,128}',parts[5])),'EXACT_THS_OAUTH_MAP_KEY_REQUIRED')
                fields={'clientid','clientsecret','clientauthenticationmethod','authorizationgranttype','redirecturi','scope','provider'} if canonical[4]=='registration' else {'issueruri','authorizationuri','tokenuri','userinfouri','usernameattribute','jwkseturi'}
                require(canonical[-1] in fields,'UNREVIEWED_THS_OAUTH_PROPERTY')
            require(type(item) in (str,bool,int,list),'OWNER_JSON_SCALAR_TYPE')
            values=item if type(item)is list else [item]
            require(len(values)<=256 and all(type(v)in(str,bool,int) for v in values),'OWNER_JSON_SCALAR_LIST')
            if oauth:
                require(type(item)is str or canonical[-1]=='scope' and type(item)is list and all(type(v)is str for v in item),'THS_OAUTH_PROPERTY_TYPE')
            for v in values:
                require(type(v)is not str or len(v)<=65536 and not any(c in v for c in ('${','#{','\x00')),'LITERAL_OWNER_JSON_VALUES_REQUIRED')
    visit(value)
    if session:
        require(set(session)==set(session_fields),'COMPLETE_RETAINED_SESSION_PROPERTIES_REQUIRED')
        require(session['server.servlet.session.cookie.httponly'] is True and session['server.servlet.session.cookie.secure'] is True,'SECURE_HTTPONLY_SESSION_REQUIRED')
        require(session['server.servlet.session.cookie.samesite'].lower() in ('strict','lax','none'),'EXPLICIT_SESSION_SAMESITE_REQUIRED')
        timeout=session['server.servlet.session.timeout']
        simple=re.fullmatch(r'[1-9][0-9]{0,8}(?i:ns|us|ms|s|m|h|d)?',timeout)
        iso=re.fullmatch(r'P(?:[0-9]{1,8}D)?(?:T(?:[0-9]{1,8}H)?(?:[0-9]{1,8}M)?(?:[0-9]{1,8}(?:\.[0-9]{1,9})?S)?)?',timeout)
        require(simple or iso and not timeout.endswith('T') and any(c in '123456789' for c in timeout),'FINITE_POSITIVE_SESSION_TIMEOUT_REQUIRED')
    return {'format':'STRICT_JSON','ownerThsOAuthAndSessionOnly':True,'retainedSessionSecurityValidated':bool(session),'migrationOverridePresent':False,
            'propertyCount':len(found),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'configurationValuesPrinted':False}

def additional_location(value):
    require(type(value) is str and 0 < len(value) <= 4096, 'EXACT_ADDITIONAL_LOCATION_REQUIRED')
    if value.startswith('optional:'):
        value = value[len('optional:'):]
    require(value.startswith('file:'), 'ONLY_RETAINED_FILE_OVERLAY_SUPPORTED')
    path = value[len('file:'):]
    require(path.startswith('/') and str(Path(path)) == path and '..' not in Path(path).parts
            and re.fullmatch(r'/[A-Za-z0-9_./-]+\.(?:yml|yaml)',path), 'EXACT_SINGLE_OWNER_OVERLAY_REQUIRED')
    return path

