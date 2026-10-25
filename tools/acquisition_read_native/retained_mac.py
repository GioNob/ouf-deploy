"""Pure exact legacy-MAC transition; never a general Config field exclusion."""
import copy,hashlib,json,re
class MacTransitionDenied(RuntimeError):pass
def require(ok,code):
    if not ok:raise MacTransitionDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def valid(value):return type(value)is str and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value)is not None and value.lower()!='00:00:00:00:00:00'and not(int(value[:2],16)&1)
def detached_config(original):
    config=original['Config'];mac=config.get('MacAddress');networks=original['NetworkSettings']['Networks']
    require('MacAddress'in config and valid(mac)and type(networks)is dict and len(networks)==1,'ONE_PROVEN_LEGACY_CONFIG_AND_ENDPOINT_MAC_REQUIRED')
    endpoint=next(iter(networks.values()));require(valid(endpoint.get('MacAddress'))and endpoint['MacAddress'].lower()==mac.lower(),'EXACT_LEGACY_ENDPOINT_MAC_EQUALITY_REQUIRED')
    result=copy.deepcopy(config);del result['MacAddress'];return result
def verify_detached(original,actual,*,expected_name):
    expected=detached_config(original)
    require(actual['Id']==original['Id']and actual['Image']==original['Image']and actual['Name']==expected_name,'SAME_DETACHED_OLD_MCP_ID_IMAGE_NAME_REQUIRED')
    require(actual['State']['Running']is False and actual['State']['Pid']==0 and actual['State']['StartedAt']==original['State']['StartedAt'],'SAME_STOPPED_OLD_MCP_GENERATION_REQUIRED')
    require(actual['NetworkSettings']['Networks']=={},'DETACHED_OLD_MCP_MUST_HAVE_NO_ENDPOINTS')
    require('MacAddress'not in actual['Config']and encoded(actual['Config'])==encoded(expected),'ONLY_PROVEN_LEGACY_MAC_FIELD_ABSENCE_ALLOWED')
    require(encoded(sorted(actual['Mounts'],key=lambda m:m['Destination']))==encoded(sorted(original['Mounts'],key=lambda m:m['Destination'])),'EXACT_DETACHED_OLD_MCP_MOUNTS_REQUIRED')
    host=copy.deepcopy(original['HostConfig']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    require(encoded(actual['HostConfig'])==encoded(host),'EXACT_REVIEWED_STOPPED_OLD_MCP_HOST_CONFIG_REQUIRED')
    return {'profile':'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1','originalConfigHash':digest(original['Config']),'detachedConfigHash':digest(expected),'originalEndpointSetHash':digest(original['NetworkSettings']['Networks']),'originalHashesRewritten':False}
