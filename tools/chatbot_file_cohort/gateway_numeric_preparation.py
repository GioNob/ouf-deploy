"""Private preparation of qualified APISIX compatibility; no runtime effects.

This is the exact retained installation's closed YAML adapter. Unsupported YAML
requires another qualified adapter; endpoint/topology values are never inferred.
"""
import hashlib
import re
from pathlib import Path
from tools.chatbot_file_cohort.plan import require
from tools.chatbot_file_cohort.gateway import private_config
from tools.chatbot_file_cohort.gateway_preparation import stage_private
from tools.chatbot_file_cohort.gateway_runtime import NUMERIC_ASSETS, NUMERIC_IMAGE_IDS


def numeric_config(raw):
    require(type(raw)is bytes and 0<len(raw)<=1048576,'BOUNDED_APISIX_CONFIG_REQUIRED')
    text=raw.decode('utf-8')
    # Preserve every original byte; accept only a plain block mapping. YAML
    # anchors/merges/tags and quoted/flow keys could hide an extension override.
    require('\t' not in text and '\r' not in text
        and not re.search(r'(?m)^\s*[^#\n]*(?:[&*!]|<<\s*:|[{}])',text)
        and not re.search(r'(?m)^\s*[\'"]',text), 'PLAIN_RETAINED_APISIX_CONFIG_REQUIRED')
    require(len(re.findall(r'(?m)^apisix:\s*$',text))==1
        and not re.search(r'(?m)^\s*(?:lua_module_hook|extra_lua_path)\s*:',text),
        'UNCOMPOSED_APISIX_LUA_EXTENSION_REQUIRED')
    return re.sub(r'(?m)^apisix:[ \t]*$',
        'apisix:\n  extra_lua_path: /usr/local/apisix/conf/?.lua\n  lua_module_hook: ouf_json_precision',text,count=1).encode('utf-8')


def prepare(source_root,output_directory,image,old_config_binding):
    require(image in NUMERIC_IMAGE_IDS,'QUALIFIED_APISIX_NUMERIC_IMAGE_REQUIRED')
    raw,_=private_config(old_config_binding['path'],old_config_binding)
    updated=numeric_config(raw)
    name='apisix-numeric-'+hashlib.sha256(updated).hexdigest()+'.yaml'
    stage_private(output_directory,name,updated,0o444)
    _,config=private_config(Path(output_directory)/name)
    assets=[]
    for destination,expected in sorted(NUMERIC_ASSETS.items()):
        filename=Path(destination).name
        value,_=private_config(Path(source_root)/'tools/chatbot_file_cohort/assets/apisix'/filename)
        require(hashlib.sha256(value).hexdigest()==expected,'QUALIFIED_NUMERIC_SOURCE_HASH_DRIFT')
        target='numeric-'+expected+'-'+filename
        stage_private(output_directory,target,value,0o444)
        _,binding=private_config(Path(output_directory)/target)
        assets.append({'destination':destination,'binding':binding,'readOnly':True})
    return config,assets


def prepare_continuation(previous,engine,source,output_directory,cohort_id):
    from tools.chatbot_file_cohort import gateway_recovery as recovery
    from tools.chatbot_file_cohort.gateway import NamespaceAdmin
    from tools.chatbot_file_cohort.gateway_runtime import compile_runtime,proposed_transport
    from tools.chatbot_file_cohort.gateway_recovery_plan import compile_remaining
    from tools.chatbot_file_cohort.plan import digest,environment
    old=previous['prepared']['gatewayPlan']
    binding=recovery.current_gateway_transport(previous,engine)
    transport=NamespaceAdmin(engine,binding);transport.check()
    first=transport.routes()
    code,actual=engine.request('GET','/v1.44/containers/'+transport.binding['runtimeBinding']['containerId']+'/json')
    require(code==200,'RETAINED_GATEWAY_UNAVAILABLE')
    raw_key,key_binding=private_config(old['proposalKeyBinding']['path'])
    require(key_binding['sha256']==old['proposalKeyBinding']['sha256'],'RETAINED_PROPOSAL_KEY_CHANGED')
    key=raw_key.decode('ascii')
    env=environment(actual['Config'].get('Env')or[])
    selected=[name for name,value in env.items()if value==key]
    require(len(selected)==1,'EXACT_RETAINED_PROPOSAL_KEY_ENV_REQUIRED')
    config,assets=prepare(source,output_directory,actual['Image'],transport.binding['configBinding'])
    runtime=compile_runtime(actual,transport.binding['configBinding'],config,selected[0],key,key_binding['sha256'],cohort_id,
        admin_key_binding=transport.binding.get('adminKeyBinding'),numeric_assets=assets)
    second=transport.routes();transport.check()
    plan=compile_remaining(old,previous['gatewayJournal'],first,second,proposed_transport(runtime),digest(runtime))
    plan['gatewayRuntimePlanHash']=digest(runtime)
    plan['governedReprocessing'].pop('executionIntegrationQualified')
    plan['governedReprocessing']['executionProfile']=recovery.PROFILE
    return plan,runtime
