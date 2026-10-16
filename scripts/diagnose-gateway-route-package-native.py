#!/usr/bin/env python3
"""Disposable CI-only APISIX Admin API reproduction; never target input/apply.

All route identities, URLs and credentials come from synthetic repository
fixtures. This executable refuses to run outside GitHub Actions.
"""
import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def docker(*args):
    return subprocess.run(['docker',*args],check=True,capture_output=True,text=True,timeout=180).stdout.strip()


def main():
    assert os.environ.get('GITHUB_ACTIONS')=='true', 'Disposable CI only'
    parser=argparse.ArgumentParser();parser.add_argument('--gateway-source',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True);a=parser.parse_args()
    sys.path.insert(0,str(a.gateway_source.resolve()))
    from tests.test_file_loop_coherence import retained_installation
    from tools.materialize_semantic_proposals import add_to_existing
    from tools.materialize_onboarding_review import materialize as review
    from tools.materialize_semantic_human_runtime import materialize as semantic_human
    from tools.materialize_trusted_human_onboarding_runtime import materialize as human
    import yaml
    rt,existing=retained_installation()
    result=review(add_to_existing(existing,rt,'DELEGATION_KEY','SEMANTIC_PROPOSAL_KEY'),rt,'DELEGATION_KEY','AUTHORIZATION_OWNER_KEY')
    result['routes'].extend(semantic_human(rt,'$ENV://OIDC_SECRET')['routes'])
    approvals={'trusted-human-onboarding-approvals-get','trusted-human-onboarding-approvals-post'}
    result['routes'].extend(r for r in human(rt,'$ENV://OIDC_SECRET')['routes'] if r['id'] in approvals)
    rows=[copy.deepcopy(r) for r in result['routes'] if not r['id'].startswith('operational-execute-')]
    for r in rows:r.setdefault('status',1);r.setdefault('priority',0)
    rows.sort(key=lambda r:r['id'])
    net='ouf-admin-reproduction-'+str(os.getpid());etcd=net+'-etcd';apisix=net+'-apisix'
    key='0123456789abcdef0123456789abcdef' # public synthetic CI credential
    report={'schema':'ouf.gateway-admin-native-reproduction.v1','targetAccess':False,'runtimeAuthorityIssued':False,'syntheticFixture':True,'routes':[]}
    docker('network','create',net)
    try:
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);root.chmod(0o755)
            cfg={'apisix':{'node_listen':9080},'deployment':{'role':'traditional','role_traditional':{'config_provider':'etcd'},'admin':{'admin_listen':{'ip':'0.0.0.0','port':9180},'allow_admin':['0.0.0.0/0'],'admin_key':[{'name':'admin','key':key,'role':'admin'}]},'etcd':{'host':['http://'+etcd+':2379']}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY','AUTHORIZATION_OWNER_KEY','UDP_OWNER_KEY','SEMANTIC_READ_KEY','SEMANTIC_PROPOSAL_KEY']}}
            hook=root/'ouf_json_precision.lua'
            hook.write_text("local expected=9007199254740991\nfor _,name in ipairs({'cjson','cjson.safe'}) do\n local json=require(name)\n json.encode_number_precision(16)\n assert(json.decode(json.encode(expected))==expected, 'OUF_JSON_INTEGER_ROUNDTRIP_REQUIRED')\nend\n")
            hook.chmod(0o644)
            # Qualify a narrowly scoped upstream compiler fix: Lua's %s rounds
            # numeric constants while generating the range comparison code.
            image_ref='apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'
            source=docker('run','--rm','--entrypoint','cat',image_ref,'/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua')+'\n'
            anchor='local function addRangeCheck(ctx, op, reference, msg)\n'
            assert source.count(anchor)==1, 'RANGE_COMPILER_SOURCE_DRIFT'
            patched=source.replace(anchor,anchor+"  reference = sformat('%.17g', reference)\n")
            validator=root/'jsonschema.lua';validator.write_text(patched);validator.chmod(0o644)
            report['rangeCompilerOriginalSha256']=hashlib.sha256(source.encode()).hexdigest()
            report['rangeCompilerPatchedSha256']=hashlib.sha256(patched.encode()).hexdigest()
            print(json.dumps({k:v for k,v in report.items() if k.startswith('rangeCompiler')}),flush=True)
            cfg['apisix'].update(extra_lua_path='/usr/local/apisix/conf/?.lua',lua_module_hook='ouf_json_precision')
            config=root/'config.yaml';config.write_text(yaml.safe_dump(cfg));config.chmod(0o644)
            docker('run','-d','--name',etcd,'--network',net,'quay.io/coreos/etcd:v3.5.17','etcd','--listen-client-urls=http://0.0.0.0:2379','--advertise-client-urls=http://'+etcd+':2379')
            env=['-e','OIDC_SECRET=synthetic-ci-only']
            for i,name in enumerate(cfg['nginx_config']['envs'][1:]):env+=['-e',name+'='+str(i+1)*64]
            docker('run','-d','--name',apisix,'--network',net,'-p','127.0.0.1::9180','-p','127.0.0.1::9080',*env,'-v',str(config)+':/usr/local/apisix/conf/config.yaml:ro','-v',str(hook)+':/usr/local/apisix/conf/ouf_json_precision.lua:ro','-v',str(validator)+':/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua:ro',image_ref)
            port=int(docker('port',apisix,'9180/tcp').rsplit(':',1)[1])
            def request(method,path,body=None):
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                try:
                    raw=None if body is None else json.dumps(body).encode()
                    conn.request(method,path,body=raw,headers={'X-API-KEY':key,'Content-Type':'application/json'})
                    resp=conn.getresponse();data=resp.read(8388609);assert len(data)<=8388608
                    return resp.status,json.loads(data)
                finally:conn.close()
            for attempt in range(45):
                try:
                    if request('GET','/apisix/admin/routes')[0]==200:break
                except (OSError,ValueError,http.client.HTTPException):pass
                time.sleep(1)
            else:raise RuntimeError('Disposable APISIX not ready: '+docker('logs','--tail','30',apisix))
            image=json.loads(docker('image','inspect','apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d'))[0]
            report['image']=image['RepoDigests'];report['imageId']=image['Id']
            print(json.dumps({'image':report['image'],'imageId':report['imageId']}),flush=True)
            for route in rows:
                status,body=request('PUT','/apisix/admin/routes/'+route['id'],route)
                observed={'id':route['id'],'status':status,'requestSha256':hashlib.sha256(json.dumps(route,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
                if status not in (200,201):observed['syntheticFixtureError']=str(body)[:1800]
                else:
                    code,read=request('GET','/apisix/admin/routes/'+route['id']);value=read.get('value',read)
                    if isinstance(value,dict) and 'value' in value:value=value['value']
                    value={k:v for k,v in value.items() if k not in ('create_time','update_time')}
                    observed['readbackMatches']=code==200 and value==route
                    if value!=route:
                        def differences(a,b,path=''):
                            if type(a)!=type(b):return [{'path':path,'expectedType':type(a).__name__,'observedType':type(b).__name__,**({'expected':a,'observed':b} if isinstance(a,(int,float)) and isinstance(b,(int,float)) else {})}]
                            if isinstance(a,dict):
                                return [d for k in sorted(set(a)|set(b)) for d in differences(a.get(k),b.get(k),path+'/'+k)]
                            if isinstance(a,list):
                                if len(a)!=len(b):return [{'path':path,'expectedLength':len(a),'observedLength':len(b)}]
                                return [d for i,(x,y) in enumerate(zip(a,b)) for d in differences(x,y,path+'/'+str(i))]
                            return [] if a==b else [{'path':path,'expected':a,'observed':b}]
                        observed['syntheticFixtureDifferences']=differences(route,value)[:20]
                report['routes'].append(observed);print(json.dumps(observed),flush=True)
            assert len(report['routes'])==37 and all(x.get('readbackMatches') is True for x in report['routes']), 'ALL_ROUTE_ROUNDTRIPS_REQUIRED'
            probe={'id':'ci-number-roundtrip','uri':'/ci-number-roundtrip','methods':['POST'],
                'plugins':{'request-validation':{'body_schema':{'type':'object','required':['version'],
                    'properties':{'version':{'type':'integer','minimum':0,'maximum':9007199254740991}}}},
                    'serverless-post-function':{'phase':'access','functions':['return function(conf,ctx) ngx.req.read_body(); ngx.header.content_type="application/json"; ngx.print(ngx.req.get_body_data()); return ngx.exit(200) end']}},
                'upstream':{'type':'roundrobin','nodes':{'127.0.0.1:9':1}},'status':1,'priority':0}
            assert request('PUT','/apisix/admin/routes/ci-number-roundtrip',probe)[0] in (200,201)
            # Exercise request-validation's own decode/re-encode in the data plane.
            vectors=[0,1,9007199254740990,9007199254740991,9007199254740992,-1,True,1.5]
            dataport=int(docker('port',apisix,'9080/tcp').rsplit(':',1)[1])
            for value in vectors:
                expected=type(value)is int and 0<=value<=9007199254740991
                payload={'version':value,'nested':[[],{},True,False,None,{'text':'9007199254740991'}]}
                for attempt in range(30):
                    conn=http.client.HTTPConnection('127.0.0.1',dataport,timeout=5)
                    try:
                        conn.request('POST','/ci-number-roundtrip',body=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
                        resp=conn.getresponse();raw=resp.read(65537);status=resp.status
                    finally:conn.close()
                    if status!=404:break
                    time.sleep(0.2)
                assert status==(200 if expected else 400),(value,status,raw)
                if expected:assert json.loads(raw)==payload,(value,raw)
            report['numericBoundaryVectors']=len(vectors);report['numericPayloadPreserved']=True
            print(json.dumps({'numericBoundaryVectors':len(vectors),'numericPayloadPreserved':True}),flush=True)
            docker('restart',apisix)
            for attempt in range(45):
                try:
                    code,doc=request('GET','/apisix/admin/routes')
                    if code==200:break
                except (OSError,ValueError,http.client.HTTPException):pass
                time.sleep(1)
            else:raise RuntimeError('APISIX restart readiness exhausted')
            restored={v['value']['id']:{k:x for k,x in v['value'].items() if k not in ('create_time','update_time')} for v in doc['list']}
            assert all(restored.get(row['id'])==row for row in rows)
            report['allRoutesExactAfterRestart']=True
            print(json.dumps({'allRoutesExactAfterRestart':True,'routeCount':len(rows)}),flush=True)
            report['complete']=True
            a.report.write_text(json.dumps(report,indent=2)+'\n')
    except Exception:
        for name in (apisix,etcd):
            diag=subprocess.run(['docker','logs','--tail','25',name],capture_output=True,text=True,timeout=30)
            print(name,diag.stdout,diag.stderr,flush=True)
        raise
    finally:
        for name in (apisix,etcd):subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        subprocess.run(['docker','network','rm',net],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)

if __name__=='__main__':main()
