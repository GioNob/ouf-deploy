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
    docker('network','create','--internal',net)
    try:
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);root.chmod(0o755)
            cfg={'apisix':{'node_listen':9080},'deployment':{'role':'traditional','role_traditional':{'config_provider':'etcd'},'admin':{'admin_listen':{'ip':'0.0.0.0','port':9180},'allow_admin':['0.0.0.0/0'],'admin_key':[{'name':'admin','key':key,'role':'admin'}]},'etcd':{'host':['http://'+etcd+':2379']}},'nginx_config':{'envs':['OIDC_SECRET','DELEGATION_KEY','AUTHORIZATION_OWNER_KEY','UDP_OWNER_KEY','SEMANTIC_READ_KEY','SEMANTIC_PROPOSAL_KEY']}}
            config=root/'config.yaml';config.write_text(yaml.safe_dump(cfg));config.chmod(0o644)
            docker('run','-d','--name',etcd,'--network',net,'quay.io/coreos/etcd:v3.5.17','etcd','--listen-client-urls=http://0.0.0.0:2379','--advertise-client-urls=http://'+etcd+':2379')
            env=['-e','OIDC_SECRET=synthetic-ci-only']
            for i,name in enumerate(cfg['nginx_config']['envs'][1:]):env+=['-e',name+'='+str(i+1)*64]
            docker('run','-d','--name',apisix,'--network',net,'-p','127.0.0.1::9180',*env,'-v',str(config)+':/usr/local/apisix/conf/config.yaml:ro','apache/apisix:3.18.0-debian')
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
            report['image']=json.loads(docker('image','inspect','apache/apisix:3.18.0-debian'))[0]['RepoDigests']
            for route in rows:
                status,body=request('PUT','/apisix/admin/routes/'+route['id'],route)
                observed={'id':route['id'],'status':status,'requestSha256':hashlib.sha256(json.dumps(route,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
                if status not in (200,201):observed['syntheticFixtureError']=str(body)[:1800]
                else:
                    code,read=request('GET','/apisix/admin/routes/'+route['id']);value=read.get('value',read)
                    if isinstance(value,dict) and 'value' in value:value=value['value']
                    value={k:v for k,v in value.items() if k not in ('create_time','update_time')}
                    observed['readbackMatches']=code==200 and value==route
                report['routes'].append(observed);print(json.dumps(observed),flush=True)
            report['complete']=True
            a.report.write_text(json.dumps(report,indent=2)+'\n')
    finally:
        for name in (apisix,etcd):subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        subprocess.run(['docker','network','rm',net],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)

if __name__=='__main__':main()
