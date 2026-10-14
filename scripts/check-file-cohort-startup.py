#!/usr/bin/env python3
"""Boot exact Registry candidate with four disposable mounts and real PostgreSQL.
This does not qualify target TLS, token admission, installation custody or frame authority.
"""
import argparse, hashlib, http.server, json, os, secrets, subprocess, tempfile, threading, time, urllib.request
from pathlib import Path

def run(*args, timeout=30):
    return subprocess.check_output(args, timeout=timeout, stderr=subprocess.PIPE).decode().strip()

def main():
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    record=json.loads((a.package/'package-record.json').read_text())
    tag=record['imageTag'];suffix=secrets.token_hex(6);pg='ouf-pg-'+suffix;app='ouf-sem-'+suffix
    issuer='http://127.0.0.1:19091/issuer'
    class Discovery(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.endswith('/jwks'):
                response={'keys':[]}
            elif '/.well-known/' in self.path:
                response={'issuer':issuer,'jwks_uri':issuer+'/jwks','authorization_endpoint':issuer+'/authorize',
                          'token_endpoint':issuer+'/token','response_types_supported':['code'],
                          'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256']}
            else:self.send_error(404);return
            raw=json.dumps(response).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',19091),Discovery)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='ouf-file-cohort-') as rootname:
            root=Path(rootname);root.chmod(0o755)
            policy=root/'policy';policy.mkdir(mode=0o755);(policy/'token').write_text('DISPOSABLE_NOT_ADMITTED')
            config=root/'database';config.mkdir(mode=0o755);(config/'spring.datasource.password').write_text('disposable-password')
            delegation=root/'delegation';delegation.write_text('a'*64);delegation.chmod(0o444)
            receipt=root/'proposal';receipt.write_text('b'*64)
            run('sudo','chown','0:10001',str(receipt));run('sudo','chmod','0440',str(receipt))
            mounts=[(policy,'/run/ouf/policy'),(delegation,'/run/ouf/delegation.key'),(config,'/run/ouf/database'),(receipt,'/run/ouf/proposal.key')]
            run('docker','run','-d','--name',pg,'-p','127.0.0.1:55433:5432','-e','POSTGRES_DB=ouf_semantic','-e','POSTGRES_USER=ouf_semantic','-e','POSTGRES_PASSWORD=disposable-password','postgres:17-alpine',timeout=120)
            for _ in range(60):
                if subprocess.run(['docker','exec',pg,'pg_isready','-U','ouf_semantic'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                time.sleep(1)
            else:raise RuntimeError('DISPOSABLE_POSTGRES_STARTUP_TIMEOUT')
            args=['docker','run','-d','--name',app,'--network','host','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--pids-limit','256']
            for source,target in mounts:args+=['--mount',f'type=bind,src={source},dst={target},readonly']
            environment={
                'SPRING_PROFILES_ACTIVE':'file-first','OUF_SCHEMA_GOV_ENABLED':'false','OUF_DISCOVERY_WORKER_ENABLED':'false',
                'SPRING_CONFIG_IMPORT':'configtree:/run/ouf/database/','OUF_SEM_DB_URL':'jdbc:postgresql://127.0.0.1:55433/ouf_semantic',
                'OUF_SEM_DB_USER':'ouf_semantic','PORT':'18081','OUF_IAM_ENABLED':'true','OUF_IAM_ISSUER':issuer,'OUF_IAM_AUDIENCE':'ouf-disposable',
                'OUF_SEMANTIC_DELEGATION_KEY_FILE':'/run/ouf/delegation.key','OUF_SEMANTIC_DELEGATION_WORKLOAD':'ouf-mcp-disposable',
                'OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY_FILE':'/run/ouf/proposal.key','OUF_SEMANTIC_PROPOSAL_RECEIPT_ISSUER':issuer,
                'OUF_SEMANTIC_PROPOSAL_RECEIPT_AUDIENCE':'ouf-disposable','OUF_SEMANTIC_PROPOSAL_RECEIPT_WORKLOAD':'ouf-mcp-disposable'}
            for k,v in environment.items():args+=['-e',k+'='+v]
            args.append(tag);run(*args)
            for _ in range(150):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:18081/actuator/health',timeout=2) as response:
                        if json.load(response).get('status')=='UP':break
                except Exception:pass
                if run('docker','inspect','--format','{{.State.Running}}',app)!='true':raise RuntimeError('REGISTRY_EXITED_BEFORE_READY')
                time.sleep(1)
            else:raise RuntimeError('REGISTRY_STARTUP_TIMEOUT')
            observed=json.loads(run('docker','inspect',app))[0]
            assert observed['Image']==record['imageId'] and observed['Config']['User']=='10001:10001'
            assert len(observed['Mounts'])==4 and all(not m['RW'] for m in observed['Mounts'])
            versions=run('docker','exec',pg,'psql','-U','ouf_semantic','-Atc','SELECT version FROM ouf_sem.flyway_schema_history WHERE success AND version IS NOT NULL ORDER BY installed_rank').splitlines()
            assert versions==[str(n) for n in range(1,11)], 'EXACT_V1_V10_MIGRATIONS_REQUIRED'
            result={'schema':'ouf.file-first-disposable-startup.v1','status':'DISPOSABLE_BOOT_PASSED','imageId':record['imageId'],
                    'sourceCommit':record['sourceCommit'],'mountCount':4,'runtimeUser':observed['Config']['User'],
                    'providerEnabled':False,'discoveryWorkerEnabled':False,'schemaVersions':versions,
                    'iamEnabled':True,'fixtureIssuerTransport':'LOOPBACK_HTTP','targetIamJavaTlsTrustProven':False,
                    'policyTokenAdmissionProven':False,'targetFourMountExecutionQualified':False,
                    'notReleaseAcceptance':True,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False}
            (a.package/'file-first-four-mount-boot.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
            print('OUF_FILE_FIRST_DISPOSABLE_BOOT=PASS')
    except Exception:
        logs=subprocess.run(['docker','logs','--tail','100',app],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10).stdout
        # Only disposable configuration exists in this test; retain bounded failure output in CI artifact.
        (a.package/'disposable-startup-diagnostics.txt').write_bytes(logs[-32768:])
        raise
    finally:
        for name in [app,pg]:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        server.shutdown();server.server_close()

if __name__=='__main__':main()
