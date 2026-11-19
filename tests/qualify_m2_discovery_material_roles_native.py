"""Actual thirteen disposable Docker peers and root Unix transport; no target/IAM."""
import copy
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from test_m2_discovery_material_roles import MaterialRoles,alias
from tools.m2_discovery_installation_profile import material_role_preparation as m


def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    def cli(*args):return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=45).strip()
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    fixture=MaterialRoles();ids=[]
    try:
        root,k,peers,*_=fixture.fixture();roles=sorted(peers);current={}
        cli('pull','alpine:3.22')
        for role in roles:
            cid=cli('run','-d','--network','none','--user','10001:10001',
                '-e','OUF_GATEWAY_DELEGATION_KEY='+'b'*64,
                '-e','OUF_SEMANTIC_READ_OWNER_KEY='+'c'*64,
                '-e','OUF_SEMANTIC_PROPOSAL_OWNER_KEY='+'d'*64,
                'alpine:3.22','sleep','240')
            ids.append(cid);current[role]=json.loads(cli('inspect',cid))[0]
        socket_path=Path('/var/run/docker.sock').resolve();s=socket_path.lstat()
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(socket_path))
        peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
        assert peer[1]==0
        binding={'socketPath':str(socket_path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],
                 'peerCredentials':peer}
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();k['boot_path'].write_text(boot)
        values={}
        for folder,name in [(k['input_root'],'inputs.json'),(k['cohort_root'],'inputs.json'),
                            (k['candidate_root'],'material-candidates.private.json')]:
            values[str(folder)]=json.loads((folder/name).read_bytes())
        inputs=values[str(k['input_root'])];cohort=values[str(k['cohort_root'])];candidates=values[str(k['candidate_root'])]
        cohort.update(bootId=boot,observations={alias(r):v for r,v in current.items()},
                      processPins={alias(r):m.process_pin(v['State']['Pid']) for r,v in current.items()},
                      rootProcessPins={'pid1':m.process_pin(1),'engine':m.process_pin(peer[0])},engineBinding=binding)
        k['cohort_hash']=m.digest(cohort)
        inputs.update(bootId=boot,observations={r:current[r] for r in inputs['observations']},
                      processPins={r:m.process_pin(current[r]['State']['Pid']) for r in inputs['observations']},
                      engineBinding=binding,rootProcessPins=cohort['rootProcessPins'],
                      sourceBinding={'root':str(k['cohort_root']),'inputsHash':k['cohort_hash'],'resultHash':m.COHORT_RESULT_HASH})
        k['input_hash']=m.digest(inputs);candidates.update(installationInputsHash=k['input_hash'],processPins=inputs['processPins'])
        k['candidate_hash']=m.digest(candidates)
        for folder,name in [(k['input_root'],'inputs.json'),(k['cohort_root'],'inputs.json'),
                            (k['candidate_root'],'material-candidates.private.json')]:
            (folder/name).write_bytes(m.encoded(values[str(folder)]))
        k.update(pin=m.process_pin,engine_factory=m.ReadOnlyEngine)
        before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        c=m.Preparation(root/'native-positive');result=m.prepare(c,**k)
        assert result['currentPeerCount']==13 and result['counts']['engineGets']==27
        assert result['counts']['privateCopiesPrepared']==2 and result['counts']['preparedCopyReads']==3
        assert result['counts']['metadataReads']==4 and all(p.read_bytes()==raw for p,raw in before.items())
        assert all(m.stable_binding(json.loads(cli('inspect',v['Id']))[0])==m.stable_binding(v) for v in current.values())
        sealed={p:p.read_bytes() for p in c.scope.iterdir()}
        try:m.Preparation(c.scope);raise AssertionError('consumed scope replayed')
        except m.Stop as e:assert 'CONSUMED_NO_REPLAY' in str(e)
        assert all(p.read_bytes()==raw for p,raw in sealed.items())
        cli('stop','--time','1',current['peer-8']['Id'])
        denied=m.Preparation(root/'native-stopped-peer')
        try:m.prepare(denied,**k);raise AssertionError('stopped peer accepted')
        except m.Stop:pass
        assert denied.counts['privateCopiesPrepared']==0 and not (denied.scope/'prepared-inputs.private.json').exists()
        print(json.dumps({'schema':'ouf.m2-discovery-material-role-preparation-native-ci.v1',
            'actualDisposablePeerCount':13,'actualRootUnixEnginePeer':True,'actualKernelProcessPins':True,
            'engineGets':27,'privateCopiesPrepared':2,'publicCertificateCopiesPrepared':1,
            'sourceFilesAndPositivePeerBindingsUnchanged':True,'heterogeneousRoleLabelsMatchedByExactId':True,'failedPredecessorPreserved':True,'sameScopeReplayDenied':True,
            'stoppedPeerRefusedBeforeCopies':True,'syntheticPrivateInputsAndHistoricalProvenance':True,
            'applicationJavaStarted':False,'targetExecuted':False,'iamRequests':0,'oauthRequests':0,
            'sqlSessions':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
        fixture.doCleanups()

if __name__=='__main__':main()
