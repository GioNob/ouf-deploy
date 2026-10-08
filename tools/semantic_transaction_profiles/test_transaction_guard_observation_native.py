"""Isolated actual nft read under borrowed flock; Docker/systemd are fixtures.

No real Docker lifecycle or target acceptance is proved by this test.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'semantic_frame_compiler'),str(HERE.parent/'semantic_cohort_admission/cohort-draft')]
from transaction_guard_observation import observe_locked
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import NftBackend,structure_hash
from assemble_provider_profiles import encoded,digest
from authenticate_provider_transaction import TransactionDenied


def main():
    assert os.geteuid()==0
    assert os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino
    nft=str(Path(shutil.which('nft')).resolve())
    with tempfile.TemporaryDirectory(dir='/root',prefix='ouf-locked-native-') as temp:
        root=Path(temp)
        def write(path,raw,mode=0o600):
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(raw);path.chmod(mode);return digest(raw)
        def doc(path,value):return write(path,encoded(value))
        lock=root/'guard.lock';write(lock,b'')
        kernel={'tableName':'ouf_guard_ci','guardedInterfaces':['ci0'],'existingInterfaces':[],
            'staticFlows':[],'providerFlows':[{'endpointRef':'provider'+str(i),'endpoint':'https://example.org/',
            'source':'198.19.1.'+str(i+2),'addresses':[],'leaseSeconds':30,
            'resolutionEvidenceRef':'ci-authority-only','allowedPrivateAddresses':[]} for i in range(2)]}
        subprocess.run([nft,'-f','-'],input=materialize(kernel,empty_provider_sets=True)['nftRules'].encode(),check=True)
        backend=NftBackend([nft],kernel,'0'*64,5)
        structure=structure_hash(backend.tables())
        commands={'nft':{'path':nft,'sha256':digest(Path(nft).read_bytes())}}
        boot={'kernel':kernel,'lockFile':str(lock),'compilerFile':str(root/'compiler.py'),
              'compilerHash':write(root/'compiler.py',b'# never executed\n'),'journalFile':str(root/'boot-journal.json'),
              'transactionId':'1'*64}
        boot_hash=doc(root/'boot-configuration.json',boot)
        owner={'kernel':kernel,'commonLockFile':str(lock),'nftPath':nft,'nftSha256':commands['nft']['sha256'],
            'expectedStructureHash':structure,'readBudgetSeconds':5,'journalFile':str(root/'owner-journal.json'),
            'binding':{'transactionId':'2'*64,'configurationHash':'3'*64,'leaseStructureHash':structure}}
        owner_hash=doc(root/'coordinated-configuration.json',owner)
        profile={'coordinatedConfigurationHash':owner_hash,'bootConfigurationHash':boot_hash,
            'bootGuardFile':str(root/'boot-guard.py'),'bootGuardHash':write(root/'boot-guard.py',b'# never executed\n')}
        profile_hash=doc(root/'boot-profile.json',profile)
        doc(root/'owner-journal.json',{'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],
            'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[],[]]})
        doc(root/'boot-journal.json',{'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY',
            'transactionId':boot['transactionId'],'configurationHash':boot_hash,'leaseStructureHash':structure,'startAuthorized':False})
        candidates={str(i)*64:{'imageManifestDigest':'sha256:'+str(i+3)*64,'runtimeName':'ci-only'} for i in (1,2)}
        for cid,expected in candidates.items():doc(root/(cid+'.json'),{'id':cid,'image':expected['imageManifestDigest'],
            'runtime':'ci-only','state':{'Status':'created','Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}})
        guard_command='ci-not-target-boot-command'
        docker_raw=('#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nprint((Path('+repr(str(root))+')/(sys.argv[-1]+".json")).read_text())\n').encode()
        system_raw=('#!/usr/bin/python3\nprint('+repr(guard_command)+')\n').encode()
        for name,raw in [('docker',docker_raw),('systemctl',system_raw)]:
            path=root/name;commands[name]={'path':str(path),'sha256':write(path,raw,0o755)}
        units={name:str(root/name) for name in ('guard.service','docker-drop-in.conf')}
        artifacts={name:write(Path(path),b'ci-unit') for name,path in units.items()}
        receipt={'schema':'ouf.semantic-provider-network-guard-installation.v1','state':'INSTALLED','directory':str(root),
            'configurationHash':owner_hash,'bootConfigurationHash':boot_hash,'bootProfileHash':profile_hash,
            'startAuthorized':False,'leaseAuthorized':False,'sourceHashes':{'test.py':write(root/'source/test.py',b'# not executed\n')},
            'transitionSourceHashes':{'test.py':write(root/'migration/test.py',b'# not executed\n')},
            'observerHash':write(root/'transition-source.py',b'# not executed\n'),'artifactHashes':artifacts,'guardCommand':guard_command}
        receipt_binding={'path':str(root/'installation-receipt.json'),'sha256':doc(root/'installation-receipt.json',receipt)}
        fd=os.open(lock,os.O_RDWR);other=os.open(lock,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=observe_locked(fd,receipt_binding,owner_hash,candidates,commands,units)
            assert result['providerSetsEmpty'] and result['lockInodePreserved']
            try:fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:pass
            else:raise AssertionError('borrowed guard lock released')
            subprocess.run([nft,'add','element','inet',kernel['tableName'],'provider_0','{','1.1.1.1','timeout','30s','}'],check=True)
            try:observe_locked(fd,receipt_binding,owner_hash,candidates,commands,units)
            except TransactionDenied as error:assert error.diagnosis['reason']=='PROVIDER_KERNEL_MEMBERSHIP_NOT_EMPTY'
            else:raise AssertionError('nonempty native provider membership accepted')
            print('LOCKED_NATIVE_GUARD=PASS REAL_NFT=true LOCK_REACQUIRED=false DOCKER_SYSTEMD_FIXTURE_ONLY=true TARGET_ACCEPTANCE=false')
        finally:os.close(other);os.close(fd)


if __name__=='__main__':main()
