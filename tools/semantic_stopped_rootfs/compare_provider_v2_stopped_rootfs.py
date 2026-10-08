"""Observe only the two exact stopped OUF candidates; no launch or signing."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).parent))
from prepare_provider_image_rootfs import Budget,canonical,decode,load_sealer,private,program,require,sha,write_once
from stopped_rootfs_comparison import expected_overlay,stopped_export_view,validated

OFFLINE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-offline-rootfs-s3BU0nDX')
DATA_ROOT=Path('/var/lib/docker')
SNAPSHOT_PARENT=Path('/etc/ouf/deploy-snapshots')
SOCKET='unix:///var/run/docker.sock'
SOURCE_MANIFEST='fb797f12eb838bfdc5eae7cd28617f6d7d17531968d710735df248354496e250'
DOCKER=('/usr/bin/docker','7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40')
MOUNT=('/usr/bin/mount','2f36342bd2fef42343c4fa4a2a396a7f56c7c8f4ddcbd31c43205c62e152e6d4')
UMOUNT=('/usr/bin/umount','3f3046ef1cdc5134eb0b7ac586c6fea3bcea22aa6614830a14e274f3905b6cd5')
ROLES={
 'adapter':{'cid':'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
  'name':'ouf-semantic-provider-v2','archive':'8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207',
  'manifest':'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc',
  'config':'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320',
  'seal':'8a67afc590854316165176c39fbc0d393bb9b38ab6662430d2a36d3313858cf8'},
 'southbound':{'cid':'1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
  'name':'ouf-semantic-southbound-v2','archive':'1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641',
  'manifest':'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366',
  'config':'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04',
  'seal':'ec013e0317560153aece8e08a393442c95aaa13f64e3df274c61987953e546d8'}}


def main():
    require(os.geteuid()==0 and len(sys.argv)==1,'FIXED_ROOT_ENTRYPOINT_REQUIRED')
    os.umask(0o077)
    output=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-rootfs-compare-',dir=SNAPSHOT_PARENT))
    output.chmod(0o700)
    print('OUF_ROOTFS_COMPARISON_SNAPSHOT='+str(output),flush=True)
    config=output/'docker-config';config.mkdir(mode=0o700)
    socket=SOCKET
    def docker(*args,bound=4194304):
        executable=validated(DOCKER)
        with tempfile.TemporaryFile() as stream:
            result=subprocess.run([executable,'--host',socket,'--config',str(config),*args],
                stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.DEVNULL,timeout=30,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            stream.seek(0);raw=stream.read(bound+1)
        require(result.returncode==0 and len(raw)<=bound,'BOUNDED_DOCKER_READ_FAILED')
        program(*DOCKER);return raw
    def selected(role):
        spec=ROLES[role];rows=decode(docker('inspect',spec['cid']))
        require(type(rows) is list and len(rows)==1,'EXACT_CONTAINER_REQUIRED')
        item=rows[0];state=item['State']
        require(item['Id']==spec['cid'] and item['Name']=='/'+spec['name'] and item['Image']==spec['manifest']
            and state['Status']=='created' and state['Pid']==0 and not state['Running']
            and state['StartedAt'].startswith('0001-01-01'),'NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
        return {k:item[k] for k in ('Id','Image','Name','State','Config','HostConfig','Mounts','NetworkSettings')}
    def states():
        ids=docker('ps','-aq','--no-trunc',bound=65536).decode().splitlines()
        require(len(ids)<=256 and len(ids)==len(set(ids)),'CONTAINER_INVENTORY_UNBOUNDED')
        if not ids:return {}
        raw=docker('inspect','--format','{{.Id}} {{json .State}}',*ids,bound=1048576)
        result={}
        for line in raw.splitlines():
            cid,body=line.split(b' ',1);state=decode(body)
            # Health-probe timestamps can advance without a lifecycle change.
            # Observe the complete lifecycle fields, not unrelated probe ticks.
            result[cid.decode()]={key:state[key] for key in ('Status','Running','Paused','Restarting',
                'OOMKilled','Dead','Pid','ExitCode','Error','StartedAt','FinishedAt')}
        require(set(result)==set(ids),'STATE_INVENTORY_UNPROVEN');return result
    info=decode(docker('info','--format','{{json .}}'))
    version=decode(docker('version','--format','{{json .Server}}'))
    require(info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs'
        and info['DockerRootDir']==str(DATA_ROOT) and version['GitCommit']=='464cd50', 'ENGINE_BINDING_DRIFT')
    source=OFFLINE/'source';sealer=load_sealer(source,SOURCE_MANIFEST)
    original_states=states();before={role:selected(role) for role in ROLES};results=[]
    for role,spec in ROLES.items():
        root=OFFLINE/role;raw=private(root/'expected-docker-rootfs.json');receipt=decode(raw)
        require(receipt['schema']=='ouf.semantic-offline-docker-rootfs.v1'
            and receipt['sourceManifestSha256']==SOURCE_MANIFEST and receipt['engineCommit']=='464cd50c3d9e92877d56940ea160de6fca7bea23'
            and receipt['archiveSha256']==spec['archive'] and receipt['manifestDigest']==spec['manifest']
            and receipt['configDigest']==spec['config'] and receipt['rootfsSeal']['sha256']==spec['seal']
            and receipt['offlineDockerInitLayerApplied'] is True and receipt['targetRootfsCompared'] is False,
            'OFFLINE_EXPECTATION_BINDING_DRIFT')
        lower=root/'bundle/rootfs';limits=receipt['rootfsLimits']
        require(sealer(lower,limits,Budget())==receipt['rootfsSeal'],'OFFLINE_EXPECTATION_CHANGED')
        directory=output/role;directory.mkdir(mode=0o700)
        target=DATA_ROOT/'rootfs/overlayfs'/spec['cid']
        with expected_overlay(lower,directory,MOUNT,UMOUNT) as view:
            expected=sealer(view,limits,Budget())
            with stopped_export_view(DOCKER,socket,config,spec['cid'],target) as mounted:
                actual=sealer(mounted,limits,Budget())
                require(actual==expected,'TARGET_ROOTFS_DIFFERS_FROM_INDEPENDENT_EXPECTATION')
        require(sealer(lower,limits,Budget())==receipt['rootfsSeal'],'OFFLINE_EXPECTATION_CHANGED')
        require(sha(canonical(selected(role)))==sha(canonical(before[role])),'STOPPED_CANDIDATE_CONFIGURATION_CHANGED')
        result={'role':role,'containerId':spec['cid'],'offlineReceiptSha256':sha(raw),
            'originalOfflineSeal':receipt['rootfsSeal'],'expectedOverlaySeal':expected,'actualSeal':actual,
            'strictSealsMatch':True,'targetRootfsCompared':True,'neverStarted':True,'exportMountReleased':True,
            'privateMountContentsRead':False,'dockerInitLayerAccepted':False,'acceptanceGranted':False,'startAuthorized':False}
        write_once(output/(role+'-comparison.json'),canonical(result));results.append(result)
    require(states()==original_states,'EXISTING_CONTAINER_STATES_CHANGED')
    load_sealer(source,SOURCE_MANIFEST)
    result={'schema':'ouf.semantic-provider-v2-stopped-rootfs-comparison.v1','roles':results,
        'strictSealsMatch':True,'existingContainerStatesUnchanged':True,'containerLifecycleOperations':0,
        'temporaryExpectedOverlayMounts':len(results),'stoppedContainerExports':len(results),'privateKeysRead':0,'providerCalls':0,
        'signaturesIssued':0,'runtimeConfigurationWrites':0,'firewallWrites':0,'secretValuesPrinted':False,
        'acceptanceGranted':False,'startAuthorized':False,'status':'INDEPENDENT_ROOTFS_COMPARISON_PASS'}
    write_once(output/'comparison.json',canonical(result))
    print('OUF_PROVIDER_V2_ROOTFS_COMPARISON='+canonical(result).decode(),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if isinstance(error,ValueError) else type(error).__name__
        allowed={'TARGET_ROOTFS_DIFFERS_FROM_INDEPENDENT_EXPECTATION','OFFLINE_EXPECTATION_CHANGED',
            'EXPORT_MOUNT_NOT_OBSERVABLE','ROOTFS_ALREADY_MOUNTED','ENGINE_BINDING_DRIFT',
            'NEVER_STARTED_EXACT_CANDIDATE_REQUIRED','EXISTING_CONTAINER_STATES_CHANGED'}
        print('OUF_PROVIDER_V2_ROOTFS_COMPARISON=BLOCKED REASON='+ (reason if reason in allowed else 'BOUNDED_COMPARISON_FAILED')+' NO_RAW_OUTPUT=true',flush=True)
        raise SystemExit(1)
