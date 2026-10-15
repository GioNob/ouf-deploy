"""Compile a four-mount proposal from a fixed independent Engine CI baseline.

No observed replacement OCI is an input. Changes are exactly the signed launch,
four source declarations and finite resource limits; kernel/default Engine fields
remain those of the versioned baseline and must later match native observation.
"""
import copy
import hashlib
import json

from transition_journal import require
from file_only_profile import FileOnlyProfile
from compile_file_only_frame_policy import docker_bridge_environment
from compile_creation_frame_policy import compile_policy as compile_baseline

BASELINE_SHA256='ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63'
ENGINE={'serverVersion':'29.8.1','storageDriver':'overlayfs','cgroupDriver':'systemd','backend':'containerd-overlayfs'}

def compile_inputs(raw,request,tree,token,delegation,proposal,engine_profile):
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==BASELINE_SHA256,
            'PINNED_INDEPENDENT_ENGINE_BASELINE_REQUIRED')
    baseline=json.loads(raw);require(baseline.get('schema')=='ouf.semantic-ci-engine-frame-baseline.v1'
        and baseline.get('engine')==engine_profile==ENGINE and baseline.get('role')=='southbound'
        and baseline.get('mountOrdering')=='depth-path' and baseline.get('syntheticFixture') is True
        and baseline.get('targetTemplateApproved') is False,'EXACT_INDEPENDENT_ENGINE_BASELINE_PROFILE_REQUIRED')
    dummy={'schema':'ouf.semantic-docker-frame-context.v1','containerId':'a'*64,
        'bundleParent':'/run/reviewed/bundles','metadataParent':'/var/lib/reviewed/containers',
        'networkNamespaceParent':'/run/reviewed/netns','networkNamespaceName':None,'cgroupDriver':'systemd',
        'rootfsPath':'/var/lib/reviewed/rootfs','storageParent':'/var/lib/reviewed'}
    compile_baseline(baseline['template'],baseline['launch'],dummy)
    FileOnlyProfile(request,tree);host=request['HostConfig']
    require(host.get('ReadonlyRootfs',False) is False and host.get('CapDrop')==['ALL']
        and 'no-new-privileges:true' in host.get('SecurityOpt',[]) and host.get('Privileged',False) is False,
        'EXACT_FILE_ONLY_HARDENED_ROOT_MODE_REQUIRED')
    require(type(host.get('Memory')) is int and 0<host['Memory']==host.get('MemorySwap')<=8589934592
        and type(host.get('PidsLimit')) is int and 1<=host['PidsLimit']<=4096
        and type(host.get('NanoCpus')) is int and 0<host['NanoCpus']<=8000000000
        and host['NanoCpus']%10000==0,'EXACT_FILE_ONLY_FINITE_RESOURCE_PROFILE_REQUIRED')
    require(not any(host.get(k) for k in ('CpuPeriod','CpuQuota','CpuRealtimePeriod','CpuRealtimeRuntime','CpusetCpus','CpusetMems',
        'MemoryReservation','MemorySwappiness','OomKillDisable','Ulimits','Sysctls','Devices','DeviceRequests','GroupAdd')),
        'RESOURCE_OR_KERNEL_OVERRIDE_OUTSIDE_FIXED_BASELINE')
    files=[copy.deepcopy(delegation),{k:v for k,v in proposal.items() if k!='metadataHash'}]
    bindings=[{k:s[k] for k in ('source','target','readOnly')} for s in files]
    bindings += [{k:tree[k] for k in ('source','target','readOnly')},{k:token[k] for k in ('source','target')}|{'readOnly':True}]
    startup={'uid':10001,'gid':10001,'umask':None,'cwd':request['WorkingDir'],
        'args':request['Entrypoint']+(request.get('Cmd') or []),'env':docker_bridge_environment(request)}
    launch={'schema':'ouf.semantic-creation-frame-launch.v1','startup':startup,'sources':files,
        'manifest':{'user':'10001:10001','readOnlyRoot':False,'memoryBytes':host['Memory'],
            'pidsLimit':host['PidsLimit'],'mounts':bindings}}
    template=copy.deepcopy(baseline['template']);oci=template['expectedOci']
    oci['process']['user']={'uid':10001,'gid':10001,'additionalGids':[10001]}
    for key in ('cwd','args','env'):oci['process'][key]=copy.deepcopy(startup[key])
    require(oci['process'].get('capabilities')=={} and oci['process'].get('noNewPrivileges') is True,
            'INDEPENDENT_CAPABILITY_BASELINE_DRIFT')
    resources=oci['linux']['resources'];resources['memory']={'limit':host['Memory'],'swap':host['MemorySwap']}
    resources['pids']={'limit':host['PidsLimit']};resources['cpu']={'period':100000,'quota':host['NanoCpus']//10000}
    old_targets={s['target'] for s in baseline['launch']['sources']}
    old=[m for m in oci['mounts'] if m['destination'] in old_targets]
    require(len(old)==1 and old[0]['options']==['rbind','rro','rprivate'],'FIXED_READONLY_BIND_BASELINE_REQUIRED')
    retained=[m for m in oci['mounts'] if m['destination'] not in old_targets]
    defaults=[m for m in retained if m['type']!='bind'];engine_mounts=[m for m in retained if m['type']=='bind']
    require({m['destination'] for m in engine_mounts}=={'/etc/hosts','/etc/hostname','/etc/resolv.conf'},'FIXED_ENGINE_MOUNT_SET_REQUIRED')
    mounted=[{'type':'bind','source':b['source'],'destination':b['target'],'options':copy.deepcopy(old[0]['options'])} for b in bindings]
    oci['mounts']=defaults+sorted(mounted+engine_mounts,key=lambda m:(m['destination'].count('/'),m['destination']))
    return template,launch
