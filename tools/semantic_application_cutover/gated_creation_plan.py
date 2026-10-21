"""Explicit new launch proposal: wait before the immutable image's Java entry.

Pure plan, no Engine, source/key read, signature, grant or old plan overwrite.
Image/rootfs/publication provenance stays independently verified. The new request
needs fresh private plan/HUMAN/source authority; old intake59… is not reused.
"""
import copy,re
from transition_journal import digest,require

GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
PROFILE='ouf.semantic-preapplication-gate.v2'

def compile_gate(parent_request,parent_request_hash,image_configuration):
    require(type(parent_request) is dict and digest(parent_request)==parent_request_hash,'EXACT_PARENT_CREATION_REQUEST_REQUIRED')
    require(type(image_configuration) is dict and type(image_configuration.get('config')) is dict,'VERIFIED_IMMUTABLE_IMAGE_CONFIGURATION_REQUIRED')
    cfg=image_configuration['config'];entry=cfg.get('Entrypoint');cmd=cfg.get('Cmd') or []
    require(type(entry) is list and entry==['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
            and cmd==[],'EXACT_PUBLISHED_V11_APPLICATION_ENTRY_REQUIRED')
    require(parent_request.get('Entrypoint') in (None,entry) and parent_request.get('Cmd') in (None,[])
            and parent_request.get('User')=='10001:10001','PARENT_APPLICATION_LAUNCH_OR_USER_DRIFT')
    require(type(parent_request.get('Image')) is str and re.fullmatch('sha256:[0-9a-f]{64}',parent_request['Image'])
            and cfg.get('User')=='10001:10001','EXACT_NATIVE_IMAGE_AND_NONROOT_IDENTITY_REQUIRED')
    host=parent_request.get('HostConfig');require(type(host) is dict and host.get('Runtime','runc')=='runc'
            and host.get('Privileged',False) is False and host.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
            and not host.get('CapAdd') and not host.get('DeviceRequests') and not host.get('Devices')
            and all(host.get(k) not in ('host',) and not str(host.get(k,'')).startswith('container:') for k in ('NetworkMode','PidMode','IpcMode','UTSMode')),'BOUNDED_NONPRIVILEGED_GATE_SCOPE_REQUIRED')
    options=host.get('SecurityOpt') or []
    require(type(options) is list and len(options)<=8 and all(type(v) is str for v in options),'EXPLICIT_RETAINED_SECURITY_OPTIONS_REQUIRED')
    require(not any(v=='privileged' or v in ('seccomp=unconfined','seccomp:unconfined','apparmor=unconfined','apparmor:unconfined') for v in options),'UNCONFINED_GATE_PROFILE_DENIED')
    existing=[v for v in options if v.startswith('no-new-privileges')]
    require(existing in ([],['no-new-privileges'],['no-new-privileges:true']),'EXPLICIT_NO_NEW_PRIVILEGES_REQUIRED')
    following=copy.deepcopy(parent_request);following['Entrypoint']=copy.deepcopy(ENTRY);following['Cmd']=copy.deepcopy(entry)
    following['HostConfig']['CapDrop']=['ALL']
    following['HostConfig']['SecurityOpt']=[v for v in options if not v.startswith('no-new-privileges')]+['no-new-privileges:true']
    # Preserve Image/config/source mounts/network/resources; only these explicit
    # launch/hardening fields differ. No Java executes before fresh caught SIGUSR1.
    return following,{'schema':'ouf.semantic-preapplication-gate-proposal.v1','profile':PROFILE,
                      'parentCreationRequestHash':parent_request_hash,'creationRequestHash':digest(following),
                      'imageConfigurationHash':digest(image_configuration),'candidateImageId':following['Image'],
                      'launchGateHash':digest({'Entrypoint':ENTRY,'Cmd':entry}),
                      'changedConfigFields':['Entrypoint','Cmd'],'changedHostFields':['CapDrop','SecurityOpt'],
                      'releaseSignal':'SIGUSR1','imageRebuilt':False,'originalPlanOverwritten':False,
                      'sourceInputsAuthenticatedHere':False,'applicationCutoverAuthorized':False,'productionApplyReady':False,
                      'signaturesIssued':0,'completeRealizedOciProven':False,'notReleaseAcceptance':True}
