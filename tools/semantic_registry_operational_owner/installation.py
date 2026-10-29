"""Pure installation material compiler. No signing, file writes or service start.

The authenticated installer must create these exact bytes and a real scoped
installation attestation. A proposal alone cannot start the runtime worker.
"""
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import ssl
import time
from .core import require, digest, encoded
from .contract import SCHEMA, absolute


def public_ca_bundle(profile, expected_trust_hash, context):
    """Freeze the already approved IAM certificate set, without ambient extras.

    Preparation supplies the current issuer context. Neither a caller API CA
    nor a newly discovered root can silently replace the retained IAM trust.
    Returns public PEM bytes only, without writing files or making requests.
    """
    from tools.semantic_policy_token_owner.iam_admission import PinnedIamOpener
    clock=lambda:(time.time(),time.monotonic())
    original=PinnedIamOpener(profile,clock,context=context)
    require(original.trust_digest()==expected_trust_hash,'RETAINED_IAM_TRUST_SET_REQUIRED')
    certificates=sorted(context.get_ca_certs(binary_form=True))
    require(1<=len(certificates)<=1024,'BOUNDED_IAM_CA_SET_REQUIRED')
    raw=''.join(ssl.DER_cert_to_PEM_cert(cert) for cert in certificates).encode('ascii')
    require(len(raw)<=4194304,'BOUNDED_IAM_PUBLIC_CA_BUNDLE_REQUIRED')
    replay=ssl.create_default_context(cadata=raw.decode('ascii'))
    require(PinnedIamOpener(profile,clock,context=replay).trust_digest()==expected_trust_hash,
            'EXACT_EXPLICIT_IAM_TRUST_REPRODUCTION_REQUIRED')
    return raw


def configuration(proposal, *, sources, fence_binding, common_lock_identity, verification, service_unit_path):
    require(type(proposal) is dict and proposal.get('schema')==SCHEMA
            and proposal.get('runtimeAuthorityIssued') is False
            and proposal.get('targetApplyAuthorized') is False
            and proposal.get('priorControlledGrantAttempts')==321,
            'REVIEWED_OPERATIONAL_INSTALLATION_PROPOSAL_REQUIRED')
    require(type(sources) is list and bool(sources), 'COMPLETE_OPERATIONAL_EXECUTION_BINDINGS_REQUIRED')
    for source in sources:
        require(type(source) is dict and set(source)=={'path','sha256','maximumBytes'},
                'EXACT_OPERATIONAL_EXECUTION_BINDING_REQUIRED')
        absolute(source['path'])
        require(type(source['sha256']) is str and len(source['sha256'])==64
                and set(source['sha256'])<=set('0123456789abcdef')
                and type(source['maximumBytes']) is int and 1<=source['maximumBytes']<=67108864,
                'BOUNDED_OPERATIONAL_EXECUTION_BINDING_REQUIRED')
    require(len({s['path'] for s in sources})==len(sources), 'UNIQUE_OPERATIONAL_EXECUTION_BINDINGS_REQUIRED')
    require(type(fence_binding) is dict and set(fence_binding)=={'path','value'}
            and type(fence_binding['value']) is dict,
            'EXACT_OPERATIONAL_SUCCESSOR_FENCE_REQUIRED')
    absolute(fence_binding['path'])
    require(type(common_lock_identity) is list and len(common_lock_identity)==9
            and all(type(v) is int and v>=0 for v in common_lock_identity),
            'EXACT_OPERATIONAL_COMMON_LOCK_IDENTITY_REQUIRED')
    require(type(verification) is dict and set(verification)=={'trustPolicy','openssl','context'},
            'PUBLIC_OPERATIONAL_RECEIPT_VERIFICATION_REQUIRED')
    require(proposal['sourceManifestHash']==digest(proposal['sourceManifest']),
            'OPERATIONAL_SOURCE_MANIFEST_CHANGED')
    absolute(service_unit_path)
    return copy.deepcopy(dict(schema='ouf.registry-operational-token-configuration.v1',
        proposalHash=digest(proposal), sourceManifest=proposal['sourceManifest'], sources=sources,
        ownerInputs=proposal['ownerInputs'], policy=proposal['policy'], destinations=proposal['destinations'],
        priorControlledAttempts=321, predecessorInputsHash=proposal['inputsBinding']['sha256'],
        fenceBinding=fence_binding, commonLockIdentity=common_lock_identity,
        verification=verification, tlsCa=proposal['publicTlsCaBinding'],serviceUnitPath=service_unit_path,
        hostBootIdPath='/run/ouf/host-boot-id'))


def unit_word(value):
    # No shell, environment/specifier expansion, list separators or alternate
    # bind destinations. Deployment values still come from reviewed bindings.
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+',value)
            and '..' not in Path(value).parts,'EXACT_SYSTEMD_BOUND_PATH_REQUIRED')
    return value


def service_unit(c, configuration_hash, python, capsule):
    """Exact root worker sandbox. The host manager owns process lifecycle.

    A private root hides host secrets, sockets and process roots.
    Only approved inputs/output are bind-mounted back; IAM peers bound egress.
    No signing key, Docker socket, API server credential or host PID tree.
    """
    from tools.semantic_policy_token_owner.iam_admission import IamProfile
    p=copy.deepcopy(c['ownerInputs']['iamProfile'])
    for key in ('required_scopes','allowed_scopes','peer_addresses'):p[key]=tuple(p[key])
    profile=IamProfile(**p)
    require(python.startswith('/usr/') and c['verification']['openssl']['path'].startswith('/usr/'),
            'QUALIFIED_SYSTEM_RUNTIME_PREFIX_REQUIRED')
    require(re.fullmatch('[a-f0-9]{64}',configuration_hash) is not None,'PINNED_SYSTEMD_CONFIGURATION_REQUIRED')
    install=unit_word(c['destinations']['installationRoot']);ledger=unit_word(c['destinations']['ledgerRoot'])
    output=unit_word(c['ownerInputs']['binding']['output_directory']);gid=c['ownerInputs']['binding']['output_gid']
    require(type(gid) is int and 1<=gid<=2**31-1,'EXISTING_TOKEN_OUTPUT_GROUP_REQUIRED')
    readonly={install+'/capsule.py',install+'/configuration.json',install+'/iam-ca.pem',
        install+'/installed.json',install+'/receipt-signatures',c['serviceUnitPath'],
        str(Path(c['ownerInputs']['credentialPath']).parent),
        str(Path(c['verification']['trustPolicy']['path']).parent),
        str(Path(c['destinations']['commonInvocationLock']).parent),
        str(Path(c['fenceBinding']['path']).parent)}
    require(all(len(Path(path).parts)>=4 for path in(
        str(Path(c['ownerInputs']['credentialPath']).parent),str(Path(c['verification']['trustPolicy']['path']).parent),
        str(Path(c['destinations']['commonInvocationLock']).parent),str(Path(c['fenceBinding']['path']).parent))),
        'DEDICATED_CREDENTIAL_TRUST_AND_FENCE_DIRECTORIES_REQUIRED')
    # These are operating-system public inputs, never service discovery.
    readonly.update(('/etc/passwd','/etc/group','/etc/nsswitch.conf','/etc/ld.so.cache'))
    lines=['[Unit]','Description=OUF Registry existing IAM credential renewal',
        'After=network-online.target','Wants=network-online.target',
        'StartLimitIntervalSec=300','StartLimitBurst=3','', '[Service]',
        'Type=simple','RootDirectory='+install+'/sandbox','User=root','Group=root',
        'ExecStart=:'+unit_word(python)+' -I -B -S '+unit_word(capsule)+' worker --configuration '+install+
        '/configuration.json --configuration-sha256 '+configuration_hash,
        'Restart=on-failure','RestartSec=15','TimeoutStopSec=35','KillMode=control-group',
        'UMask=0077','NoNewPrivileges=yes','CapabilityBoundingSet=CAP_CHOWN',
        'ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','PrivateDevices=yes',
        'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectKernelLogs=yes',
        'ProtectControlGroups=yes','ProtectClock=yes','LockPersonality=yes',
        'MemoryDenyWriteExecute=yes','RestrictRealtime=yes','RestrictSUIDSGID=yes',
        'RestrictNamespaces=yes','RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
        'SystemCallArchitectures=native','SystemCallFilter=@system-service',
        'SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd',
        'MountAPIVFS=no','InaccessiblePaths=+/proc',
        'BindReadOnlyPaths=/usr /lib -/lib64 '+' '.join(unit_word(x) for x in sorted(readonly))+
        ' /proc/sys/kernel/random/boot_id:'+unit_word(c['hostBootIdPath']),
        'BindPaths='+ledger+' '+output,'ReadWritePaths=+'+ledger+' +'+output,
        'IPAddressDeny=any',*['IPAddressAllow='+ip for ip in profile.peer_addresses],
        'Environment=PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null',
        'UnsetEnvironment=PYTHONPATH PYTHONHOME PYTHONSTARTUP SSLKEYLOGFILE SSL_CERT_FILE SSL_CERT_DIR HTTP_PROXY HTTPS_PROXY ALL_PROXY',
        'LimitNOFILE=256','TasksMax=32','', '[Install]','WantedBy=multi-user.target','']
    return '\n'.join(lines).encode('ascii')


def key_isolation(c, key_paths):
    """Reject a bind layout that would expose any existing signing key."""
    directories=[Path(c['ownerInputs']['credentialPath']).parent,Path(c['verification']['trustPolicy']['path']).parent,
        Path(c['destinations']['commonInvocationLock']).parent,Path(c['fenceBinding']['path']).parent,
        Path(c['ownerInputs']['binding']['output_directory']),Path(c['destinations']['ledgerRoot']),
        Path('/usr'),Path('/lib'),Path('/lib64')]
    for value in key_paths:
        path=Path(absolute(value))
        require(not any(path==parent or parent in path.parents for parent in directories),
                'SIGNING_KEYS_MUST_BE_OUTSIDE_EVERY_RUNTIME_BIND')


REVIEW_SCHEMA='ouf.registry-operational-installation-review.v1'
AUTHORITY_SCHEMA='ouf.registry-operational-installation-authority.v1'
HUMAN_SCHEMA='ouf.registry-operational-installation-human-mandate.v1'
DECISION='APPROVE_EXACT_INSTALLATION_AND_REVIEWED_NORMAL_RENEWAL'


def review_scope(review):
    require(type(review) is dict and review.get('schema')==REVIEW_SCHEMA,
            'COMPLETE_OPERATIONAL_INSTALLATION_REVIEW_REQUIRED')
    c=review['configuration'];proposal=review['proposal'];unit=review['serviceUnit']
    require(c['proposalHash']==digest(proposal) and c['sourceManifest']==proposal['sourceManifest']
            and c['policy']==proposal['policy'] and c['ownerInputs']==proposal['ownerInputs']
            and c['destinations']==proposal['destinations']
            and c['predecessorInputsHash']==proposal['inputsBinding']['sha256']
            and c['priorControlledAttempts']==proposal['priorControlledGrantAttempts']==321
            and review['maximumInstallationSeconds']==900 and review['runtimeAuthorityIssued'] is False
            and review['targetApplyAuthorized'] is False and review['releaseAcceptance'] is False,
            'EXACT_COMPLETE_OPERATIONAL_REVIEW_BINDINGS_REQUIRED')
    require(unit['path']==c['serviceUnitPath']
            and unit['sha256']==hashlib.sha256(unit['body'].encode('ascii')).hexdigest()
            and unit['body'].encode('ascii')==service_unit(c,digest(c),review['executables']['python']['path'],
                c['destinations']['installationRoot']+'/capsule.py'),
            'EXACT_RECOMPILED_OPERATIONAL_SERVICE_UNIT_REQUIRED')
    require(review['capsuleSource']['sha256']==next(s['sha256'] for s in c['sources']
                if s['path']==c['destinations']['installationRoot']+'/capsule.py')
            and review['publicCaSource']['sha256']==c['tlsCa']['sha256'],
            'EXACT_OPERATIONAL_INSTALLATION_ARTIFACT_BINDINGS_REQUIRED')
    return {'schema':'ouf.registry-operational-installation-scope.v1','reviewHash':digest(review),
        'configurationHash':digest(c),'sourceManifestHash':digest(c['sourceManifest']),
        'serviceUnitHash':unit['sha256'],'policyHash':proposal['policyHash'],
        'predecessorInputsHash':c['predecessorInputsHash'],'priorControlledAttempts':321,
        'normalRenewalAfterInstallation':True,'sameAttemptRedispatchAllowed':False,
        'legacyFiniteBudgetExtended':False,'nativeRecoveryReplayAllowed':False,
        'containerLifecycleOperationsAllowed':False,'iamPermissionChangesAllowed':False}


class SignedInstallation:
    """Fresh finite installation gate using existing real scoped Ed25519 roles.

    This schema cannot authorize a legacy cutover/recovery phase. Runtime
    renewal uses the completed installation receipt and existing IAM permission;
    it never reuses or extends the installation HUMAN execution window.
    """
    def __init__(self, review, authority_raw, human_binding, approved_human_hash, verifier):
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        require(type(verifier) is DetachedAuthenticator,'ACTUAL_OPERATIONAL_ROLE_VERIFIER_REQUIRED')
        self.review=copy.deepcopy(review);self.scope=review_scope(review);self.raw=authority_raw
        self.human=copy.deepcopy(human_binding);self.approved_human=approved_human_hash;self.verifier=verifier
        require(set(human_binding)=={'path','sha256'} and human_binding['sha256']==approved_human_hash,
                'EXPLICIT_ROOT_OPERATIONAL_HUMAN_BINDING_REQUIRED')
        self.check()

    def check(self):
        from .guard import protected_file
        raw=protected_file(self.human['path'],131072,expected=self.approved_human,modes=(0o600,))
        human=json.loads(raw);authority=json.loads(self.raw)
        require(encoded(human)==raw and encoded(authority)==self.raw,'EXACT_OPERATIONAL_AUTHORITY_BYTES_REQUIRED')
        expected={'schema':AUTHORITY_SCHEMA,'scope':self.scope,'issuedAt':human['issuedAt'],
            'expiresAt':human['expiresAt'],'installationRef':self.review['verification']['context']['installationRef'],
            'entityRef':self.review['verification']['context']['entityRef'],
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
        require(authority==expected and set(human)=={'schema','reviewHash','authorityHash','decision','state','issuedAt','expiresAt'}
            and human['schema']==HUMAN_SCHEMA and human['reviewHash']==digest(self.review)
            and human['authorityHash']==hashlib.sha256(self.raw).hexdigest()
            and human['decision']==DECISION and human['state']=='ACTIVE'
            and type(human['issuedAt']) is int and type(human['expiresAt']) is int
            and human['expiresAt']-human['issuedAt']==self.review['maximumInstallationSeconds']
            and human['issuedAt']<=time.time()<human['expiresAt'],
            'FRESH_EXACT_FINITE_OPERATIONAL_INSTALLATION_MANDATE_REQUIRED')
        ctx=self.review['verification']['context']
        require(self.verifier.policy_binding==self.review['verification']['trustPolicy']
                and self.verifier.openssl_binding==self.review['verification']['openssl'],
                'REVIEWED_OPERATIONAL_INSTALLATION_VERIFIER_REQUIRED')
        for role,issuer in (('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(self.verifier(self.raw,role,ctx[issuer],ctx['installationRef'],ctx['entityRef']) is True,
                    'CURRENT_DUAL_OPERATIONAL_INSTALLATION_SIGNATURES_REQUIRED')
        from tools.semantic_provider_deployment_authentication import policy as public_policy
        current=public_policy(self.verifier.read_policy(),ctx['installationRef'],ctx['entityRef'],time.time())
        for role,issuer in (('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),
                           ('CREATION_ATTESTATION','attestorRef')):
            keys=[k for k in current['keys'] if role in k['roles'] and k['issuerRef']==ctx[issuer]
                  and k['state']=='ACTIVE' and k['notBefore']<=human['issuedAt']]
            require(len(keys)==1 and keys[0]['expiresAt']>=human['expiresAt'],
                    'WHOLE_INSTALLATION_WINDOW_WITHIN_CURRENT_SCOPED_KEY_AUTHORITY_REQUIRED')
        return True


def read_object(path, maximum=8388608, expected=None):
    from .guard import protected_file
    raw=protected_file(path,maximum,expected=expected,modes=(0o400,0o600))
    value=json.loads(raw)
    require(type(value) is dict and encoded(value)==raw,'CANONICAL_OPERATIONAL_INSTALLATION_INPUT_REQUIRED')
    return value


@contextmanager
def directory(path):
    """Hold every ancestry FD; no symlink traversal or writable ancestors."""
    from .store import identity
    path=Path(absolute(str(path)));fds=[];pins=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in path.parts[1:]:
            s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_INSTALLATION_ANCESTRY_REQUIRED')
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            fds.append(fd);pins.append((parent,part,fd,identity(os.fstat(fd))))
        s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_INSTALLATION_DIRECTORY_REQUIRED')
        yield fd
        for parent,name,child,pin in pins:
            require(pin==identity(os.fstat(child))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'INSTALLATION_ANCESTRY_CHANGED')
    finally:
        for fd in reversed(fds):os.close(fd)


def new_file(parent, name, raw, mode=0o600):
    require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,200}',name)
            and name not in('.','..') and type(raw) is bytes and len(raw)<=8388608,
            'BOUNDED_EXCLUSIVE_INSTALLATION_FILE_REQUIRED')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
    try:
        os.fchown(fd,0,0);os.fchmod(fd,mode);remaining=memoryview(raw)
        while remaining:
            n=os.write(fd,remaining);require(n>0,'INSTALLATION_WRITE_INCOMPLETE');remaining=remaining[n:]
        os.fsync(fd);os.fsync(parent)
    finally:os.close(fd)


@contextmanager
def existing_lock(path):
    from .store import file_identity
    path=Path(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==0o600,'EXISTING_PRIVATE_INSTALLATION_LOCK_REQUIRED')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:require(False,'CONCURRENT_INSTALLATION_OR_TOKEN_OWNER')
            yield list(file_identity(s))
            require(file_identity(s)==file_identity(os.fstat(fd))
                    ==file_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                    'INSTALLATION_LIFETIME_LOCK_CHANGED')
        finally:os.close(fd)


def predecessor_guard(inputs):
    native=inputs['prepared']['nativeContext'];scope=inputs['review']['scopes']['semanticRegistryPostbootOwner']
    require(read_object(Path(native['executionRoot'])/'recovery.json')==inputs['retainedNativeJournal']
            and read_object(Path(native['executionRoot'])/'native-reads.json')==inputs['retainedNativeReads'],
            'NATIVE_PREFIX_OR_READ_ACCOUNTING_CHANGED')
    for name,value in inputs['retainedOwnerRecords'].items():
        require(read_object(Path(scope['journalPath'])/name)==value,'CANCELLED_OWNER_HISTORY_CHANGED')
    require(read_object(inputs['retainedFence']['path'])==inputs['retainedFence']['value'],
            'PREDECESSOR_GLOBAL_FENCE_CHANGED')


def verify_running_generation(inputs):
    """One allowlisted Engine GET; never lifecycle or gateway/database calls."""
    from engine_creation import Engine
    from tools.semantic_live_route_diagnostic.reader import process_ticks
    context=inputs['prepared']['nativeContext'];binding=context['engineBinding']
    cid=context['plan']['stages'][0]['intent']['registryId']
    engine=Engine(binding['socketPath'],tuple(binding['socketBinding']))
    code,row=engine.request('GET','/v1.44/containers/'+cid+'/json')
    old=inputs['currentRegistryObservation'];g=inputs['retainedNativeJournal']['newGeneration'];state=row.get('State',{})
    require(code==200 and row.get('Id')==cid==old['Id'] and row.get('Image')==old['Image']
            and all(row.get(k)==old.get(k) for k in('Config','HostConfig','Mounts','NetworkSettings','RestartCount'))
            and state.get('Running') is True and state.get('Paused') is False
            and state.get('Restarting') is False and state.get('Dead') is False
            and state.get('Pid')==g['pid'] and process_ticks(g['pid'])==g['startTicks']
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==g['bootId'],
            'EXACT_CURRENT_RUNNING_REGISTRY_GENERATION_REQUIRED')
    ns=Path('/proc')/str(g['pid'])/'ns/net';s=ns.stat()
    require((s.st_dev,s.st_ino)==(g['namespaceDevice'],g['namespaceInode']),
            'SAME_RUNNING_REGISTRY_NETWORK_NAMESPACE_REQUIRED')
    return digest(row)


def install_files(review, authority, attestor):
    """Single-use installation transaction, with no token grant or process start.

    A consumed stable claim survives every failure. It is never an automatic
    resume token. Old journals and counters are read only. The global fence is
    switched last, after complete signed installation material is durable.
    """
    from .guard import protected_file
    from .core import initial,RenewalPolicy
    from .store import file_identity
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    require(type(authority) is SignedInstallation and authority.review==review
            and type(attestor) is ExistingEd25519Signer
            and attestor.verifier is authority.verifier,
            'ACTUAL_SIGNED_INSTALLATION_AND_EXISTING_ATTESTOR_REQUIRED')
    key_isolation(review['configuration'],[attestor.key['path']])
    authority.check();scope=review_scope(review);c=review['configuration']
    inputs=read_object(review['proposal']['inputsBinding']['path'],expected=review['proposal']['inputsBinding']['sha256'])
    p=dict(c['policy']);p['failure_delays']=tuple(p['failure_delays']);policy=RenewalPolicy(**p)
    from .contract import compile_proposal
    require(encoded(compile_proposal(inputs,review['proposal']['inputsBinding'],c['sourceManifest'],policy,
                c['destinations'],c['tlsCa']))==encoded(review['proposal']),
            'INDEPENDENT_OPERATIONAL_PROPOSAL_RECOMPILATION_REQUIRED')
    require(attestor.scope==dict(role='CREATION_ATTESTATION',issuerRef=review['verification']['context']['attestorRef'],
                installationRef=review['verification']['context']['installationRef'],
                entityRef=review['verification']['context']['entityRef']),
            'EXACT_EXISTING_OPERATIONAL_INSTALLATION_ATTESTOR_REQUIRED')
    old=inputs['review']['scopes']['semanticRegistryPostbootOwner'];native=inputs['prepared']['nativeContext']
    require(old['logicalOwnerScopeHash']==review['logicalOwnerScopeHash']
            and c['destinations']['commonInvocationLock']==old['journalPath']+'/invocation.lock',
            'SAME_LOGICAL_OWNER_INSTALLATION_REQUIRED')
    root=Path(c['destinations']['installationRoot']);ledger=Path(c['destinations']['ledgerRoot']);unit=Path(c['serviceUnitPath'])
    require(root.parent==ledger.parent and root!=ledger and root.parent!=root,
            'EXPLICIT_SIBLING_PRIVATE_INSTALLATION_ROOTS_REQUIRED')
    source=protected_file(review['capsuleSource']['path'],2097152,expected=review['capsuleSource']['sha256'],modes=(0o400,0o600))
    ca=protected_file(review['publicCaSource']['path'],4194304,expected=review['publicCaSource']['sha256'],modes=(0o400,0o600))
    claim_name='operational-install-'+review['logicalOwnerScopeHash']+'.claim.json'
    with existing_lock(Path(native['executionRoot'])/'invocation.lock'), existing_lock(c['destinations']['commonInvocationLock']) as common:
        require(common==c['commonLockIdentity'],'SAME_REVIEWED_COMMON_INVOCATION_LOCK_REQUIRED')
        predecessor_guard(inputs);authority.check()
        with directory(root.parent) as parent, directory(unit.parent) as unit_parent:
            # This claim is keyed by logical owner, independent of source,
            # random review paths, old HUMAN windows and attempt budgets.
            new_file(parent,claim_name,encoded({'schema':'ouf.registry-operational-installation-claim.v1',
                'reviewHash':digest(review),'authorityHash':hashlib.sha256(authority.raw).hexdigest(),
                'logicalOwnerScopeHash':review['logicalOwnerScopeHash'],'priorControlledAttempts':321,
                'automaticReplayAllowed':False,'budgetReset':False}))
            # Consume observation before network dispatch. A later failure
            # leaves it and the stable installation claim in place.
            mark='operational-install-'+review['logicalOwnerScopeHash']+'.get1.json'
            new_file(parent,mark,encoded({'attempt':1,'method':'GET'}))
            verify_running_generation(inputs);authority.check()
            for target in(root,ledger):
                os.mkdir(target.name,0o700,dir_fd=parent);os.fsync(parent)
            with directory(root) as files, directory(ledger) as state:
                os.mkdir('sandbox',0o700,dir_fd=files);os.mkdir('fence',0o700,dir_fd=files);os.fsync(files)
                with directory(root/'sandbox') as sandbox:
                    for name in('usr','lib','lib64','etc','run','proc','dev'):os.mkdir(name,0o755,dir_fd=sandbox)
                    os.mkdir('tmp',0o1777,dir_fd=sandbox);os.fsync(sandbox)
                with directory(root/'fence') as fence_files:
                    new_file(fence_files,'fence.json',encoded(dict(c['fenceBinding']['value'],active=False)))
                new_file(files,'capsule.py',source,0o400);new_file(files,'iam-ca.pem',ca,0o600)
                new_file(files,'configuration.json',encoded(c),0o600)
                p=dict(c['policy']);p['failure_delays']=tuple(p['failure_delays']);policy=RenewalPolicy(**p)
                boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                require(boot==review['bootId'],'SAME_INSTALLATION_BOOT_REQUIRED')
                row=initial(digest(c),c['predecessorInputsHash'],321,policy,boot,(time.time(),time.monotonic()))
                new_file(state,'state.json',encoded(row));new_file(state,'invocation.lock',b'');new_file(state,'cas.lock',b'')
                authority.check();new_file(unit_parent,unit.name,review['serviceUnit']['body'].encode('ascii'),0o644)
                os.mkdir('receipt-signatures',0o700,dir_fd=files);os.fsync(files)
                receipt={'schema':'ouf.registry-operational-token-installation-receipt.v1','complete':True,
                    'configurationHash':digest(c),'proposalHash':c['proposalHash'],
                    'sourceManifestHash':digest(c['sourceManifest']),'operationalRenewalInstalled':True,
                    'priorControlledAttempts':321,'serviceUnitPath':str(unit),'serviceUnitHash':review['serviceUnit']['sha256'],
                    'reviewHash':digest(review),'authorityHash':hashlib.sha256(authority.raw).hexdigest(),
                    'installationClaimHash':digest(read_object(root.parent/claim_name))}
                authority.check();signature=attestor.sign(encoded(receipt));authority.check()
                with directory(root/'receipt-signatures') as signatures:
                    new_file(signatures,digest(receipt)+'.CREATION_ATTESTATION.json',signature)
                new_file(files,'installed.json',encoded(receipt))
            predecessor_guard(inputs);authority.check()
            new_file(parent,'operational-install-'+review['logicalOwnerScopeHash']+'.get2.json',encoded({'attempt':2,'method':'GET'}))
            verify_running_generation(inputs);authority.check()
            # Exact compare-and-swap of the fence under both invocation locks.
            fence=Path(inputs['retainedFence']['path'])
            with directory(fence.parent) as fence_parent:
                before=os.stat(fence.name,dir_fd=fence_parent,follow_symlinks=False)
                require(read_object(fence)==inputs['retainedFence']['value'],'OLD_FENCE_MUST_MATCH_BEFORE_INSTALLATION_COMMIT')
                name='operational-fence-'+review['logicalOwnerScopeHash']+'.tmp'
                new_file(fence_parent,name,encoded(c['fenceBinding']['value']))
                authority.check()
                require(file_identity(before)==file_identity(os.stat(fence.name,dir_fd=fence_parent,follow_symlinks=False))
                        and read_object(fence)==inputs['retainedFence']['value'],'GLOBAL_FENCE_CAS_CONFLICT')
                os.replace(name,fence.name,src_dir_fd=fence_parent,dst_dir_fd=fence_parent);os.fsync(fence_parent)
                require(read_object(fence)==c['fenceBinding']['value'],'COMMITTED_OPERATIONAL_FENCE_READBACK_REQUIRED')
            # The dedicated DIRECTORY is mounted read only in the worker, so
            # atomic fence replacements and revocations remain visible there.
            # It is activated only AFTER the legacy-global CAS has committed.
            active_fence=Path(c['fenceBinding']['path'])
            with directory(active_fence.parent) as public_fence:
                require(read_object(active_fence)==dict(c['fenceBinding']['value'],active=False),
                        'INACTIVE_OPERATIONAL_FENCE_REQUIRED_BEFORE_ACTIVATION')
                new_file(public_fence,'active.tmp',encoded(c['fenceBinding']['value']))
                authority.check()
                os.replace('active.tmp',active_fence.name,src_dir_fd=public_fence,dst_dir_fd=public_fence);os.fsync(public_fence)
                require(read_object(active_fence)==c['fenceBinding']['value'],'OPERATIONAL_FENCE_ACTIVATION_READBACK_REQUIRED')
            result={'schema':'ouf.registry-operational-installation-result.v1','status':'NORMAL_RENEWAL_INSTALLED_NOT_STARTED',
                'complete':True,'reviewHash':digest(review),'configurationHash':digest(c),'engineGets':2,
                'retainedControlledGrantAttempts':321,'oauthRequests':0,'tokenGrants':0,
                'containerLifecycleOperations':0,'nativeJournalWrites':0,'processStarted':False,
                'permanentRenewalProven':False,'originalSemanticGetSucceeded':False,'releaseAcceptance':False,
                'automaticReplayAllowed':False,'budgetReset':False}
            with directory(root) as files:new_file(files,'installation-result.json',encoded(result))
            return result


def make_review(inputs, binding, manifest, capsule_source, ca_source, *, parent, unit_parent,
                common_identity, authority_inputs, policy):
    """Recompile all installed bytes; this remains a proposal, not authority."""
    from .contract import compile_proposal
    old=inputs['review']['scopes']['semanticRegistryPostbootOwner'];logical=old['logicalOwnerScopeHash']
    require(re.fullmatch('[a-f0-9]{64}',logical) is not None,'EXACT_LOGICAL_REGISTRY_OWNER_REQUIRED')
    absolute(parent);absolute(unit_parent)
    destinations={'installationRoot':parent+'/semantic-registry-operational-'+logical,
        'ledgerRoot':parent+'/semantic-registry-operational-state-'+logical,
        'commonInvocationLock':old['journalPath']+'/invocation.lock'}
    ca={'path':destinations['installationRoot']+'/iam-ca.pem','sha256':ca_source['sha256']}
    proposal=json.loads(encoded(compile_proposal(inputs,binding,manifest,policy,destinations,ca)))
    verification={'trustPolicy':authority_inputs['trustPolicy'],'openssl':authority_inputs['executables']['openssl'],
                  'context':authority_inputs['context']}
    sources=[{'path':destinations['installationRoot']+'/capsule.py','sha256':capsule_source['sha256'],'maximumBytes':2097152}]
    sources.extend({'path':authority_inputs['executables'][key]['path'],
                    'sha256':authority_inputs['executables'][key]['sha256'],'maximumBytes':67108864} for key in('python','openssl'))
    fence={'path':destinations['installationRoot']+'/fence/fence.json','value':{'schema':'ouf.registry-operational-owner-fence.v1',
        'logicalOwnerScopeHash':logical,'proposalHash':digest(proposal),'sourceManifestHash':digest(manifest),
        'journalPath':destinations['ledgerRoot'],'installationRoot':destinations['installationRoot'],
        'predecessorWorkerHash':digest(inputs['retainedOwnerRecords']['recovery.json']),
        'priorControlledAttempts':321,'operationalFencePath':destinations['installationRoot']+'/fence/fence.json','active':True}}
    unit_path=unit_parent+'/ouf-registry-token-'+logical[:24]+'.service'
    c=configuration(proposal,sources=sources,fence_binding=fence,common_lock_identity=common_identity,
                    verification=verification,service_unit_path=unit_path)
    body=service_unit(c,digest(c),authority_inputs['executables']['python']['path'],destinations['installationRoot']+'/capsule.py')
    result={'schema':REVIEW_SCHEMA,'proposal':proposal,'configuration':c,
        'serviceUnit':{'path':unit_path,'sha256':hashlib.sha256(body).hexdigest(),'body':body.decode('ascii')},
        'capsuleSource':capsule_source,'publicCaSource':ca_source,'verification':verification,
        'executables':authority_inputs['executables'],'authorityProfile':authority_inputs['authorityProfile'],
        'stdlibHash':authority_inputs['stdlibHash'],'stdlibFileCount':authority_inputs['stdlibFileCount'],
        'logicalOwnerScopeHash':logical,'bootId':inputs['retainedNativeJournal']['bootId'],
        'maximumInstallationSeconds':900,'processStartAuthorizedAfterInstallation':True,
        'bootEnablementAuthorized':True,'maximumManagerMutationCommands':2,
        'maximumInitialPublicationWaitSeconds':45,
        'maximumInstallationEngineGets':2,'tokenGrantsDuringInstallation':0,
        'oldNativeJournalWritesAllowed':False,'callerTokenRebindingAllowed':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    review_scope(result)
    return result


def source_custody(review):
    import sys
    from .guard import protected_file
    from .contract import SOURCE_NAMES
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    from tools.semantic_policy_token_owner.iam_governance_intake import executable
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.geteuid()==os.getegid()==0,'ISOLATED_ROOT_OPERATIONAL_INSTALLATION_REQUIRED')
    manifest=review['configuration']['sourceManifest']
    require(set(manifest['sourceHashes'])==SOURCE_NAMES,'COMPLETE_INSTALLATION_SOURCE_CUSTODY_REQUIRED')
    for name,sha in manifest['sourceHashes'].items():
        module=sys.modules.get(name)
        require(module is not None and getattr(module,'__qualified_source_sha256__',None)==sha,
                'SEALED_EXECUTED_OPERATIONAL_INSTALLATION_SOURCE_REQUIRED')
    require(str(Path(sys.executable).resolve(strict=True))==review['executables']['python']['path'],
            'REVIEWED_OPERATIONAL_INSTALLATION_INTERPRETER_REQUIRED')
    for value in review['executables'].values():
        require(executable(value['path'])=={k:value[k] for k in('path','sha256')},
                'OPERATIONAL_INSTALLATION_EXECUTABLE_CHANGED')
    library=stdlib_binding()
    require(digest(library)==review['stdlibHash'] and len(library['fileHashes'])==review['stdlibFileCount'],
            'OPERATIONAL_INSTALLATION_STDLIB_CHANGED')
    protected_file(review['capsuleSource']['path'],2097152,expected=review['capsuleSource']['sha256'],modes=(0o400,0o600))


def rebuild_review(review):
    from .core import RenewalPolicy
    from .store import file_identity
    inputs=read_object(review['proposal']['inputsBinding']['path'],expected=review['proposal']['inputsBinding']['sha256'])
    old=inputs['review']['authorityInputs'];observed=dict(old)
    observed['executables']=review['executables']
    require({k:v for k,v in observed.items() if k!='executables'}=={k:v for k,v in old.items() if k!='executables'},
            'EXISTING_PUBLIC_INSTALLATION_AUTHORITY_REQUIRED')
    require({k:review[k] for k in('authorityProfile','stdlibHash','stdlibFileCount')}
            =={k:old[k] for k in('authorityProfile','stdlibHash','stdlibFileCount')}
            and review['verification']=={'trustPolicy':old['trustPolicy'],'openssl':old['executables']['openssl'],'context':old['context']},
            'SAME_EXISTING_INSTALLATION_AUTHORITY_AND_RUNTIME_REQUIRED')
    p=dict(review['configuration']['policy']);p['failure_delays']=tuple(p['failure_delays']);policy=RenewalPolicy(**p)
    expected=make_review(inputs,review['proposal']['inputsBinding'],review['configuration']['sourceManifest'],
        review['capsuleSource'],review['publicCaSource'],parent=str(Path(review['configuration']['destinations']['installationRoot']).parent),
        unit_parent=str(Path(review['serviceUnit']['path']).parent),common_identity=review['configuration']['commonLockIdentity'],
        authority_inputs=observed,policy=policy)
    require(expected==review,'COMPLETE_OPERATIONAL_INSTALLATION_REVIEW_CHANGED')
    require(list(file_identity(Path(review['configuration']['destinations']['commonInvocationLock']).lstat()))
            ==review['configuration']['commonLockIdentity'],'REVIEWED_OPERATIONAL_COMMON_LOCK_CHANGED')
    return inputs


def load_installation_authority(review, review_path):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    root=Path(review_path).parent;v=review['verification']
    verifier=DetachedAuthenticator(v['trustPolicy'],str(root/'authority'),v['openssl'])
    raw=(root/'authority'/'authority.json')
    from .guard import protected_file
    authority_raw=protected_file(raw,131072,modes=(0o600,))
    receipt=read_object(root/'authority'/'issued.json')
    human={'path':str(root/'authority'/'human.json'),'sha256':receipt['humanHash']}
    result=SignedInstallation(review,authority_raw,human,receipt['humanHash'],verifier)
    require(receipt['reviewHash']==digest(review) and receipt['authorityHash']==hashlib.sha256(authority_raw).hexdigest(),
            'EXACT_ISSUED_OPERATIONAL_INSTALLATION_RECEIPT_REQUIRED')
    return result


def issue_installation(review, review_path):
    import termios
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    inputs=rebuild_review(review);source_custody(review)
    profile,_=authority_metadata(inputs['review']['authorityInputs'])
    prompt=('\nInstallazione rinnovo ordinario della credenziale Registry. Revisione privata: '+str(review_path)+
        '\nSHA256: '+digest(review)+'\nContatore precedente conservato: 321. Nuovi tentativi distinti: massimo '+
        str(review['configuration']['policy']['maximum_attempts_per_hour'])+'/ora; nessun replay dello stesso tentativo.'+
        '\nIl servizio rinnovera le credenziali dopo questa installazione e ai successivi riavvii.'+
        '\nInstallazione: massimo 900 secondi; nessuna modifica a permessi IAM, container, gateway o database.'+
        '\nPer approvare questa revisione esatta scrivi: APPROVO '+digest(review)+'\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd),'CONTROLLING_OPERATIONAL_INSTALLATION_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,prompt.encode());answer=bytearray()
        while len(answer)<=128:
            char=os.read(fd,1)
            if char in(b'',b'\n'):break
            answer.extend(char)
        require(bytes(answer)==('APPROVO '+digest(review)).encode(),'EXACT_OPERATIONAL_INSTALLATION_NOT_APPROVED')
    finally:os.close(fd)
    require(read_object(review_path,expected=digest(review))==review,'OPERATIONAL_REVIEW_CHANGED_DURING_APPROVAL')
    source_custody(review);rebuild_review(review);authority_metadata(inputs['review']['authorityInputs'])
    now=int(time.time());ctx=review['verification']['context']
    value={'schema':AUTHORITY_SCHEMA,'scope':review_scope(review),'issuedAt':now,'expiresAt':now+900,
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    raw=encoded(value);human={'schema':HUMAN_SCHEMA,'reviewHash':digest(review),
        'authorityHash':hashlib.sha256(raw).hexdigest(),'decision':DECISION,'state':'ACTIVE',
        'issuedAt':now,'expiresAt':now+900}
    root=Path(review_path).parent
    # Stable across code/review directory changes; issuance cannot be reset by
    # regenerating a proposal. The install claim is separate and also stable.
    parent=Path(review['configuration']['destinations']['installationRoot']).parent
    with directory(parent) as files:
        new_file(files,'operational-issue-'+review['logicalOwnerScopeHash']+'.claim.json',encoded({
            'reviewHash':digest(review),'authorityHash':hashlib.sha256(raw).hexdigest(),'automaticReplayAllowed':False}))
    with directory(root) as files:os.mkdir('authority',0o700,dir_fd=files);os.fsync(files)
    with directory(root/'authority') as files:
        new_file(files,'authority.json',raw);new_file(files,'human.json',encoded(human))
        verifier=DetachedAuthenticator(review['verification']['trustPolicy'],str(root/'authority'),review['verification']['openssl'])
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(time.time()<now+900,'FINITE_OPERATIONAL_ISSUANCE_WINDOW_EXPIRED')
            signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
                {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
            new_file(files,hashlib.sha256(raw).hexdigest()+'.'+role+'.json',signer.sign(raw))
        SignedInstallation(review,raw,{'path':str(root/'authority'/'human.json'),'sha256':digest(human)},digest(human),verifier)
        receipt={'schema':'ouf.registry-operational-installation-issued.v1','reviewHash':digest(review),
            'authorityHash':hashlib.sha256(raw).hexdigest(),'humanHash':digest(human),
            'runtimeEffectsDispatched':0,'installationAuthorityIssued':True,'tokenGrants':0,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
        new_file(files,'issued.json',encoded(receipt))
        return receipt


def operator(delivery, argv, capsule_path):
    import sys
    from .guard import protected_file
    from .core import RenewalPolicy
    from .store import file_identity
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_policy_token_owner.iam_governance_intake import executable
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    from tools.semantic_policy_token_owner.iam_admission import IamProfile
    require(len(argv) in(1,3) and argv[0] in('deploy','prepare','issue','install','start','status'),'ONE_EXACT_OPERATIONAL_INSTALLATION_ACTION_REQUIRED')
    if argv[0]=='deploy':
        require(len(argv)==1,'NO_DEPLOYMENT_OVERRIDE_ALLOWED')
        prepared=operator(delivery,['prepare'],capsule_path)
        print(encoded(prepared).decode(),flush=True)
        path,sha=prepared['privateReviewPath'],prepared['reviewHash']
        # Exactly one pass, no automatic retry/resume of any failed phase.
        # The issue action asks the controlling TTY for the concrete review.
        for mode in('issue','install','start'):
            result=operator(delivery,[mode,path,sha],capsule_path)
            print(encoded(result).decode(),flush=True)
        require(result['workerState']=='ACTIVE' and result['publications']>=1
                and result['managerActive'] and result['managerProcessRunning'],
                'INITIAL_ACTUAL_OPERATIONAL_PUBLICATION_AND_PROCESS_REQUIRED')
        return dict(result,status='NORMAL_RENEWAL_RUNNING_ORIGINAL_APPLICATION_GET_UNPROVEN')
    if argv[0]=='prepare':
        require(len(argv)==1,'NO_PREPARATION_ENDPOINT_OVERRIDE_ALLOWED')
        binding=delivery['case']['inputs'];inputs=read_object(binding['path'],expected=binding['sha256'])
        old=inputs['review'];public=old['authorityInputs'];profile,_=authority_metadata(public)
        require(public['executables']['python']==executable(str(Path(sys.executable).resolve(strict=True))),
                'SAME_EXECUTED_INSTALLATION_PYTHON_REQUIRED')
        require(digest(stdlib_binding())==public['stdlibHash'],'SAME_INSTALLATION_STDLIB_REQUIRED')
        context=dict(inputs['prepared']['ownerContext']['ownerInputs']['iamProfile'])
        for key in('required_scopes','allowed_scopes','peer_addresses'):context[key]=tuple(context[key])
        ca=public_ca_bundle(IamProfile(**context),inputs['prepared']['ownerContext']['ownerInputs']['tlsTrustHash'],ssl.create_default_context())
        capsule=protected_file(capsule_path,2097152,modes=(0o400,0o600));cap_sha=hashlib.sha256(capsule).hexdigest()
        parent=str(Path(binding['path']).parent.parent)
        root=Path(parent)/('semantic-registry-operational-review-'+digest({'predecessorInputsHash':binding['sha256'],
             'sourceManifestHash':digest(delivery['sourceManifest'])}))
        owner=old['scopes']['semanticRegistryPostbootOwner'];common=owner['journalPath']+'/invocation.lock'
        with existing_lock(Path(inputs['prepared']['nativeContext']['executionRoot'])/'invocation.lock'),existing_lock(common) as common_id:
            predecessor_guard(inputs)
            with directory(parent) as files:os.mkdir(root.name,0o700,dir_fd=files);os.fsync(files)
            with directory(root) as files:
                new_file(files,'capsule.py',capsule,0o400);new_file(files,'iam-ca.pem',ca,0o400)
                programs=copy.deepcopy(public);programs['executables']={k:v for k,v in public['executables'].items() if k in('python','openssl')}
                programs['executables']['systemctl']=executable(str(Path('/usr/bin/systemctl').resolve(strict=True)))
                review=make_review(inputs,binding,delivery['sourceManifest'],{'path':str(root/'capsule.py'),'sha256':cap_sha},
                    {'path':str(root/'iam-ca.pem'),'sha256':hashlib.sha256(ca).hexdigest()},parent=parent,
                    unit_parent='/etc/systemd/system',common_identity=common_id,authority_inputs=programs,
                    policy=RenewalPolicy(60,120,15,60,3,15,(5,15,60,300)))
                key_isolation(review['configuration'],[value['path'] for value in profile['keyBindings'].values()])
                source_custody(review);new_file(files,'review.json',encoded(review),0o600)
        return {'schema':REVIEW_SCHEMA,'status':'COMPLETE_NORMAL_RENEWAL_INSTALLATION_REVIEW_PREPARED',
            'complete':True,'privateReviewPath':str(root/'review.json'),'reviewHash':digest(review),
            'priorControlledGrantAttempts':321,'maximumNewAttemptsPerHour':60,'oauthRequests':0,'engineGets':0,
            'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(argv)==3 and re.fullmatch('[a-f0-9]{64}',argv[2]),'EXACT_PRIVATE_OPERATIONAL_REVIEW_PATH_AND_HASH_REQUIRED')
    review=read_object(argv[1],expected=argv[2]);inputs=rebuild_review(review);source_custody(review)
    require(review['configuration']['sourceManifest']==delivery['sourceManifest']
            and review['proposal']['inputsBinding']==delivery['case']['inputs'],'SAME_SEALED_OPERATIONAL_DELIVERY_REQUIRED')
    if argv[0]=='issue':return issue_installation(review,argv[1])
    if argv[0]=='install':
        from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
        authority=load_installation_authority(review,argv[1]);profile,_=authority_metadata(inputs['review']['authorityInputs'])
        key_isolation(review['configuration'],[value['path'] for value in profile['keyBindings'].values()])
        ctx=review['verification']['context']
        attestor=ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],authority.verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        return install_files(review,authority,attestor)
    return manage_installed(review,argv[1],start=argv[0]=='start')


def manage_installed(review, review_path, *, start):
    import subprocess
    from .guard import InstalledGuard
    from .store import Store
    from .core import RenewalPolicy,validate
    c=review['configuration'];root=Path(c['destinations']['installationRoot'])
    guard=InstalledGuard(root/'configuration.json',digest(c))
    require(guard.configuration==c and read_object(root/'installation-result.json')['complete'] is True,
            'COMPLETED_EXACT_OPERATIONAL_INSTALLATION_REQUIRED')
    program=review['executables']['systemctl']
    from tools.semantic_policy_token_owner.iam_governance_intake import executable
    require(executable(program['path'])==program,'REVIEWED_NATIVE_PROCESS_MANAGER_REQUIRED')
    unit=Path(c['serviceUnitPath']).name
    if start:
        load_installation_authority(review,review_path).check()
        with directory(root) as files:
            new_file(files,'start-claim.json',encoded({'reviewHash':digest(review),'unitHash':review['serviceUnit']['sha256'],
                'maximumManagerMutationCommands':2,'automaticReplayAllowed':False}))
            for ordinal,args in enumerate((['daemon-reload'],['enable','--now',unit]),1):
                load_installation_authority(review,review_path).check()
                new_file(files,'manager-attempt-'+str(ordinal)+'.json',encoded({'ordinal':ordinal,'attemptNotCompletion':True}))
                result=subprocess.run([program['path'],*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,timeout=45,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                require(result.returncode==0,'MANAGER_START_OUTCOME_REQUIRES_RECONCILIATION')
    ledger=Store(c['destinations']['ledgerRoot'])
    try:
        until=time.monotonic()+(review['maximumInitialPublicationWaitSeconds'] if start else 0)
        row=ledger.read()
        while start and row['state'] not in('ACTIVE','BLOCKED','REVOKED') and time.monotonic()<until:
            time.sleep(0.5);row=ledger.read()
    finally:ledger.close()
    result=subprocess.run([program['path'],'show',unit,'--property=ActiveState,SubState,MainPID','--no-pager'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=4096,'BOUNDED_NATIVE_MANAGER_OBSERVATION_REQUIRED')
    properties=dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines())
    require(set(properties)=={'ActiveState','SubState','MainPID'} and properties['MainPID'].isdigit(),
            'EXACT_NATIVE_MANAGER_PROCESS_PROPERTIES_REQUIRED')
    p=dict(c['policy']);p['failure_delays']=tuple(p['failure_delays']);validate(row,RenewalPolicy(**p))
    require(row['installationHash']==digest(c) and row['predecessorInputsHash']==c['predecessorInputsHash'],
            'SAME_INSTALLED_OPERATIONAL_LEDGER_REQUIRED')
    return {'schema':'ouf.registry-operational-owner-observation.v1','status':'INSTALLED_OWNER_PROCESS_OBSERVED',
        'managerActive':properties['ActiveState']=='active','managerProcessRunning':int(properties['MainPID'])>0,
        'workerState':row['state'],'newOperationalGrantAttempts':row['attempts'],
        'controlledCumulativeGrantAttempts':row['cumulativeAttempts'],'publications':row['publications'],
        'lastPublishedWindowPositive':row['tokenExpiresWall'] is not None and row['tokenExpiresWall']>time.time(),
        'lastWindowIsNotCurrentIamAdmissionProof':True,'bootEnablementConfigured':True,
        'processStartRequested':start,'applicationReadinessProven':False,'originalSemanticGetSucceeded':False,
        'permanentRenewalProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
