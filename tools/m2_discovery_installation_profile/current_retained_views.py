"""Effective per-process mount views for the accepted retained declarations.

Kernel mountinfo/fdinfo and O_PATH only. No setns, command, mount syscall,
Engine, directory enumeration or mounted-file content in this observer. Host
file continuity and live-owner/token admission remain separate typed owners.
"""
import hashlib,os,re,stat
from pathlib import Path
from .custody_capture import attrs,digest,process_pin,require
from .current_retained_static import CurrentRetainedStaticBytes,StaticObservation,BOOT_PATH
from .retained_mount_lifecycle import LIVE,CONTRACT_HASH
from .node_owner import ObservationBudget

KERNEL_CONTRACT='https://www.kernel.org/doc/html/latest/filesystems/proc.html#proc-pid-mountinfo-information-about-mounts'
LIMITS={'maximumSeconds':90,'maximumMountinfoBytes':262144,'maximumMountRows':4096,'maximumFdinfoBytes':8192}


def canonical(value):
    require(type(value) is str and value.startswith('/') and not value.startswith('//') and value!='/' and str(Path(value))==value
        and '..' not in Path(value).parts and len(Path(value).parts)<=64,
        'EXACT_EFFECTIVE_MOUNT_DESTINATION_REQUIRED')
    return value


def unescape(value):
    require(not re.search(r'\\(?!040|011|012|134)',value),'KERNEL_MOUNTINFO_ESCAPE_UNPROVEN')
    return re.sub(r'\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)


def parse_mountinfo(raw):
    require(type(raw) is bytes and 0<len(raw)<=LIMITS['maximumMountinfoBytes'] and raw.endswith(b'\n')
        and b'\x00' not in raw,'COMPLETE_BOUNDED_KERNEL_MOUNTINFO_REQUIRED')
    rows=[];ids=set()
    for line in raw.decode('utf-8').splitlines():
        values=line.split(' ')
        require('' not in values and values.count('-')==1,'EXACT_KERNEL_MOUNTINFO_SEPARATOR_REQUIRED')
        separator=values.index('-')
        require(separator>=6 and len(values)==separator+4 and values[0].isdigit() and int(values[0])>0
            and values[1].isdigit() and re.fullmatch('[0-9]+:[0-9]+',values[2])
            and values[0] not in ids and len(rows)<LIMITS['maximumMountRows'],
            'UNIQUE_BOUNDED_KERNEL_MOUNTINFO_ROWS_REQUIRED')
        point=unescape(values[4]);require(point.startswith('/') and str(Path(point))==point
            and '..' not in Path(point).parts,'CANONICAL_KERNEL_MOUNTPOINT_REQUIRED')
        options=values[5].split(',');require(len(options)==len(set(options))
            and len({'ro','rw'}&set(options))==1,'ONE_EFFECTIVE_PER_MOUNT_ACCESS_MODE_REQUIRED')
        rows.append({'mountId':int(values[0]),'mountPoint':point,'readOnly':'ro' in options});ids.add(values[0])
    return rows


def select_mount(rows,target,readonly):
    canonical(target);found=[row for row in rows if row['mountPoint']==target]
    require(len(found)==1 and found[0]['readOnly'] is readonly
        and not any(row['mountPoint'].startswith(target+'/') for row in rows),
        'EXACT_EFFECTIVE_MOUNT_ACCESS_AND_NO_SHADOWING_REQUIRED')
    return found[0]


def kernel_read(path,maximum,budget):
    budget.check();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        pieces=[];size=0
        while size<=maximum:
            budget.check();raw=os.read(fd,min(65536,maximum+1-size))
            if not raw:break
            pieces.append(raw);size+=len(raw)
        require(0<size<=maximum,'BOUNDED_COMPLETE_KERNEL_METADATA_REQUIRED');return b''.join(pieces)
    finally:os.close(fd)


def fd_mount_id(fd,budget):
    raw=kernel_read('/proc/self/fdinfo/'+str(fd),LIMITS['maximumFdinfoBytes'],budget)
    rows=[row.split(':',1)[1].strip() for row in raw.decode('ascii').splitlines() if row.startswith('mnt_id:')]
    require(len(rows)==1 and rows[0].isdigit() and int(rows[0])>0,'EXACT_HELD_DESCRIPTOR_MOUNT_ID_REQUIRED')
    return int(rows[0])


def view_node(root,target):
    canonical(target);fds=[];fd=os.dup(root);fds.append(fd)
    try:
        for name in Path(target).parts[1:]:
            fd=os.open(name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            require(not stat.S_ISLNK(os.fstat(fd).st_mode),'EFFECTIVE_MOUNT_VIEW_LINK_DENIED')
        return os.dup(fd)
    finally:
        for fd in reversed(fds):os.close(fd)


class CurrentRetainedMountViews:
    def __init__(self,static_bytes):
        require(type(static_bytes) is CurrentRetainedStaticBytes,'ACTUAL_STATIC_BYTES_OWNER_FOR_EFFECTIVE_VIEWS_REQUIRED')
        self.static_bytes=static_bytes;self.runtime=static_bytes.runtime
        self.ids=(id(static_bytes),id(self.runtime));self.guard()

    def guard(self):
        require(type(self.static_bytes) is CurrentRetainedStaticBytes
            and self.ids==(id(self.static_bytes),id(self.runtime)) and self.static_bytes.runtime is self.runtime,
            'SAME_CURRENT_STATIC_BYTES_AND_EFFECTIVE_VIEW_RUNTIME_REQUIRED')
        return self.static_bytes.guard()

    def observe(self):
        budget=ObservationBudget(LIMITS['maximumSeconds']);held=self.guard()
        capture,seed,classes,_,seals=self.static_bytes.material(budget);c=StaticObservation(budget)
        peers=capture['peers'];proofs={};readonly=0;writable=0;tables={};sources={}
        def roots():
            self.guard();budget.check()
            require(BOOT_PATH.read_text().strip()==seed['bootId']
                and all(process_pin(p['pid'])==p for p in seed['rootProcessPins'].values())
                and all(process_pin(p['processPin']['pid'])==p['processPin'] for p in peers.values()),
                'EFFECTIVE_VIEW_BOOT_ROOT_OR_RETAINED_GENERATION_CHANGED')
        roots()
        for role,peer in sorted(peers.items()):
            roots();pid=peer['processPin']['pid'];proc_root='/proc/'+str(pid)+'/root'
            mountinfo='/proc/'+str(pid)+'/mountinfo';before=kernel_read(mountinfo,LIMITS['maximumMountinfoBytes'],budget)
            tables[mountinfo]=before
            rows=parse_mountinfo(before);root=os.open(proc_root,os.O_PATH|os.O_DIRECTORY)
            root_frame=attrs(os.fstat(root))[:5];members=[]
            try:
                for mount,kind in zip(peer['mounts'],classes[role]):
                    roots();selected=select_mount(rows,mount['destination'],mount['readOnly'])
                    require(kind in LIVE|{'STATIC_CAPTURE_CANDIDATE','MUTABLE_CONTENT_NOT_OBSERVED'},
                        'EXACT_CAPTURED_STATIC_LIVE_OR_WRITABLE_VIEW_REQUIRED')
                    expected=(mount['metadataTree']['metadata'] if kind in LIVE|{'STATIC_CAPTURE_CANDIDATE'} else mount['metadata'])
                    static=kind=='STATIC_CAPTURE_CANDIDATE';frame=expected if static else expected[:5]
                    source=c.node(Path(mount['source']));view=None;again=None
                    try:
                        view=view_node(root,mount['destination'])
                        host=attrs(os.fstat(source));inside=attrs(os.fstat(view))
                        require((host==inside==frame if static else host[:5]==inside[:5]==frame)
                            and fd_mount_id(view,budget)==selected['mountId'],
                            'EFFECTIVE_MOUNT_VIEW_SOURCE_IDENTITY_OR_ACCESS_CHANGED')
                        again=view_node(root,mount['destination'])
                        final=attrs(os.fstat(again))
                        require((final==inside if static else final[:5]==inside[:5])
                            and fd_mount_id(again,budget)==selected['mountId'],
                            'EFFECTIVE_MOUNT_NAMED_VIEW_CHANGED_DURING_READ')
                        members.append({'mountHash':mount['mountHash'],'lifecycleClass':kind,
                            'mountId':selected['mountId'],'readOnly':selected['readOnly'],'sourceAndViewMetadata':frame})
                        sources[mount['source']]=(frame,static)
                        readonly+=int(mount['readOnly']);writable+=int(not mount['readOnly'])
                    finally:
                        if again is not None:os.close(again)
                        if view is not None:os.close(view)
                        os.close(source)
                require(kernel_read(mountinfo,LIMITS['maximumMountinfoBytes'],budget)==before,
                    'EFFECTIVE_KERNEL_MOUNT_TABLE_CHANGED_DURING_READ')
                fresh=os.open(proc_root,os.O_PATH|os.O_DIRECTORY)
                try:require(attrs(os.fstat(fresh))[:5]==attrs(os.fstat(root))[:5]==root_frame,
                    'EFFECTIVE_PROCESS_ROOT_CHANGED_DURING_READ')
                finally:os.close(fresh)
                proofs[role]=digest({'processPin':peer['processPin'],'root':root_frame,
                    'mountinfoHash':hashlib.sha256(before).hexdigest(),'members':members})
            finally:os.close(root)
        for path,(before,static) in sources.items():
            fd=c.node(Path(path))
            try:require((attrs(os.fstat(fd))==before if static else attrs(os.fstat(fd))[:5]==before),
                'EFFECTIVE_VIEW_HOST_SOURCE_CHANGED_DURING_INTERVAL')
            finally:os.close(fd)
        require(all(kernel_read(path,LIMITS['maximumMountinfoBytes'],budget)==raw for path,raw in tables.items()),
            'EFFECTIVE_KERNEL_MOUNT_TABLE_CHANGED_DURING_INTERVAL')
        roots();require(readonly==25 and writable==4 and c.counts['engineGets']==0
            and all(attrs(Path(p).lstat())==v for p,v in seals.items()),
            'EXACT_EFFECTIVE_VIEW_SET_AND_UNCHANGED_PRIVATE_INPUTS_REQUIRED')
        self.runtime.selected.held(held);budget.check()
        return {'schema':'ouf.discovery-current-retained-mount-views.v1',
            'nativeRuntimeInputsHash':self.runtime.input_hash,'heldHistoryHash':digest(held),
            'staticCandidateHash':self.static_bytes.bindings['candidateHash'],'lifecycleContractHash':CONTRACT_HASH,
            'effectiveViewsHash':digest(proofs),'currentMountDeclarationsMatchEffectiveViews':True,
            'readonlyMounts':readonly,'writableMounts':writable,'retainedProcessCount':10,
            'directEngineGets':0,'mountedFileContentBytesRead':0,'liveMembersObservedOrAdmitted':False,
            'newCaptureScopeCreated':False,'privatePathsOrValuesPrinted':False,
            'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
            'fullCohortProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
