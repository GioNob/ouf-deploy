"""One private archive input for the exact thirteen previously observed images.

GET-only image export, never import, extraction, container execution or source
admission. Archive bytes can contain image configuration or build-time values;
they remain root-private. No mounted host file is opened for content. The six
earlier scopes stay consumed. This maintenance input grants no runtime budget.
"""
import copy,hashlib,http.client,json,os,re,shutil,socket,stat,struct,time
from pathlib import Path
from .custody_capture import attrs,decode,digest,encoded,process_pin,require,Stop
from .retained_mount_capture import RetainedCapture
from .retained_mount_role_correction import select_roles,ROSTER
from .retained_mount_intake import validate_capture
from .retained_view_intake import validate_views,CANDIDATE,CANDIDATE_HASH,RESULT_HASH
from .retained_view_capture import CASE as VIEW_CASE
from .retained_readonly_hashes import history_frames

OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-native-image-archives-9f1d571b-20261101-v1')
BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')
CASE={**copy.deepcopy(VIEW_CASE),'viewCandidatePath':str(CANDIDATE),
    'viewCandidateHash':CANDIDATE_HASH,'viewResultHash':RESULT_HASH}
PROFILE={'schema':'ouf.retained-native-image-archive-input-profile.v1','maximumAttempts':1,
    'maximumSeconds':1800,'maximumEngineGets':13,'maximumImageBytes':2147483648,
    'maximumTotalImageBytes':8589934592,'minimumInitialFreeBytes':9663676416,
    'minimumRemainingFreeBytes':1073741824,'maximumIdleSeconds':30,
    'priorControlAttempts':6,'priorDirectEngineGets':22,'maximumCumulativeControlAttempts':7,
    'maximumCumulativeDirectEngineGets':35,'automaticReplayAllowed':False,
    'oldScopesRearmedOrReset':False,'runtimeBudgetResetOrGrant':False,
    'imageConfigurationOrBuildValuesMayBePresentInPrivateArchives':True}


def preflight(scope):
    scope=Path(scope);RetainedCapture.ancestors(scope)
    require(not os.path.lexists(scope),'NATIVE_IMAGE_ARCHIVE_SCOPE_CONSUMED_NO_REPLAY')
    require(shutil.disk_usage(scope.parent).free>=PROFILE['minimumInitialFreeBytes'],
        'NATIVE_IMAGE_ARCHIVE_REQUIRES_NINE_GIB_FREE_BEFORE_SCOPE_OR_ENGINE')


class ImageCapture(RetainedCapture):
    def __init__(self,scope):
        preflight(scope);super().__init__(scope)
        # New input deadline, not a reset or continuation of any runtime clock.
        self.until=time.monotonic()+PROFILE['maximumSeconds']
        self.counts.update(imageArchivesCaptured=0,imageArchiveBytes=0)
        self.put('native-image-archive.claim.json',{'schema':'ouf.retained-native-image-archive-claim.v1',
            'caseHash':digest(CASE),'profile':PROFILE,'automaticReplayAllowed':False})


class ImageEngine:
    def __init__(self,capture,binding,images):
        require(type(binding) is dict and set(binding)=={'socketPath','socketBinding','peerCredentials'}
            and len(images)==len(set(images))==13
            and all(type(v) is str and re.fullmatch('sha256:[a-f0-9]{64}',v) for v in images),
            'EXACT_THIRTEEN_CONTENT_ADDRESSED_IMAGE_INPUTS_REQUIRED')
        self.c,self.binding=capture,copy.deepcopy(binding)
        self.allowed={'/v1.44/images/'+v+'/get' for v in images};self.used=set()

    def export(self,image,role):
        c,b=self.c,self.binding;c.guarded();path='/v1.44/images/'+image+'/get'
        require(path in self.allowed and path not in self.used
            and c.counts['engineGets']<PROFILE['maximumEngineGets'] and role in ROSTER,
            'CLOSED_SINGLE_PASS_THIRTEEN_IMAGE_GETS_REQUIRED')
        selected=Path(b['socketPath']);c.ancestors(selected);info=selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0
            and [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]==b['socketBinding'],
            'NATIVE_IMAGE_ENGINE_SOCKET_CUSTODY_CHANGED')
        class Local(http.client.HTTPConnection):
            def connect(self):
                self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                self.sock.settimeout(min(PROFILE['maximumIdleSeconds'],max(.001,c.until-time.monotonic())))
                self.sock.connect(str(selected))
                require(list(struct.unpack('3i',self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))==b['peerCredentials']
                    and b['peerCredentials'][1:]==[0,0],'NATIVE_IMAGE_ENGINE_PEER_CREDENTIALS_CHANGED')
        client=Local('exact-private-image-export');self.used.add(path);c.counts['engineGets']+=1
        filename='image-'+role+'.docker.tar';fd=None;size=0;h=hashlib.sha256()
        try:
            client.request('GET',path,headers={'Connection':'close'});reply=client.getresponse()
            require(reply.status==200 and reply.getheader('Content-Type','').split(';',1)[0].strip()=='application/x-tar',
                'SUCCESSFUL_NATIVE_IMAGE_TAR_REPLY_REQUIRED')
            length=reply.getheader('Content-Length')
            require(length is None or (length.isascii() and length.isdigit()
                and 0<int(length)<=PROFILE['maximumImageBytes']),'BOUNDED_NATIVE_IMAGE_REPLY_REQUIRED')
            fd=os.open(c.scope/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
            first=attrs(os.fstat(fd))[:6]
            while True:
                c.guarded()
                require(shutil.disk_usage(c.scope).free>=PROFILE['minimumRemainingFreeBytes'],
                    'NATIVE_IMAGE_ARCHIVE_FREE_SPACE_RESERVE_REQUIRED')
                block=reply.read1(min(1048576,PROFILE['maximumImageBytes']+1-size))
                if not block:break
                size+=len(block);c.counts['engineBytes']+=len(block);c.counts['imageArchiveBytes']+=len(block)
                require(size<=PROFILE['maximumImageBytes']
                    and c.counts['imageArchiveBytes']<=PROFILE['maximumTotalImageBytes'],
                    'BOUNDED_NATIVE_IMAGE_ARCHIVE_BYTES_REQUIRED')
                view=memoryview(block)
                while view:
                    written=os.write(fd,view);require(written>0,'COMPLETE_PRIVATE_IMAGE_ARCHIVE_WRITE_REQUIRED');view=view[written:]
                h.update(block)
            os.fsync(fd);after=attrs(os.fstat(fd))
            require(size>0 and size%512==0 and (length is None or size==int(length))
                and first==after[:6] and after==attrs((c.scope/filename).lstat())
                and after[6]==size and stat.S_IMODE(after[2])==0o400 and after[3:6]==[0,0,1],
                'COMPLETE_STABLE_PRIVATE_IMAGE_ARCHIVE_REQUIRED')
            c.seals[str(c.scope/filename)]=after;c.counts['imageArchivesCaptured']+=1;c.guarded()
            return {'imageIdRequested':image,'filename':filename,'bytes':size,'sha256':h.hexdigest(),
                'metadata':after,'nativeIdentityAndSourceAdmissionEstablished':False}
        finally:
            if fd is not None:os.close(fd)
            client.close()


def collect(c):
    case_hash=digest(CASE);view_root=Path(CASE['viewCandidatePath']).parent
    scopes={CASE['failedScope']:('capture.claim.json','result.json'),
        str(Path(CASE['candidatePath']).parent):('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json'),
        CASE['failedHashScope']:('capture.claim.json','readonly-hash-preparation.claim.json','result.json'),
        CASE['reconciliationScope']:('capture.claim.json','reconciliation.claim.json','reconciliation.private.json','result.json'),
        str(Path(CASE['staticCandidatePath']).parent):('capture.claim.json','static-custody.claim.json','static-custody.private.json','result.json'),
        str(view_root):('capture.claim.json','effective-view.claim.json','effective-views.private.json','result.json')}
    seals={}
    for root,names in scopes.items():seals.update(history_frames(root,names))
    def read(path,maximum):return decode(c.read(Path(path),0,0,0o600,maximum,'metadataReads'))
    capture=read(CASE['candidatePath'],8388608);receipt=read(CASE['resultPath'],16384);seed=read(CASE['seedPath'],2097152)
    validate_capture(capture,receipt,seed,candidate_hash=CASE['candidateHash'],result_hash=CASE['resultHash'],
        seed_hash=CASE['seedHash'],roster=ROSTER)
    views=read(CASE['viewCandidatePath'],8388608);view_result=read(view_root/'result.json',16384)
    view_case={k:v for k,v in CASE.items() if k not in ('viewCandidatePath','viewCandidateHash','viewResultHash')}
    validate_views(views,view_result,capture,candidate_hash=CASE['viewCandidateHash'],result_hash=CASE['viewResultHash'],case=view_case)
    mapping=select_roles(seed,ROSTER);images={r:seed['observations'][alias]['Image'] for r,alias in mapping.items()}
    def roots():
        c.guarded();require(digest(CASE)==case_hash and BOOT_PATH.read_text().strip()==seed['bootId']
            and set(seed['rootProcessPins'])=={'pid1','engine'} and seed['rootProcessPins']['pid1']['pid']==1
            and seed['rootProcessPins']['engine']['pid']==seed['engineBinding']['peerCredentials'][0]
            and all(process_pin(p['pid'])==p for p in seed['rootProcessPins'].values()),
            'NATIVE_IMAGE_CAPTURE_BOOT_ROOT_PROCESS_OR_CASE_CHANGED')
        require(all(attrs(Path(p).lstat())==v for p,v in {**seals,**c.seals}.items()),
            'NATIVE_IMAGE_CAPTURE_HISTORY_INPUT_OR_ARCHIVE_CHANGED')
    # Captured container identities select immutable image addresses only.
    # Container state/configuration is not freshly inspected by this input.
    roots();engine=ImageEngine(c,seed['engineBinding'],list(images.values()));archives={}
    for role,image in sorted(images.items()):
        roots();archives[role]=engine.export(image,role);roots()
    require(c.counts['engineGets']==c.counts['imageArchivesCaptured']==13
        and c.counts['mountFileContentBytesRead']==c.counts['credentialFileReads']==0,
        'EXACT_THIRTEEN_PRIVATE_ARCHIVES_AND_ZERO_HOST_CONTENT_READS_REQUIRED')
    private={'schema':'ouf.retained-native-image-archive-candidates.v1','caseHash':case_hash,'profile':PROFILE,
        'viewCandidateHash':CASE['viewCandidateHash'],'seedHash':CASE['seedHash'],'bootId':seed['bootId'],
        'archives':archives,'nativeIdentityAndSourceAdmissionEstablished':False,
        'completePrivateCustodyProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(private))<=131072,'BOUNDED_PRIVATE_IMAGE_ARCHIVE_INDEX_REQUIRED')
    roots();c.put('native-image-archives.private.json',private)
    return {'schema':'ouf.retained-native-image-archive-result.v1',
        'status':'NATIVE_IMAGE_ARCHIVE_CANDIDATES_CAPTURED_NOT_ADMITTED','candidateHash':digest(private),
        'viewCandidateHash':CASE['viewCandidateHash'],'counts':dict(c.counts),'allSixPriorScopesPreserved':True,
        'cumulativeControlAttempts':7,'cumulativeDirectEngineGets':35,
        'nativeIdentityAndSourceAdmissionEstablished':False,'currentContainerConfigurationFreshlyObserved':False,
        'mountedHostFileContentsObserved':False,'imageBytesRetainedPrivately':True,
        'privatePathsNamesValuesOrIndividualArchiveHashesPrinted':False,
        'completePrivateCustodyProven':False,'liveOwnerAuthenticated':False,'expectedPermissionOrContentPolicyEstablished':False,
        'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=ImageCapture(OUTPUT);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'NATIVE_IMAGE_ARCHIVE_INPUT_UNPROVEN'
        consumed=os.path.lexists(OUTPUT)
        result={'schema':'ouf.retained-native-image-archive-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'scopeConsumed':consumed,'counts':dict(c.counts) if c is not None else {},
            'cumulativeControlAttempts':7 if c is not None else (None if consumed else 6),
            'cumulativeDirectEngineGets':22+c.counts['engineGets'] if c is not None else (None if consumed else 22),
            'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code


if __name__=='__main__':raise SystemExit(main())
