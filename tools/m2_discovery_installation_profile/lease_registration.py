"""Register the exact installed unit and dispatch one manager reload.

No service enable/start/restart, journal initialization, signing or container
operation. Lost reload results are reconciled by manager and owned-link reads;
an exclusive durable dispatch is never retried.
"""
import copy,os,stat
from pathlib import Path
from .custody_capture import digest,encoded,require
from .lease_installation_template import recompile
from .lease_file_installation import LeaseFileInstallation,inode
from .lease_unit import path,beneath
from .lease_service import existing_kernel_lock
from .installation_lock import observed_logical_inode
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import protected_file,private_json

UNIT_DIRECTORIES=frozenset(('/etc/systemd/system','/run/systemd/system'))

def registration_scope(template,start,*,unit_directory,journal_directory):
    t=recompile(template);units=path(unit_directory);journal=path(journal_directory)
    require(units in UNIT_DIRECTORIES,
        'EXPLICIT_LOCAL_SYSTEM_MANAGER_UNIT_DIRECTORY_REQUIRED')
    roots=(t['installationRoot'],t['configurationTemplate']['ledgerRoot'],t['sandboxRoot'],start['journalDirectory'])
    require(len(Path(journal).parts)>=4 and all(not beneath(journal,p) and not beneath(p,journal) for p in (*roots,units)),
        'SEPARATE_PRIVATE_WORKER_REGISTRATION_JOURNAL_REQUIRED')
    require(start.get('schema')=='ouf.discovery-lease-manager-start-scope.v1'
        and start['installation']['templateHash']==digest(t),'SAME_REVIEWED_WORKER_MANAGER_START_REQUIRED')
    return {'schema':'ouf.discovery-worker-manager-registration-scope.v1','templateHash':digest(t),
        'startScopeHash':digest(start),'unitDirectory':units,'journalDirectory':journal,
        'unitName':start['unitName'],'manager':copy.deepcopy(start['manager']),
        'maximumDaemonReloadAttempts':1,'serviceEnableStartOrRestartAuthorized':False,
        'containerLifecycleOperationsAuthorized':False,'replaceExistingUnitAuthorized':False}


def registered_component(template,installation,registration):
    require(type(installation) is dict and installation.get('schema')=='ouf.discovery-lease-files-and-start-scope.v1',
        'EXACT_WORKER_FILES_AND_START_SCOPE_BEFORE_MANAGER_REGISTRATION_REQUIRED')
    expected=registration_scope(template,installation['start'],unit_directory=registration['unitDirectory'],
        journal_directory=registration['journalDirectory'])
    require(registration==expected and all(not beneath(registration['journalDirectory'],p)
        and not beneath(p,registration['journalDirectory']) for p in (installation['publication']['journalDirectory'],)),
        'EXACT_SEPARATELY_REVIEWED_WORKER_REGISTRATION_REQUIRED')
    return {'schema':'ouf.discovery-worker-registered-installation-and-start-scope.v1',
        'installation':copy.deepcopy(installation),'registration':copy.deepcopy(registration)}


class LeaseRegistration:
    def __init__(self,installation):
        require(type(installation) is LeaseFileInstallation and type(installation.start.registration_scope) is dict,
            'TYPED_FILE_INSTALLATION_WITH_REVIEWED_MANAGER_REGISTRATION_REQUIRED')
        self.installation=installation;self.start=installation.start
        self.scope=copy.deepcopy(self.start.registration_scope);self.scope_hash=digest(self.scope)
        self.root=Path(self.scope['journalDirectory']);self.link=Path(self.scope['unitDirectory'])/self.scope['unitName']
        self.root_pin=inode(self.root)
        self.current_scope()

    def current_scope(self):
        require(type(self.installation) is LeaseFileInstallation and self.installation.start is self.start
            and self.scope==self.start.registration_scope and digest(self.scope)==self.scope_hash
            and self.start.manager_component==registered_component(self.start.template,self.start.installation_component,self.scope)
            and self.link==Path(self.scope['unitDirectory'])/self.scope['unitName']
            and str(self.root)==self.scope['journalDirectory'],'WORKER_REGISTRATION_SCOPE_DRIFT')
        with directory(self.root) as fd:
            require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700 and inode(self.root)==self.root_pin,
                'CURRENT_PRIVATE_REGISTRATION_DIRECTORY_REQUIRED')

    def current(self,intent):
        self.current_scope();self.start.current(intent)
        c=self.start.proposal['configuration']
        protected_file(c['serviceUnitPath'],65536,expected=c['serviceUnitHash'],modes=(0o644,))
        return c

    def claim(self):
        return {'schema':'ouf.discovery-worker-manager-registration-claim.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.start.parent_hash,'childAuthorityHash':self.start.authority_hash,
            'transitionContextHash':self.start.transition.context,'intentHash':self.start.intent_hash,
            'configurationHash':digest(self.start.proposal['configuration']),
            'maximumDaemonReloadAttempts':1,'automaticReplayAllowed':False}

    def link_proof(self):
        with directory(self.link.parent):
            s=self.link.lstat()
            require(stat.S_ISLNK(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
                and os.readlink(self.link)==self.start.proposal['configuration']['serviceUnitPath'],
                'EXACT_OWNED_INSTALLED_WORKER_UNIT_LINK_REQUIRED')
            return inode(self.link)

    def manager_read(self):
        from .lease_start_owner import MANAGER_FIELDS
        raw=self.start.manager(['show',self.scope['unitName'],'--no-pager','--property='+','.join(sorted(MANAGER_FIELDS))])
        pairs=[line.split('=',1) for line in raw.decode('ascii').splitlines()]
        require(all(len(v)==2 for v in pairs) and len(pairs)==len(MANAGER_FIELDS),'EXACT_REGISTERED_WORKER_MANAGER_READ_REQUIRED')
        value=dict(pairs)
        require(set(value)==MANAGER_FIELDS and value['LoadState']=='loaded'
            and value['DropInPaths']=='' and value['NeedDaemonReload']=='no'
            and Path(value['FragmentPath']).resolve()==Path(self.start.proposal['configuration']['serviceUnitPath'])
            and value['MainPID'].isdigit() and value['ActiveState'] in ('inactive','active','activating'),
            'EXACT_RELOADED_WORKER_MANAGER_REGISTRATION_REQUIRED')
        return value

    def apply(self,intent):
        c=self.current(intent)
        outcome,_=self.installation.observe(intent)
        require(outcome=='APPLIED','COMPLETE_INITIAL_FILE_PUBLICATION_REQUIRED_BEFORE_REGISTRATION')
        with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root) as journal:
            new_file(journal,'claim.json',encoded(self.claim()))
            self.current(intent)
            with directory(self.link.parent) as unit_directory:
                os.symlink(c['serviceUnitPath'],self.link.name,dir_fd=unit_directory);os.fsync(unit_directory)
                new_file(journal,'owned-link.json',encoded({'inode':self.link_proof()}))
            self.current(intent)
            new_file(journal,'reload-dispatch.json',b'{"reloadAttempts":1}')
            self.start.manager(['daemon-reload'])
            self.current(intent);self.manager_read()
            new_file(journal,'complete.json',encoded(self.claim()))

    def observe(self,intent):
        c=self.current(intent)
        with observed_logical_inode(c['commonInvocationLock'],c['commonLockIdentity']),directory(self.root):
            if not os.path.lexists(self.root/'claim.json'):
                return 'UNKNOWN',{'ownedRegistrationClaimPresent':False,'automaticReplayAllowed':False}
            require(private_json(self.root/'claim.json')==self.claim(),'EXACT_RETAINED_REGISTRATION_CLAIM_REQUIRED')
            try:
                require(private_json(self.root/'owned-link.json')=={'inode':self.link_proof()},'WORKER_UNIT_LINK_INODE_DRIFT')
                require(protected_file(self.root/'reload-dispatch.json',64,modes=(0o600,))==b'{"reloadAttempts":1}',
                    'EXACT_OWNED_ONE_USE_MANAGER_RELOAD_REQUIRED')
                self.manager_read()
            except FileNotFoundError:
                return 'UNKNOWN',{'ownedRegistrationClaimPresent':True,'partialRegistrationPreserved':True,'automaticReplayAllowed':False}
            if os.path.lexists(self.root/'complete.json'):
                require(private_json(self.root/'complete.json')==self.claim(),'WORKER_REGISTRATION_COMMIT_DRIFT')
            self.current(intent)
            return 'APPLIED',{'schema':'ouf.discovery-worker-manager-registered.v1','scopeHash':self.scope_hash,
                'claimHash':digest(self.claim()),'ownedLinkHash':digest(private_json(self.root/'owned-link.json')),
                'serviceStartPerformed':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,
                'applicationE2EProven':False,'releaseAcceptance':False}
