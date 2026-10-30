"""Selected Registry/MCP imports under the existing discovery parent.

Reuses the existing archive/native identity and one-use Import owner. The other
cohort sections have separate owners; neither an import receipt nor this class
proves their admission, capability publication or CSV application acceptance.
Historical five-image intake/authority/source bytes remain unchanged.
"""
import copy,re,subprocess
from pathlib import Path
from .custody_capture import digest,encoded,require
from .parent_authority import DiscoveryParentAuthority
from .gate_peer_window import GatePeerWindow
from engine_creation import Engine
from image_custody import archive,loaded,runtime_image_id,unbound_audit
from image_import import Import
from tools.chatbot_file_cohort.images import private_open,engine_image_profile
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_registry_operational_owner.installation import directory,new_file
from tools.semantic_registry_operational_owner.guard import private_json,protected_file

MODULES=('semantic','mcp')
PLAN='ouf.discovery-selected-image-import-plan.v1'
COMPONENT='ouf.discovery-cohort-installation-scope.v1'

def hashed(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def image_scope(plan):
    fields={'schema','registryCreationRequestHash','cohortManifestHash','images','nativeEngineProfile','dockerBinding','journalDirectories',
        'maximumImportSecondsPerImage','maximumImportAttemptsPerImage','retagAllowed','automaticReplayAllowed','runtimeAuthorityIssued'}
    require(type(plan) is dict and set(plan)==fields and plan['schema']==PLAN
        and hashed(plan['registryCreationRequestHash']) and hashed(plan['cohortManifestHash'])
        and type(plan['images']) is list and [r.get('module') for r in plan['images']]==list(MODULES)
        and plan['maximumImportSecondsPerImage']==180 and plan['maximumImportAttemptsPerImage']==1
        and all(plan[k] is False for k in ('retagAllowed','automaticReplayAllowed','runtimeAuthorityIssued')),
        'EXACT_TWO_SELECTED_DISCOVERY_IMAGE_IMPORTS_REQUIRED')
    docker=plan['dockerBinding'];roots=plan['journalDirectories']
    require(type(docker) is dict and set(docker)=={'path','sha256'} and hashed(docker['sha256'])
        and Path(docker['path']).is_absolute() and str(Path(docker['path']))==docker['path'] and '..' not in Path(docker['path']).parts
        and type(roots) is dict and set(roots)==set(MODULES)
        and all(type(p) is str and Path(p).is_absolute() and str(Path(p))==p and '..' not in Path(p).parts for p in roots.values())
        and all(not Path(a).is_relative_to(b) and not Path(b).is_relative_to(a)
            for i,a in enumerate(roots.values()) for b in list(roots.values())[i+1:])
        and len(encoded(plan))<=262144,'EXACT_REVIEWED_DOCKER_AND_DISTINCT_IMAGE_JOURNALS_REQUIRED')
    identities={}
    for row in plan['images']:
        require(set(row)=={'module','archivePath','audit','originalArchiveSha256','modulePackageHash'}
            and all(hashed(row[k]) for k in ('originalArchiveSha256','modulePackageHash'))
            and Path(row['archivePath']).is_absolute() and '..' not in Path(row['archivePath']).parts
            and type(row['audit']) is dict and row['audit']['repositoryTags']==[],
            'EXACT_TAGLESS_IMAGE_ARCHIVE_AND_PACKAGE_BINDINGS_REQUIRED')
        identities[row['module']]=runtime_image_id(row['audit'])
    require(len(set(identities.values()))==2,'TWO_DISTINCT_DISCOVERY_IMAGES_REQUIRED')
    return {'schema':'ouf.discovery-selected-image-import-scope.v1','planHash':digest(plan),
        'cohortManifestHash':plan['cohortManifestHash'],'registryCreationRequestHash':plan['registryCreationRequestHash'],
        'imageIds':identities,'dockerBindingHash':digest(docker),'journalDirectoryHash':digest(roots),
        'imageCount':2,'maximumImportAttemptsPerImage':1,
        'maximumImportSecondsPerImage':180,'retagAllowed':False,'automaticReplayAllowed':False}

def checked_component(parent,scope):
    component=parent.review['components']['cohortInstallation']
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','images','mcp',
        'gatewayRuntime','currentAdmission','requiresFullCurrentCohortBeforeRelease','automaticReplayAllowed','budgetReset'}
    require(type(component) is dict and set(component)==fields and component['schema']==COMPONENT
        and all(component[k]==parent.scope[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash'))
        and component['images']==scope and all(type(component[k]) is dict and bool(component[k])
            for k in ('mcp','gatewayRuntime','currentAdmission'))
        and component['requiresFullCurrentCohortBeforeRelease'] is True
        and component['automaticReplayAllowed'] is component['budgetReset'] is False,
        'EXACT_PARENT_COHORT_IMAGE_SECTION_AND_SEPARATE_COHORT_OWNERS_REQUIRED')
    # Other owners validate the exact contents of their own reviewed sections.
    return copy.deepcopy(component)

class DiscoveryImages:
    def __init__(self,*,window,plan,journals,docker_binding):
        require(type(window) is GatePeerWindow and type(window.parent) is DiscoveryParentAuthority
            and type(window.engine) is Engine and type(journals) is dict and set(journals)==set(MODULES)
            and all(type(j) is Journal for j in journals.values()),'TYPED_CURRENT_PARENT_AND_TWO_IMAGE_JOURNALS_REQUIRED')
        self.window,self.parent,self.engine=window,window.parent,window.engine
        self.parent_hash=self.parent.sha;self.plan=copy.deepcopy(plan);self.scope=image_scope(plan)
        require(plan['registryCreationRequestHash']==window.request_hash
            and self.scope['imageIds']['semantic']==window.request['Image'],
            'SAME_REGISTRY_CREATION_REQUEST_AND_IMPORTED_IMAGE_REQUIRED')
        self.component=checked_component(self.parent,self.scope);self.component_hash=digest(self.component)
        require(self.component['mcp'].get('imageId')==self.scope['imageIds']['mcp'],
            'SAME_IMPORTED_MCP_IMAGE_AND_REVIEWED_REPLACEMENT_REQUIRED')
        self.journals=dict(journals);self.journal_ids={k:id(j) for k,j in journals.items()}
        self.docker=copy.deepcopy(docker_binding)
        require(type(self.docker) is dict and set(self.docker)=={'path','sha256'} and hashed(self.docker['sha256'])
            and Path(self.docker['path']).is_absolute() and '..' not in Path(self.docker['path']).parts,
            'EXPLICIT_APPROVED_DISCOVERY_DOCKER_EXECUTABLE_REQUIRED')
        require(self.docker==plan['dockerBinding'] and {k:str(j.root) for k,j in journals.items()}==plan['journalDirectories'],
            'SAME_REVIEWED_IMAGE_EXECUTABLE_AND_JOURNAL_DIRECTORIES_REQUIRED')

    def guard(self,phase=None):
        require(self.window.parent is self.parent and self.window.engine is self.engine and self.parent.sha==self.parent_hash
            and self.scope==image_scope(self.plan) and self.component==checked_component(self.parent,self.scope)
            and digest(self.component)==self.component_hash and set(self.journals)==set(MODULES)
            and self.docker==self.plan['dockerBinding']
            and {k:str(j.root) for k,j in self.journals.items()}==self.plan['journalDirectories']
            and all(id(self.journals[k])==v for k,v in self.journal_ids.items()),'DISCOVERY_IMAGE_OWNER_OR_SCOPE_DRIFT')
        self.window.sealed();self.parent.registry_child(self.window.child,self.window.raw)
        self.parent.guard('cohortInstallation',self.component);self.engine.check_socket()
        require(engine_image_profile(self.engine)==self.plan['nativeEngineProfile'],'CURRENT_DISCOVERY_NATIVE_IMAGE_STORE_REQUIRED')
        protected_file(self.docker['path'],67108864,expected=self.docker['sha256'],modes=(0o755,))
        return self.parent.sha

    def inspect(self,image_id):
        self.guard();require(image_id in self.scope['imageIds'].values(),'SELECTED_DISCOVERY_IMAGE_ONLY')
        code,value=self.engine.request('GET','/v1.44/images/'+image_id+'/json')
        require(code in (200,404),'CURRENT_DISCOVERY_IMAGE_READ_REQUIRED')
        return value if code==200 else None

    def initialize(self):
        self.guard()
        for row in self.plan['images']:
            self.journals[row['module']].initialize(Import.initial(row['audit'],self.parent.sha))

    def load(self,row):
        self.guard();require(row in self.plan['images'],'EXACT_REVIEWED_DISCOVERY_IMAGE_ROW_REQUIRED')
        journal=self.journals[row['module']];initial=Import.initial(row['audit'],self.parent.sha)
        record=Import(journal,initial['contextHash']).read(row['audit'])
        require(record['state']=='IN_FLIGHT' and record['effectAttemptCount']==1,'CONSUMED_IMAGE_IMPORT_DISPATCH_REQUIRED')
        with private_open(row['archivePath']) as source:
            require(archive(source,row['audit']['archiveSha256'],row['audit']['imageId'],row['audit']['sourceCommit'])
                ==unbound_audit(row['audit']),'CURRENT_SELECTED_IMAGE_ARCHIVE_CUSTODY_REQUIRED')
            source.seek(0);self.guard()
            claim={'schema':'ouf.discovery-image-load-dispatch.v1','contextHash':initial['contextHash'],
                'authorityHash':self.parent.sha,'imageId':runtime_image_id(row['audit']),
                'archiveHash':row['audit']['archiveSha256'],'attempt':1,'automaticReplayAllowed':False}
            with directory(journal.root) as fd:new_file(fd,'image-load-dispatch.json',encoded(claim))
            require(private_json(journal.root/'image-load-dispatch.json')==claim and journal.read()==record,
                'EXACT_DURABLE_IMAGE_LOAD_DISPATCH_AND_INVOKING_RECORD_REQUIRED')
            self.guard()
            result=subprocess.run([self.docker['path'],'--host','unix://'+self.engine.path,'--config',str(journal.root),'load'],
                stdin=source,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_API_VERSION':'1.44'})
            require(result.returncode==0,'DISCOVERY_IMAGE_IMPORT_OUTCOME_REQUIRES_RECONCILIATION')
        self.guard()

    def apply(self):
        self.guard();evidence=[]
        for row in self.plan['images']:
            journal=self.journals[row['module']];initial=Import.initial(row['audit'],self.parent.sha)
            owner=Import(journal,initial['contextHash'])
            with owner.invocation():
                state=owner.read(row['audit'])
                if state['state']=='READY':proof=owner.import_once(row['audit'],lambda:self.load(row),self.inspect,self.guard)
                elif state['state']=='IN_FLIGHT':proof=owner.reconcile(row['audit'],self.inspect,self.guard)
                else:
                    proof=loaded(row['audit'],self.inspect(runtime_image_id(row['audit'])))
                    require(digest(proof)==state['nativeEvidenceHash'],'CURRENT_VERIFIED_DISCOVERY_IMAGE_EVIDENCE_REQUIRED')
                evidence.append({'module':row['module'],'evidenceHash':digest(proof)})
        return {'schema':'ouf.discovery-selected-image-import-receipt.v1','scopeHash':digest(self.scope),'images':evidence,
            'fullCohortProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
