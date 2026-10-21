"""One claimed native image load from the already qualified archive FD.

No download, archive audit/recreation, tag write, build, migration or container
operation. Existing exact images may be adopted read-only. Ambiguous load claims
are reconciled by exact image ID/config/rootfs only, never by repeating load.
"""
import copy
import os
import re
import selectors
import signal
import subprocess
import time
from urllib.parse import quote
import iam_governance_intake as governance
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest
from tools.ingestion_rollout_execution.replacement import EngineReader
from tools.ingestion_rollout_execution.database_read import empty_config_directory
from tools.ingestion_rollout_execution import private_file
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

FIELDS=('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')
LIMIT=2147483648

def validate_profile(p,packet):
    require(type(p)is dict and set(p)=={'schema','engineBinding','dockerExecutable','dockerConfigDirectory',
            'dockerConfigIdentity','archive'},'EXACT_IMAGE_IMPORT_PROFILE_REQUIRED')
    require(p['schema']=='ouf.ingestion-rollout-native-image-load.v1','QUALIFIED_NATIVE_LOAD_PROFILE_REQUIRED')
    from tools.ingestion_rollout_execution.contract import path,hashed
    engine=p['engineBinding'];require(type(engine)is dict and set(engine)=={'socketPath','socketBinding'}
            and path(engine['socketPath'])and type(engine['socketBinding'])is list and len(engine['socketBinding'])==5
            and all(type(v)is int and v>=0 for v in engine['socketBinding'])
            and engine['socketBinding'][2]==0 and engine['socketBinding'][4]in(0o600,0o660),
            'EXACT_IMAGE_IMPORT_ENGINE_BINDING_REQUIRED')
    program=p['dockerExecutable'];require(type(program)is dict and set(program)=={'path','sha256'}
            and path(program['path'])and hashed(program['sha256']),'EXACT_IMAGE_IMPORT_DOCKER_PROGRAM_REQUIRED')
    path(p['dockerConfigDirectory'])
    private_file.validate(p['archive'],maximum=LIMIT)
    require(p['archive']['metadata'][2:4]==[0,0]
            and {k:p['archive'][k]for k in('path','sha256','metadata')}==packet['candidate']['nativeArchiveBinding'],
            'SAME_ROOT_CUSTODIED_ALREADY_QUALIFIED_NATIVE_ARCHIVE_REQUIRED')
    require(type(p['dockerConfigIdentity'])is list and len(p['dockerConfigIdentity'])==5
            and all(type(v)is int and v>=0 for v in p['dockerConfigIdentity']),'EXACT_EMPTY_LOAD_CONFIG_IDENTITY_REQUIRED')
    return p

def matched(candidate,image):
    require(type(image)is dict and image.get('Id')==candidate['nativeImageId']and image.get('Os')=='linux'
            and image.get('Architecture')=='amd64','EXACT_QUALIFIED_NATIVE_IMAGE_IDENTITY_REQUIRED')
    require(image.get('RootFS')=={'Type':'layers','Layers':candidate['rootfs']['diff_ids']}
            and candidate['rootfs']['type']=='layers','QUALIFIED_IMAGE_ROOTFS_CHANGED')
    require(type(image.get('Config'))is dict and all(image['Config'].get(k)==candidate['imageConfig'].get(k)for k in FIELDS)
            and image['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==candidate['sourceCommit'],
            'QUALIFIED_IMAGE_EXECUTION_CONFIG_CHANGED')
    return {'qualifiedNativeImageMatched':True,'imageId':candidate['nativeImageId'],
            'configurationImageId':candidate['configurationImageId'],'rootfsLayerCount':len(candidate['rootfs']['diff_ids']),
            'archiveRecreated':False,'archiveAuditReplayed':False,'repositoryTagWritesRequested':False}

def load(arguments,fd):
    process=subprocess.Popen(arguments,stdin=fd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env={'LC_ALL':'C'},start_new_session=True)
    counts={'out':0,'err':0};deadline=time.monotonic()+180
    try:
        with selectors.DefaultSelector()as watch:
            watch.register(process.stdout,selectors.EVENT_READ,'out');watch.register(process.stderr,selectors.EVENT_READ,'err')
            while watch.get_map():
                require(time.monotonic()<deadline,'FINITE_NATIVE_IMAGE_LOAD_TIMEOUT')
                for key,_ in watch.select(min(.2,max(0,deadline-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:watch.unregister(key.fileobj);continue
                    counts[key.data]+=len(raw);require(counts[key.data]<=65536,'BOUNDED_IMAGE_LOAD_OUTPUT_REQUIRED')
            code=process.wait(timeout=max(.01,deadline-time.monotonic()))
        require(code==0,'NATIVE_IMAGE_LOAD_OUTCOME_UNKNOWN_RECONCILE_ONLY')
    finally:
        if process.poll()is None:os.killpg(process.pid,signal.SIGKILL)
        process.wait(timeout=5);process.stdout.close();process.stderr.close()

class NativeImageImport:
    def __init__(self,action,journal,review,packet,human,reader):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(reader)is EngineReader,'CONCRETE_SIGNED_IMAGE_IMPORT_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human,self.reader=action,journal,human,reader
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet);self.scope=scope(self.review)
        self.profile=copy.deepcopy(review.get('imageImportProfile'));validate_profile(self.profile,self.packet)
        require(digest(packet)==review['packetBinding']['sha256']and str(journal.root)==review['executionContext'],
                'SAME_PACKET_AND_PRIVATE_IMAGE_IMPORT_CONTEXT_REQUIRED')
        self.index=[s['name']for s in review['stages']].index('IMPORT_INGESTION_IMAGE');self.stage=review['stages'][self.index]
    def guard(self):
        require(scope(self.review)==self.scope and self.profile==self.review['imageImportProfile']
                and digest(self.packet)==self.review['packetBinding']['sha256'],'IMAGE_IMPORT_REVIEW_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read();require(row.get('scopeHash')==digest(self.scope)
            and row.get('authorityHash')==self.action.authority_hash and row.get('budgetReset')is False
            and row['nextStage']==self.index and len(row['effects'])==self.index+1
            and all(e['state']=='APPLIED'for e in row['effects'][:self.index]),'ORDERED_NATIVE_IMAGE_IMPORT_CLAIM_REQUIRED')
        effect=row['effects'][self.index]
        require(effect['stage']==self.stage['name']and effect['intentHash']==self.stage['intentHash']
                and effect['state']=='CLAIMED','SAME_CLAIMED_IMAGE_IMPORT_INTENT_REQUIRED')
        engine=self.profile['engineBinding'];self.reader.engine.check_socket()
        require(self.reader.engine.path==engine['socketPath']and list(self.reader.engine.binding)==engine['socketBinding'],
                'SAME_NATIVE_IMAGE_IMPORT_ENGINE_REQUIRED')
        program=self.profile['dockerExecutable'];require(program==governance.executable(program['path']),'IMAGE_IMPORT_DOCKER_PROGRAM_CHANGED')
        require(empty_config_directory(self.profile['dockerConfigDirectory'])==self.profile['dockerConfigIdentity'],
                'EMPTY_IMAGE_IMPORT_DOCKER_CONFIG_CHANGED')
        private_file.check_metadata(self.profile['archive'],maximum=LIMIT)
        return row,effect
    def image(self):
        self.guard();engine=self.reader.engine;image=self.packet['candidate']['nativeImageId']
        status,value=engine.request('GET','/v1.44/images/'+quote(image,safe='')+'/json');self.guard()
        if status==404:return None
        require(status==200,'EXACT_CANDIDATE_NATIVE_IMAGE_READ_REQUIRED');matched(self.packet['candidate'],value)
        return value
    def mark(self,key):
        row,effect=self.guard()
        require(not effect.get('nativeImageImportAttempted',False)and not effect.get('nativeImageAlreadyPresent',False),
                'NATIVE_IMAGE_IMPORT_RESERVED_RECONCILE_NO_REPLAY')
        effects=copy.deepcopy(row['effects']);effects[-1][key]=True
        self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1});self.guard()
    def apply(self):
        row,effect=self.guard()
        require(not effect.get('nativeImageImportAttempted',False)and not effect.get('nativeImageAlreadyPresent',False),
                'NATIVE_IMAGE_IMPORT_ALREADY_CLAIMED_NO_REPLAY')
        if self.image()is not None:self.mark('nativeImageAlreadyPresent');return
        row,effect=self.guard()
        require(min(row['expiresAt']-time.time(),row['expiresMonotonic']-time.monotonic())>210,'CURRENT_FINITE_IMAGE_IMPORT_WINDOW_REQUIRED')
        with private_file.opened(self.profile['archive'],maximum=LIMIT)as fd:
            self.guard();self.mark('nativeImageImportAttempted')
            argv=[self.profile['dockerExecutable']['path'],'--host','unix://'+self.profile['engineBinding']['socketPath'],
                  '--config',self.profile['dockerConfigDirectory'],'load']
            load(argv,fd);self.guard()
    def observe(self):
        _,effect=self.guard()
        if not(effect.get('nativeImageImportAttempted')is True or effect.get('nativeImageAlreadyPresent')is True):return 'UNKNOWN',{}
        image=self.image()
        if image is None:return 'UNKNOWN',{}
        return 'APPLIED',{**matched(self.packet['candidate'],image),
            'importAttemptedByThisAction':effect.get('nativeImageImportAttempted',False),
            'existingQualifiedImageAdopted':effect.get('nativeImageAlreadyPresent',False)}
