#!/usr/bin/env python3
"""Publish ONLY the owner-confirmed existing draft after a fresh exact TTY review.

Installation-specific residual operation. No registration, CREATE, SQL, Engine,
token files, refresh, source acquisition or infrastructure lifecycle port.
"""
import base64
import copy
from datetime import datetime
from zoneinfo import ZoneInfo
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid

ADMIN = 'https://api.ouf-lab.it/api/trusted-human/v1/authorization'
BASE_REF = 'ouf-lab-authorization:48'
BASE_HASH = '6209fe7a832a4b92fcd543304a5480edb85f6f66dfe8476245075509e2c7f46b'
BASE_RESPONSE = '5de0b80b176ab6cbcb4b0e933d7408558731610c50521c466736d7464578ef70'
READER = '/usr/local/lib/ouf-acquisition-permission-descriptor-read-062b1e201904b9fd/read.py'
READER_HASH = '062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad'
CONTEXT = '/etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1'
ORIGINAL = '/home/oufadmin/ouf-acquisition-descriptor-publication-20261025'
LOOKUP = '/etc/ouf/deploy-snapshots/acquisition-existing-draft-lookup-5a31ae519ef9ee4e-v1'
ORIGINAL_REVIEW_HASH = '5a31ae519ef9ee4e14cf9258f91739ba27aa07a290f5f07b277cb8d3a44de911'
LOOKUP_RESULT_HASH = '8f69ddc401c1da775bfb1d3a76c4ff275b1918aaa353910171e1adf99e10843a'
CANDIDATE_HASH = '027f626dce41cac0dc2d1dd9338bd2aeb20bc474a438e6e26a68d4214271b46b'
DRAFT_ID = 'cb75ddb0-bd19-48fb-847f-1c47aff3207a'
MISSING = ('ingestion.contract.read', 'ingestion.lineage.read', 'urban.object.read',
           'lineage.object.read', 'lineage.property.read')
INHERITED = {'ownerGets':9, 'administrativeWrites':6, 'previewPosts':0, 'bytes':537123}
LIMITS = {'ownerGets':160, 'administrativeWrites':7, 'previewPosts':2,
          'responseBytes':5*1024*1024, 'totalBytes':32*1024*1024,
          'reviewAndExecutionSeconds':900, 'totalSeconds':1800,
          'readAttemptsPerStage':8, 'iamMetadataGets':1, 'iamPosts':121}


class Stop(Exception):
    pass


class Transient(Exception):
    def __init__(self, delay=0):
        self.delay = delay


def require(value, code):
    if not value:
        raise Stop(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def registration(cap):
    require(cap in MISSING or cap == 'ingestion.run.read', 'EXACT_DESCRIPTOR_REQUIRED')
    return {'ownerRef': 'ingestion' if cap.startswith('ingestion.') else 'udp',
            'descriptor': {'capabilityId': cap, 'operation': 'READ',
                           'requiredScope': cap, 'allowedActors': ['HUMAN']}}


def load_login():
    for path in ('/', '/usr', '/usr/local', '/usr/local/lib', str(Path(READER).parent)):
        info = os.lstat(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'PUBLIC_DEPENDENCY_ANCESTRY_REQUIRED')
    fd = os.open(READER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o444 and 0 < info.st_size <= 32768,
                'EXACT_PUBLIC_LOGIN_DEPENDENCY_REQUIRED')
        raw = os.read(fd, 32769)
        require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == READER_HASH,
                'PUBLIC_LOGIN_DEPENDENCY_HASH_MISMATCH')
    finally:
        os.close(fd)
    namespace = {'__name__': 'qualified_public_device_login', '__file__': READER}
    exec(compile(raw, READER, 'exec'), namespace)
    return namespace


class Journal:
    def __init__(self, path=CONTEXT):
        self.path = Path(path)
        try:
            os.mkdir(self.path, 0o700)
        except FileExistsError:
            raise Stop('PUBLICATION_SCOPE_EXISTS_RECONCILE_NO_REPLAY') from None
        os.chmod(self.path, 0o700)
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        self.row = {'schema': 'ouf.acquisition-descriptor-publication-journal.v1',
                    'state': 'CLAIMED', 'effects': {}, 'reads': {}, 'counts': dict(INHERITED),
                    'budgetReset': False, 'automaticReplayAllowed': False}
        self.save()

    def write(self, name, value, exclusive=False):
        require(name in ('state.json', 'review.json', 'result.json', 'lookup-evidence.json',
                         'initial-preview-response.json', 'publish-preview-response.json', 'owner-publish-response.json')
                or re.fullmatch(r'owner-draft-response-[0-9]{1,3}\.json', name), 'EXACT_PRIVATE_FILE_REQUIRED')
        target = self.path / name
        if exclusive:
            require(not target.exists() and not target.is_symlink(), 'PRIVATE_FILE_EXISTS')
        temporary = self.path / (name + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def save(self):
        self.write('state.json', self.row)

    def verify_review(self, expected):
        fd = os.open(self.path/'review.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 6*1024*1024,
                    'PRIVATE_REVIEW_CUSTODY_REQUIRED')
            raw = os.read(fd, 6*1024*1024+1)
            after = os.fstat(fd)
            fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            require(fields(before) == fields(after) and len(raw) == before.st_size
                    and digest(json.loads(raw)) == expected, 'PRIVATE_REVIEW_CHANGED')
        finally:
            os.close(fd)

    def effect(self, key, body):
        require(key == 'PUBLISH_DRAFT', 'ONLY_EXISTING_DRAFT_PUBLICATION_EFFECT_ALLOWED')
        require(key not in self.row['effects'], 'CONSUMED_EFFECT_NO_REPLAY')
        self.row['effects'][key] = {'state': 'CLAIMED', 'bodyHash': digest(body)}
        self.save()

    def applied(self, key):
        require(self.row['effects'][key]['state'] == 'CLAIMED', 'EXACT_CLAIM_REQUIRED')
        self.row['effects'][key]['state'] = 'APPLIED'
        self.save()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Stop('ADMIN_REDIRECT_DENIED')


class Transport:
    def __init__(self, token, journal, *, clock=time.monotonic, wall=time.time, sleep=time.sleep):
        self.token, self.journal = token, journal
        self.clock, self.wall, self.sleep = clock, wall, sleep
        self.deadline = clock() + 300
        self.counts = dict(INHERITED)
        self.plan = None
        self.review_hash = None
        self.draft = {'id': DRAFT_ID, 'revision': 0}
        self.last_headers = {}
        self.opener = urllib.request.build_opener(NoRedirect())

    def guard(self):
        require(self.clock() < self.deadline, 'FINITE_HUMAN_WINDOW_EXPIRED')
        if self.plan is not None:
            require(digest(self.plan) == self.review_hash, 'REVIEW_PLAN_CHANGED')

    def approve(self, plan):
        require(self.plan is None and self.journal.row.get('humanReviewApproved') is True
                and self.journal.row.get('reviewHash') == digest(plan), 'EXACT_TTY_REVIEW_REQUIRED')
        self.plan, self.review_hash = copy.deepcopy(plan), digest(plan)

    def request(self, path, *, method='GET', body=None, revision=None):
        self.guard()
        catalogue = path in {'/capabilities?limit=200&offset='+str(n) for n in range(0,10000,200)}
        draft_get = path == '/policies/'+DRAFT_ID
        preview = path == '/policies/'+DRAFT_ID+':preview'
        publish = path == '/policies/'+DRAFT_ID+':publish'
        require(body is None, 'RESIDUAL_REQUEST_BODY_FORBIDDEN')
        if method == 'GET':
            require(revision is None and (path == '/policies/active' or catalogue or draft_get), 'EXACT_RESIDUAL_GET_REQUIRED')
            kind = 'ownerGets'
        else:
            require(method == 'POST' and (preview or publish) and type(revision) is int and revision == 0
                    and self.journal.row.get('preflightComplete') is True, 'ONLY_EXISTING_DRAFT_PREVIEW_OR_PUBLICATION')
            if preview:
                require(self.counts['previewPosts'] == 0 or self.plan is not None, 'FRESH_TTY_REVIEW_BEFORE_FINAL_PREVIEW')
            if publish:
                require(self.plan is not None and self.journal.row.get('humanReviewApproved') is True
                        and self.journal.row['effects'].get('PUBLISH_DRAFT',{}).get('state') == 'CLAIMED'
                        and self.counts['previewPosts'] == 2 and self.counts['administrativeWrites'] == 6,
                        'ONE_APPROVED_RESIDUAL_PUBLICATION_ONLY')
            kind = 'previewPosts' if preview else 'administrativeWrites'
        require(self.counts[kind] < LIMITS[kind], 'CUMULATIVE_ADMIN_BUDGET_EXHAUSTED')
        if self.plan is not None:
            self.journal.verify_review(self.review_hash)
        self.counts[kind] += 1
        self.journal.row['counts'] = dict(self.counts); self.journal.save()
        headers = {'Authorization':'Bearer '+self.token, 'Accept':'application/json'}
        if revision is not None: headers['If-Match']='"0"'
        req = urllib.request.Request(ADMIN+path, headers=headers, method=method)
        try:
            reply = self.opener.open(req, timeout=min(20,max(.1,self.deadline-self.clock())))
        except urllib.error.HTTPError as error:
            if method == 'GET' and error.code in (408,429,502,503,504):
                value=error.headers.get('Retry-After'); delay=0
                if value is not None:
                    try:
                        delay=float(value) if value.isdigit() else parsedate_to_datetime(value).timestamp()-self.wall()
                        require(0 <= delay < 86400, 'INVALID_RETRY_AFTER')
                    except (ValueError,TypeError,OverflowError):raise Stop('INVALID_RETRY_AFTER') from None
                raise Transient(delay) from None
            # A mutating failure may contain an acknowledgement. Retain it privately
            # before status/JSON/ETag validation, including HTTPError responses.
            reply=error
        except (TimeoutError,urllib.error.URLError,OSError) as error:
            reason=getattr(error,'reason',error)
            if method == 'GET' and isinstance(reason,(TimeoutError,ConnectionError)):
                raise Transient() from None
            raise Stop('RESIDUAL_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION') from None
        with reply:
            data=reply.read(LIMITS['responseBytes']+1)
            self.last_headers=dict(reply.headers)
            if publish or preview or draft_get:
                name=('owner-publish-response.json' if publish else
                      ('initial-preview-response.json' if self.counts['previewPosts']==1 else 'publish-preview-response.json')
                      if preview else 'owner-draft-response-'+str(self.counts['ownerGets'])+'.json')
                self.journal.write(name, {'status':reply.code,
                    'etag':next((v for k,v in self.last_headers.items() if k.lower()=='etag'),None),
                    'bodyUtf8':data.decode('utf-8',errors='replace'), 'truncated':len(data)>LIMITS['responseBytes']}, exclusive=True)
            self.counts['bytes']+=len(data)
            self.journal.row['counts']=dict(self.counts);self.journal.save()
            require(reply.geturl()==ADMIN+path and 200 <= reply.code < 300,
                    'RESIDUAL_HTTP_STATUS_REQUIRES_RECONCILIATION')
            require(len(data)<=LIMITS['responseBytes'] and self.counts['bytes']<=LIMITS['totalBytes'],
                    'CUMULATIVE_RESPONSE_BUDGET_EXHAUSTED')
            try:value=json.loads(data) if data else None
            except (ValueError,UnicodeError):raise Stop('INVALID_OWNER_RESPONSE_RETAINED') from None
            return reply.code,value,self.last_headers


    def get(self, stage, path):
        require(stage not in self.journal.row['reads'], 'READ_STAGE_ALREADY_CONSUMED')
        for attempt in range(1, LIMITS['readAttemptsPerStage']+1):
            self.guard()
            self.journal.row['reads'][stage] = {'attempts': attempt, 'state': 'ATTEMPTING'}
            self.journal.save()
            try:
                status, value, _ = self.request(path)
                require(status == 200, 'ADMIN_GET_STATUS_REQUIRED')
                self.journal.row['reads'][stage]['state'] = 'COMPLETE'
                self.journal.save()
                return value
            except Transient as error:
                jitter = int(digest({'stage': stage, 'attempt': attempt})[:8], 16)/0xffffffff
                delay = max(error.delay, (5, 15, 60, 300, 900)[min(attempt-1, 4)]*(1+.2*jitter))
                require(attempt < LIMITS['readAttemptsPerStage'] and self.clock()+delay < self.deadline,
                        'ADMIN_READ_RETRY_WINDOW_EXHAUSTED')
                due = self.clock()+delay
                self.journal.row['reads'][stage].update(state='RETRY_WAIT', nextRetryAt=self.wall()+delay)
                self.journal.save()
                while self.clock() < due:
                    self.guard()
                    self.sleep(min(1, due-self.clock()))

def registered(transport, stage):
    result = {}
    for offset in range(0, 10000, 200):
        rows = transport.get(stage+':'+str(offset), '/capabilities?limit=200&offset='+str(offset))
        require(isinstance(rows, list) and len(rows) <= 200, 'BOUNDED_REGISTRATION_PAGE_REQUIRED')
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get('capability_id'), str)
                    and row['capability_id'] not in result, 'UNIQUE_REGISTRATION_REQUIRED')
            descriptor = row.get('descriptor')
            if isinstance(descriptor, dict) and descriptor.get('type') == 'jsonb':
                descriptor = descriptor.get('value')
            if isinstance(descriptor, str):
                descriptor = json.loads(descriptor)
            require(isinstance(descriptor, dict), 'REGISTRATION_DESCRIPTOR_REQUIRED')
            result[row['capability_id']] = {'ownerRef': row.get('owner_ref'), 'descriptor': descriptor}
        if len(rows) < 200:
            return result
    raise Stop('REGISTRATION_CATALOGUE_LIMIT')


def baseline(value):
    require(isinstance(value, dict) and value.get('policyRef') == BASE_REF
            and str(value.get('contentHash', '')).removeprefix('sha256:') == BASE_HASH
            and digest(value) == BASE_RESPONSE, 'EXACT_OBSERVED_ACTIVE_BASE_REQUIRED')
    policy = value.get('policy')
    require(isinstance(policy, dict) and set(policy) == {'bundleId', 'version', 'publishedAt', 'capabilities', 'grants'}
            and policy['bundleId'] == 'ouf-lab-authorization' and policy['version'] == 48
            and isinstance(policy['capabilities'], list) and isinstance(policy['grants'], list), 'EXACT_POLICY_SHAPE_REQUIRED')
    caps = {row['capabilityId']: row for row in policy['capabilities']}
    require(len(caps) == len(policy['capabilities']) and len(caps) <= 10000
            and caps.get('ingestion.run.read') == registration('ingestion.run.read')['descriptor']
            and not set(MISSING) & set(caps), 'EXACT_FIVE_ACTIVE_ADDITIONS_REQUIRED')
    return policy


def validate_preview(value, plan, draft):
    require(isinstance(value, dict) and value.get('draftId') == draft['id']
            and value.get('revision') == draft['revision'] and value.get('baseActiveRef') == BASE_REF
            and str(value.get('activeHash', '')).removeprefix('sha256:') == BASE_HASH
            and re.fullmatch(r'sha256:[a-f0-9]{64}', str(value.get('draftHash', '')))
            and value.get('authoritative') is False and value.get('removedCapabilities') == []
            and value.get('grantChanges') == []
            and sorted(value.get('addedCapabilities', []), key=lambda row: row['capabilityId'])
                == sorted([registration(cap)['descriptor'] for cap in MISSING], key=lambda row: row['capabilityId']),
            'OWNER_PREVIEW_DELTA_MISMATCH')


def ancestry(path, owner):
    for parent in Path(path).parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,owner) and not info.st_mode&0o022,
                'PROTECTED_RESIDUAL_INPUT_ANCESTRY_REQUIRED')


def private_json(path, owner, maximum=6*1024*1024):
    ancestry(path,owner)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=maximum,'EXACT_PRIVATE_RESIDUAL_INPUT_REQUIRED')
        raw=b''
        while len(raw)<=info.st_size:
            chunk=os.read(fd,min(65536,info.st_size+1-len(raw)))
            if not chunk:break
            raw+=chunk
        fields=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(raw)==info.st_size and fields(info)==fields(os.fstat(fd))==fields(os.lstat(path)),
                'RESIDUAL_INPUT_CHANGED')
        return json.loads(raw)
    finally:os.close(fd)


def retained(owner):
    review=private_json(ORIGINAL+'/review.json',owner)
    old=private_json(ORIGINAL+'/state.json',owner,131072)
    receipt=private_json(LOOKUP+'/result.json',0,65536)
    state=private_json(LOOKUP+'/state.json',0,131072)
    response=private_json(LOOKUP+'/owner-draft-response.json',0)
    require(digest(review)==ORIGINAL_REVIEW_HASH and old.get('reviewHash')==ORIGINAL_REVIEW_HASH
            and old.get('humanReviewApproved') is True and old.get('state')=='STOP_RECONCILE'
            and old.get('automaticReplayAllowed') is False and old.get('budgetReset') is False
            and old.get('counts')=={'administrativeWrites':6,'ownerGets':6,'previewPosts':0,'bytes':346780},
            'EXACT_CONSUMED_ORIGINAL_PUBLICATION_REQUIRED')
    candidate=review['candidatePolicy']
    require(digest(candidate)==CANDIDATE_HASH and len(candidate['grants'])==106
            and review['baselineGrantCount']==106 and digest(candidate['grants'])==review['baselineGrantsHash'],
            'EXACT_RETAINED_CANDIDATE_AND_ALL_GRANTS_REQUIRED')
    effects=old['effects']
    require(set(effects)=={'CREATE_DRAFT'}|{'REGISTER:'+cap for cap in MISSING}
            and effects['CREATE_DRAFT']=={'state':'CLAIMED','bodyHash':CANDIDATE_HASH}
            and all(effects['REGISTER:'+cap]['state']=='APPLIED' for cap in MISSING),
            'EXACT_REGISTERED_AND_RECONCILED_PREFIX_REQUIRED')
    require(digest(receipt)==LOOKUP_RESULT_HASH and receipt['complete'] is True and receipt['draftId']==DRAFT_ID
            and receipt['draftRevision']==0 and receipt['candidatePolicyHash']==CANDIDATE_HASH
            and receipt['counts']==INHERITED and receipt['continuationAuthorized'] is False
            and receipt['publishRequests']==0 and receipt['draftsCreated']==0
            and state['state']=='COMPLETE' and state['counts']==INHERITED and state['draftId']==DRAFT_ID
            and state['nativeSqlSessionAttempts']==state['containerExecAttempts']==1 and state['engineGets']==2,
            'EXACT_COMPLETED_LOOKUP_AND_CUMULATIVE_COUNTS_REQUIRED')
    require(response['status']==200 and response['etag']=='"0"','EXACT_RETAINED_OWNER_RESPONSE_REQUIRED')
    draft=json.loads(response['bodyUtf8'])
    validate_draft(draft,candidate,'DRAFT',0)
    historical={'lookup':receipt['iamCounts'],'originalPublication':old.get('iamCounts')}
    for value in historical.values():
        require(value is None or isinstance(value,dict) and set(value)=={'iamGets','iamPosts','ownerGets','bytes'}
                and all(type(n) is int and n>=0 for n in value.values()),'BOUNDED_HISTORICAL_IAM_COUNTS_REQUIRED')
    return review,candidate,receipt,historical


def validate_draft(value,candidate,state,revision):
    require(value=={'id':DRAFT_ID,'revision':revision,'state':state,'baseActiveRef':BASE_REF,'policy':candidate}
            and type(value.get('revision')) is int,'EXACT_OWNER_DRAFT_REQUIRED')


def read_draft(t,stage,candidate):
    value=t.get(stage,'/policies/'+DRAFT_ID)
    validate_draft(value,candidate,'DRAFT',0)
    require(next((v for k,v in t.last_headers.items() if k.lower()=='etag'),None)=='"0"',
            'EXACT_ZERO_DRAFT_ETAG_REQUIRED')
    return value


def prepare(candidate,old_review,journal,t,expires_at):
    current=t.get('baseline-active','/policies/active'); policy=baseline(current)
    require(len(policy['grants'])==106 and policy['grants']==candidate['grants']
            and digest(policy['capabilities'])==old_review['baselineCapabilitiesHash'], 'FULL_BASELINE_PRESERVATION_REQUIRED')
    expected=copy.deepcopy(policy)
    expected.update(version=49,publishedAt=candidate['publishedAt'])
    expected['capabilities'] += [registration(cap)['descriptor'] for cap in MISSING]
    require(candidate==expected and digest(candidate)==CANDIDATE_HASH,'EXACT_FIVE_DESCRIPTOR_ADDITIONS_ONLY')
    catalogue=registered(t,'baseline-registration')
    require(all(catalogue.get(cap)==registration(cap) for cap in ('ingestion.run.read',)+MISSING),
            'EXACT_SIX_REGISTERED_HUMAN_READ_DESCRIPTORS_REQUIRED')
    read_draft(t,'baseline-draft',candidate)
    require(t.get('baseline-verify','/policies/active')==current,'BASE_CHANGED_DURING_PREFLIGHT')
    journal.row['preflightComplete']=True;journal.save()
    status,preview,_=t.request('/policies/'+DRAFT_ID+':preview',method='POST',revision=0)
    require(status==200,'INITIAL_PREVIEW_ACK_REQUIRED')
    validate_preview(preview,{'candidatePolicy':candidate},t.draft)
    return {'schema':'ouf.existing-descriptor-residual-publication-review.v1','nonce':str(uuid.uuid4()),
        'account':'ouf-admin','originalReviewHash':ORIGINAL_REVIEW_HASH,'lookupResultHash':LOOKUP_RESULT_HASH,
        'draftId':DRAFT_ID,'draftRevision':0,'basePolicyRef':BASE_REF,'basePolicyHash':BASE_HASH,
        'candidatePolicyHash':CANDIDATE_HASH,'candidatePolicy':copy.deepcopy(candidate),
        'initialOwnerPreview':preview,'registrationCatalogueHash':digest(catalogue),
        'baselineGrantsHash':digest(policy['grants']),'baselineGrantCount':106,
        'inheritedCounts':dict(INHERITED),'countsAtReview':dict(t.counts),'limits':dict(LIMITS),
        'expiresAt':expires_at,'registrationAdditions':[],'draftCreations':0,
        'newAdministrativeWrites':1,'newGrants':0,'activatedDescriptorIds':list(MISSING),
        'roleCatalogueMutations':0,'iamConfigurationMutations':0,'sourceActivations':0,
        'acquisitionsExecuted':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
        'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}


def approve(plan,journal,t,*,fd=None,emit=None):
    fd=sys.stdin.fileno() if fd is None else fd
    emit=emit or (lambda s:print(s,flush=True))
    require(os.isatty(fd),'REAL_REVIEW_TTY_REQUIRED')
    journal.write('review.json',plan,exclusive=True)
    review_hash=digest(plan)
    journal.row.update(state='REVIEW_PREPARED',reviewHash=review_hash);journal.save()
    emit('Revisione privata: '+str(journal.path/'review.json'))
    emit('SOLA pubblicazione del draft ESISTENTE '+DRAFT_ID+', revisione 0: ACTIVE48 → 49.')
    emit('Cinque descrittori READ/HUMAN; tutti i106 grant, ruoli e assegnazioni preservati.')
    for cap in MISSING:
        emit('  '+cap+'; owner='+registration(cap)['ownerRef']+'; READ; scope='+cap+'; HUMAN')
    emit('Registrazioni aggiuntive:0. Draft creati:0. Grant nuovi:0. Acquisizioni:0. Registry intatto.')
    emit('Preview iniziale owner già verificata:5 aggiunte,0 rimozioni,0 variazioni grant; resta una preview prima del publish.')
    emit('Cumulativi iniziali:6 scritture/9 GET/0 preview/537123byte; massimi7 scritture/160 GET/2 preview/32MiB.')
    emit('Contatori correnti alla review: '+json.dumps(plan['countsAtReview'],sort_keys=True,separators=(',',':')))
    emit('Scadenza concreta: '+datetime.fromtimestamp(plan['expiresAt'],ZoneInfo('Europe/Rome')).isoformat()+' (Europe/Rome)')
    emit('STOP o risposta ambigua: prove conservate, nessun rilancio automatico. Nessuna accettazione E2E/release.')
    emit('Inserisci ESCLUSIVAMENTE la riga seguente, senza aggiungere testo:')
    emit('APPROVO '+review_hash)
    emit('Conferma:')
    while True:
        t.guard()
        ready,_,_=select.select([fd],[],[],min(1,max(.01,t.deadline-t.clock())))
        if ready:
            raw=os.read(fd,512)
            require(raw in (('APPROVO '+review_hash+'\n').encode(),('APPROVO '+review_hash+'\r\n').encode()),
                    'EXACT_RESIDUAL_REVIEW_NOT_APPROVED')
            break
    journal.verify_review(review_hash)
    journal.row.update(state='HUMAN_APPROVED',humanReviewApproved=True);journal.save()
    t.approve(plan)


def execute(plan,journal,t):
    require(t.review_hash==digest(plan) and journal.row.get('humanReviewApproved') is True,'FRESH_EXACT_REVIEW_REQUIRED')
    candidate=plan['candidatePolicy']
    baseline(t.get('reviewed-active','/policies/active'))
    catalogue=registered(t,'reviewed-registration')
    require(digest(catalogue)==plan['registrationCatalogueHash'],'REGISTERED_CATALOGUE_CHANGED')
    read_draft(t,'reviewed-draft',candidate)
    status,preview,_=t.request('/policies/'+DRAFT_ID+':preview',method='POST',revision=0)
    require(status==200 and preview==plan['initialOwnerPreview'],'FINAL_OWNER_PREVIEW_CHANGED')
    validate_preview(preview,plan,t.draft)
    baseline(t.get('prepublish-active','/policies/active'))
    read_draft(t,'prepublish-draft',candidate)
    journal.effect('PUBLISH_DRAFT',{'id':DRAFT_ID,'revision':0,'draftHash':preview['draftHash'],'reviewHash':digest(plan)})
    status,published,headers=t.request('/policies/'+DRAFT_ID+':publish',method='POST',revision=0)
    require(status==200,'PUBLICATION_ACK_REQUIRED')
    validate_draft(published,candidate,'PUBLISHED',1)
    require(next((v for k,v in headers.items() if k.lower()=='etag'),None)=='"1"','EXACT_PUBLISHED_ETAG_REQUIRED')
    current=t.get('published-active','/policies/active'); actual=current.get('policy',{})
    require(current.get('policyRef')=='ouf-lab-authorization:49' and actual.get('bundleId')==candidate['bundleId']
            and actual.get('version')==49 and actual.get('capabilities')==candidate['capabilities']
            and actual.get('grants')==candidate['grants'] and isinstance(actual.get('publishedAt'),str)
            and re.fullmatch(r'(sha256:)?[a-f0-9]{64}',str(current.get('contentHash',''))),
            'ACTIVE49_AND_ALL_GRANTS_NOT_PROVEN')
    journal.applied('PUBLISH_DRAFT')
    result={'schema':'ouf.existing-descriptor-residual-publication-result.v1',
        'status':'EXISTING_ACQUISITION_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED','complete':True,
        'draftId':DRAFT_ID,'draftRevision':1,'policyRef':current['policyRef'],'policyHash':current['contentHash'],
        'reviewHash':digest(plan),'originalReviewHash':ORIGINAL_REVIEW_HASH,'lookupResultHash':LOOKUP_RESULT_HASH,
        'candidatePolicyHash':CANDIDATE_HASH,'ownerDraftHash':preview['draftHash'],'candidateGrantCount':106,
        'allGrantsPreserved':True,'grantsHash':digest(actual['grants']),'activatedDescriptors':list(MISSING),
        'counts':dict(t.counts),'iamCounts':journal.row.get('iamCounts'),
        'historicalIamCounts':journal.row.get('historicalIamCounts'),'historicalNativeSqlSessions':1,
        'registrationsRepeated':0,'draftsCreated':0,'publishRequests':1,'newReadGrantsGranted':0,
        'roleCatalogueMutations':0,'iamConfigurationMutations':0,'sourceActivations':0,'acquisitionsExecuted':0,
        'engineRequests':0,'sqlSessions':0,'serviceCredentialFilesRead':0,'installationSigningKeysRead':False,
        'registryWorkerTouched':False,'humanReviewApproved':True,'runtimeAuthorityIssued':False,
        'automaticReplayAllowed':False,'budgetReset':False,'mcpOAuthScopesVerified':False,
        'applicationE2EProven':False,'releaseAcceptance':False,'contextPath':str(journal.path)}
    journal.write('result.json',result,exclusive=True)
    journal.row['state']='COMPLETE';journal.save()
    return result


def main():
    journal=None
    try:
        require(len(sys.argv)==1 and sys.stdin.isatty() and os.geteuid()==os.getegid()==0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_TTY_REQUIRED')
        operator=pwd.getpwnam('oufadmin').pw_uid
        require(operator>0 and os.environ.get('SUDO_UID')==str(operator),'EXACT_OUFADMIN_SUDO_CONTEXT_REQUIRED')
        ancestry(CONTEXT,0)
        source=Path(__file__);ancestry(source,0);info=source.lstat()
        require(source.resolve()==source and info.st_uid==0 and stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode)==0o400 and info.st_nlink==1,'PROTECTED_RESIDUAL_CODE_REQUIRED')
        journal=Journal()
        print('PrivateContext='+str(journal.path),flush=True)
        old_review,candidate,lookup,historical=retained(operator)
        journal.row['historicalIamCounts']=historical
        journal.write('lookup-evidence.json',{'lookup':lookup,'originalReviewHash':ORIGINAL_REVIEW_HASH},exclusive=True)
        journal.save()
        dependency=load_login();started=time.monotonic()
        def reserve_iam(counts):journal.row.update(iamCounts=counts);journal.save()
        iam=dependency['Transport'](reserve=reserve_iam)
        token=dependency['login'](iam)
        claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)))
        t=Transport(token,journal)
        token_deadline=time.monotonic()+max(0,claims['exp']-time.time()-15)
        t.deadline=min(t.deadline,started+LIMITS['totalSeconds'],token_deadline)
        require(t.deadline-t.clock()>60,'FRESH_PREFLIGHT_WINDOW_REQUIRED')
        # Include the true remaining token window in the review. No refresh or extension.
        expiry=min(time.time()+LIMITS['reviewAndExecutionSeconds'],time.time()+started+LIMITS['totalSeconds']-time.monotonic(),claims['exp']-15)
        plan=prepare(candidate,old_review,journal,t,expiry)
        t.deadline=min(t.clock()+max(0,expiry-time.time()),started+LIMITS['totalSeconds'],token_deadline)
        require(t.deadline-t.clock()>60,'FRESH_REVIEW_WINDOW_REQUIRED')
        plan['controllerSHA256']=hashlib.sha256(source.read_bytes()).hexdigest()
        plan['loginDependencySHA256']=READER_HASH
        approve(plan,journal,t)
        result=execute(plan,journal,t)
    except BaseException as error:
        reason=str(error) if type(error).__name__=='Stop' and re.fullmatch('[A-Z0-9_]{1,120}',str(error)) else 'PRIVATE_FAILURE_RECONCILE_NO_REPLAY'
        result={'schema':'ouf.existing-descriptor-residual-publication-result.v1','status':'STOP_RECONCILE','complete':False,
                'reasonCode':reason,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if journal is not None:
            journal.row.update(state='STOP_RECONCILE',reasonCode=reason);journal.save()
            result.update(counts=journal.row['counts'],contextPath=str(journal.path),
                          publicationClaimed='PUBLISH_DRAFT' in journal.row['effects'])
            if not (journal.path/'result.json').exists():journal.write('result.json',result,exclusive=True)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result.get('complete') else 2


if __name__=='__main__':raise SystemExit(main())
