#!/usr/bin/env python3
"""Exact HUMAN additive descriptor publication; grants and roles are not edited.

Existing public reader code supplies the qualified in-memory device login only.
No old reader main, scope, credential, signing key, Engine or IAM-admin access.
Every mutation is reserved durably and is never automatically retried.
"""
import copy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import select
import ssl
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
CONTEXT = '/home/oufadmin/ouf-acquisition-descriptor-publication-20261025'
MISSING = ('ingestion.contract.read', 'ingestion.lineage.read', 'urban.object.read',
           'lineage.object.read', 'lineage.property.read')
LIMITS = {'ownerGets': 160, 'administrativeWrites': 7, 'previewPosts': 2,
          'responseBytes': 5*1024*1024, 'totalBytes': 32*1024*1024,
          'reviewAndExecutionSeconds': 900, 'totalSeconds': 1800,
          'readAttemptsPerStage': 8, 'iamMetadataGets': 1, 'iamPosts': 121}


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
                    'state': 'CLAIMED', 'effects': {}, 'reads': {}, 'counts': {},
                    'budgetReset': False, 'automaticReplayAllowed': False}
        self.save()

    def write(self, name, value, exclusive=False):
        require(name in ('state.json', 'review.json', 'result.json'), 'EXACT_PRIVATE_FILE_REQUIRED')
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
        self.counts = {'ownerGets': 0, 'administrativeWrites': 0, 'previewPosts': 0, 'bytes': 0}
        self.plan = None
        self.review_hash = None
        self.draft = None
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
        catalogue = path in {'/capabilities?limit=200&offset='+str(n) for n in range(0, 10000, 200)}
        draft_get = self.draft is not None and path == '/policies/'+self.draft['id']
        preview = self.draft is not None and path == '/policies/'+self.draft['id']+':preview'
        publish = self.draft is not None and path == '/policies/'+self.draft['id']+':publish'
        if method == 'GET':
            require(body is None and revision is None and (path == '/policies/active' or catalogue or draft_get),
                    'EXACT_ADMIN_READ_REQUIRED')
            kind = 'ownerGets'
        else:
            require(method == 'POST' and self.plan is not None, 'APPROVED_ADMIN_POST_REQUIRED')
            if path == '/capabilities':
                require(body in self.plan['registrationAdditions'] and revision is None,
                        'EXACT_REGISTRATION_BODY_REQUIRED')
            elif path == '/policies':
                require(body == self.plan['candidatePolicy'] and revision is None, 'EXACT_CANDIDATE_REQUIRED')
            else:
                require((preview or publish) and body is None and revision == self.draft['revision'],
                        'EXACT_DRAFT_OPERATION_REQUIRED')
            kind = 'previewPosts' if preview else 'administrativeWrites'
        require(self.counts[kind] < LIMITS[kind], 'ADMIN_REQUEST_BUDGET_EXHAUSTED')
        if self.plan is not None:
            self.journal.verify_review(self.review_hash)
        self.counts[kind] += 1
        self.journal.row['counts'] = dict(self.counts)
        self.journal.save()  # dispatch reservation is durable, also on lost responses
        headers = {'Authorization': 'Bearer '+self.token, 'Accept': 'application/json'}
        raw = None if body is None else json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
        require(raw is None or len(raw) <= LIMITS['responseBytes'], 'BOUNDED_ADMIN_BODY_REQUIRED')
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        if revision is not None:
            headers['If-Match'] = '"'+str(revision)+'"'
        request = urllib.request.Request(ADMIN+path, data=raw, headers=headers, method=method)
        try:
            reply = self.opener.open(request, timeout=min(20, max(.1, self.deadline-self.clock())))
        except urllib.error.HTTPError as error:
            if method == 'GET' and error.code in (408, 429, 502, 503, 504):
                value = error.headers.get('Retry-After')
                delay = 0
                if value is not None:
                    try:
                        delay = float(value) if value.isdigit() else parsedate_to_datetime(value).timestamp()-self.wall()
                        require(delay >= 0 and delay < 86400, 'INVALID_RETRY_AFTER')
                    except (ValueError, TypeError, OverflowError):
                        raise Stop('INVALID_RETRY_AFTER') from None
                raise Transient(delay) from None
            raise Stop('ADMIN_HTTP_'+str(error.code)+'_NO_AUTOMATIC_REPLAY') from None
        except (TimeoutError, urllib.error.URLError) as error:
            reason = getattr(error, 'reason', error)
            if method == 'GET' and isinstance(reason, (TimeoutError, ConnectionError)):
                raise Transient() from None
            raise Stop('ADMIN_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION') from None
        with reply:
            require(reply.geturl() == ADMIN+path, 'ADMIN_REDIRECT_DENIED')
            data = reply.read(LIMITS['responseBytes']+1)
            self.counts['bytes'] += len(data)
            self.journal.row['counts'] = dict(self.counts)
            self.journal.save()
            require(len(data) <= LIMITS['responseBytes'] and self.counts['bytes'] <= LIMITS['totalBytes'],
                    'ADMIN_RESPONSE_BUDGET_EXHAUSTED')
            try:
                value = json.loads(data) if data else None
            except (ValueError, UnicodeError):
                raise Stop('INVALID_ADMIN_RESPONSE') from None
            return reply.code, value, dict(reply.headers)

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


def prepare(active, catalogue, expires_at):
    policy = baseline(active)
    for cap in ('ingestion.run.read',)+MISSING:
        if cap in catalogue:
            require(catalogue[cap] == registration(cap), 'REGISTERED_DESCRIPTOR_SEMANTICS_CONFLICT')
    require(catalogue.get('ingestion.run.read') == registration('ingestion.run.read'), 'EXISTING_RUN_DESCRIPTOR_REQUIRED')
    candidate = copy.deepcopy(policy)
    candidate.update(version=49, publishedAt=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
    candidate['capabilities'] += [registration(cap)['descriptor'] for cap in MISSING]
    return {'schema': 'ouf.acquisition-descriptor-publication-review.v1', 'nonce': str(uuid.uuid4()),
            'account': 'ouf-admin', 'basePolicyRef': BASE_REF, 'basePolicyHash': BASE_HASH,
            'baseResponseHash': BASE_RESPONSE, 'expiresAt': expires_at, 'limits': copy.deepcopy(LIMITS),
            'registrationAdditions': [registration(cap) for cap in MISSING if cap not in catalogue],
            'activatedDescriptorIds': list(MISSING), 'candidatePolicy': candidate,
            'baselineCapabilitiesHash': digest(policy['capabilities']), 'baselineGrantsHash': digest(policy['grants']),
            'baselineGrantCount': len(policy['grants']), 'newGrants': 0, 'roleCatalogueMutations': 0,
            'iamConfigurationMutations': 0, 'sourceActivations': 0, 'acquisitionsExecuted': 0,
            'applicationE2EProven': False, 'releaseAcceptance': False}


def approve(plan, journal, transport, *, fd=None, emit=None):
    fd = sys.stdin.fileno() if fd is None else fd
    emit = emit or (lambda value: print(value, flush=True))
    require(os.isatty(fd), 'REAL_REVIEW_TTY_REQUIRED')
    journal.write('review.json', plan, exclusive=True)
    review_hash = digest(plan)
    journal.row.update(state='REVIEW_PREPARED', reviewHash=review_hash)
    journal.save()
    emit('Revisione privata: '+str(journal.path/'review.json'))
    emit('Solo '+str(len(plan['registrationAdditions']))+' registrazioni READ/HUMAN e pubblicazione ACTIVE48→49 dei cinque descrittori.')
    for cap in MISSING:
        emit('  '+cap+'; owner='+registration(cap)['ownerRef']+'; READ; requiredScope='+cap+'; HUMAN')
    emit('Tutti i '+str(plan['baselineGrantCount'])+' grant esistenti, ruoli e assegnazioni conservati; nessun grant READ nuovo.')
    emit('Nessuna modifica IAM/Engine/fonte/acquisizione. Esito ambiguo: STOP e prove conservate, senza rilancio.')
    emit('Massimi: 5 registrazioni, 1 draft, 2 preview, 1 pubblicazione; 160 GET; 32 MiB cumulativi.')
    emit('Scadenza revisione/esecuzione: '+datetime.fromtimestamp(plan['expiresAt'], timezone.utc).isoformat())
    emit('Per approvare questa sola revisione, inserisci esattamente la riga seguente:')
    emit('APPROVO '+review_hash)
    emit('Conferma:')
    while True:
        transport.guard()
        ready, _, _ = select.select([fd], [], [], min(1, transport.deadline-transport.clock()))
        if ready:
            raw = os.read(fd, 512)
            require(raw in (('APPROVO '+review_hash+'\n').encode(), ('APPROVO '+review_hash+'\r\n').encode()),
                    'EXACT_DESCRIPTOR_PUBLICATION_REVIEW_NOT_APPROVED')
            break
    journal.row.update(state='HUMAN_APPROVED', humanReviewApproved=True)
    journal.verify_review(review_hash)
    journal.save()
    transport.approve(plan)


def validate_draft(value, plan, state='DRAFT'):
    require(isinstance(value, dict) and isinstance(value.get('id'), str)
            and str(uuid.UUID(value['id'])) == value['id'] and type(value.get('revision')) is int
            and value['revision'] >= 1 and value.get('state') == state and value.get('baseActiveRef') == BASE_REF
            and value.get('policy') == plan['candidatePolicy'], 'EXACT_OWNER_DRAFT_REQUIRED')


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


def execute(plan, catalogue, journal, transport):
    require(journal.row.get('humanReviewApproved') is True and transport.review_hash == digest(plan), 'HUMAN_APPROVAL_REQUIRED')
    transport.guard()
    baseline(transport.get('approved-active', '/policies/active'))
    for row in plan['registrationAdditions']:
        key = 'REGISTER:'+row['descriptor']['capabilityId']
        journal.effect(key, row)
        status, _, _ = transport.request('/capabilities', method='POST', body=row)
        require(status == 201, 'REGISTRATION_ACK_REQUIRED')
        # Remain CLAIMED until the independent registration read-back succeeds.
    after_reg = registered(transport, 'registration-readback')
    require(all(after_reg.get(cap) == value for cap, value in catalogue.items())
            and all(after_reg.get(cap) == registration(cap) for cap in MISSING), 'REGISTRATION_READBACK_MISMATCH')
    for row in plan['registrationAdditions']:
        journal.applied('REGISTER:'+row['descriptor']['capabilityId'])
    baseline(transport.get('before-draft-active', '/policies/active'))
    journal.effect('CREATE_DRAFT', plan['candidatePolicy'])
    status, draft, headers = transport.request('/policies', method='POST', body=plan['candidatePolicy'])
    require(status == 200, 'DRAFT_ACK_REQUIRED')
    validate_draft(draft, plan)
    etag = next((value for key, value in headers.items() if key.lower() == 'etag'), None)
    require(etag == '"'+str(draft['revision'])+'"', 'EXACT_DRAFT_ETAG_REQUIRED')
    transport.draft = {'id': draft['id'], 'revision': draft['revision']}
    journal.row.update(draftId=draft['id'], draftRevision=draft['revision'])
    journal.applied('CREATE_DRAFT')
    observed = transport.get('draft-readback', '/policies/'+draft['id'])
    validate_draft(observed, plan)
    require(observed['revision'] == draft['revision'], 'DRAFT_REVISION_CHANGED')
    for stage in ('initial-preview', 'publish-preview'):
        if stage == 'publish-preview':
            baseline(transport.get('before-publish-active', '/policies/active'))
        status, preview, _ = transport.request('/policies/'+draft['id']+':preview', method='POST', revision=draft['revision'])
        require(status == 200, 'PREVIEW_ACK_REQUIRED')
        validate_preview(preview, plan, draft)
        if stage == 'initial-preview':
            journal.row['ownerDraftHash'] = preview['draftHash']
            journal.save()
        else:
            require(preview['draftHash'] == journal.row['ownerDraftHash'], 'OWNER_DRAFT_HASH_CHANGED')
    journal.effect('PUBLISH_DRAFT', {'id': draft['id'], 'revision': draft['revision'], 'draftHash': journal.row['ownerDraftHash']})
    status, published, _ = transport.request('/policies/'+draft['id']+':publish', method='POST', revision=draft['revision'])
    require(status == 200, 'PUBLICATION_ACK_REQUIRED')
    validate_draft(published, plan, state='PUBLISHED')
    require(published['revision'] == draft['revision']+1, 'PUBLICATION_REVISION_REQUIRED')
    current = transport.get('published-active', '/policies/active')
    candidate, actual = plan['candidatePolicy'], current.get('policy', {})
    require(current.get('policyRef') == 'ouf-lab-authorization:49'
            and actual.get('bundleId') == candidate['bundleId'] and actual.get('version') == 49
            and actual.get('capabilities') == candidate['capabilities'] and actual.get('grants') == candidate['grants']
            and isinstance(actual.get('publishedAt'), str) and isinstance(current.get('contentHash'), str),
            'PUBLISHED_ACTIVE_PRESERVATION_NOT_PROVEN')
    journal.applied('PUBLISH_DRAFT')
    result = {'schema': 'ouf.acquisition-descriptor-publication-result.v1',
              'status': 'ACQUISITION_READ_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED', 'complete': True,
              'policyRef': current['policyRef'], 'policyHash': current['contentHash'],
              'reviewHash': digest(plan), 'ownerDraftHash': journal.row['ownerDraftHash'],
              'draftId': draft['id'], 'registeredByThisOperation': len(plan['registrationAdditions']),
              'activatedDescriptors': list(MISSING), 'preexistingDescriptorsPreserved': True,
              'allGrantsPreserved': True, 'grantsHash': digest(actual['grants']),
              'roleCatalogueMutations': 0, 'iamConfigurationMutations': 0,
              'mcpOAuthScopesVerified': False, 'newReadGrantsGranted': 0,
              'counts': dict(transport.counts), 'iamCounts': journal.row.get('iamCounts'),
              'humanReviewApproved': True, 'automaticReplayAllowed': False, 'budgetReset': False,
              'runtimeAuthorityIssued': False, 'sourceActivations': 0, 'acquisitionsExecuted': 0,
              'engineRequests': 0, 'newCredentialFileReads': 0, 'registryWorkerTouched': False,
              'applicationE2EProven': False, 'releaseAcceptance': False}
    journal.row['state'] = 'COMPLETE'
    journal.save()
    journal.write('result.json', result, exclusive=True)
    return result


def main():
    require(len(sys.argv) == 1 and sys.stdin.isatty() and os.geteuid() != 0, 'INTERACTIVE_OPERATOR_NOT_ROOT_REQUIRED')
    dependency = load_login()
    journal = Journal()
    print('Directory='+str(journal.path), flush=True)
    started = time.monotonic()
    try:
        def reserve_iam(counts):
            journal.row['iamCounts'] = counts
            journal.save()
        iam = dependency['Transport'](reserve=reserve_iam)
        try:
            token = dependency['login'](iam)
        except dependency['Stop']:
            raise Stop('QUALIFIED_HUMAN_LOGIN_STOP') from None
        # Context was already checked by qualified login and is verified by the owner on every call.
        import base64
        claims = json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1]) % 4)))
        transport = Transport(token, journal)
        total_deadline = started+LIMITS['totalSeconds']
        token_deadline = time.monotonic()+max(0, claims['exp']-time.time()-15)
        transport.deadline = min(transport.deadline, total_deadline, token_deadline)
        active = transport.get('baseline-active', '/policies/active')
        baseline(active)
        catalogue = registered(transport, 'baseline-registration')
        require(transport.get('baseline-verify', '/policies/active') == active, 'BASELINE_CHANGED_DURING_PREFLIGHT')
        transport.deadline = min(time.monotonic()+LIMITS['reviewAndExecutionSeconds'], total_deadline, token_deadline)
        require(transport.deadline-time.monotonic() > 60, 'FRESH_REVIEW_WINDOW_REQUIRED')
        plan = prepare(active, catalogue, time.time()+transport.deadline-time.monotonic())
        plan['loginDependencySHA256'] = READER_HASH
        plan['controllerSHA256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        approve(plan, journal, transport)
        print(json.dumps(execute(plan, catalogue, journal, transport), sort_keys=True, separators=(',', ':')), flush=True)
    except BaseException:
        journal.row['state'] = 'STOP_RECONCILE'
        journal.save()
        raise


if __name__ == '__main__':
    try:
        main()
    except Stop as error:
        print(json.dumps({'status': 'STOP_RECONCILE', 'reasonCode': str(error),
                          'automaticReplayAllowed': False, 'budgetReset': False,
                          'applicationE2EProven': False, 'releaseAcceptance': False}), flush=True)
        sys.exit(2)
    except Exception:
        print('{"status":"STOP_RECONCILE","reasonCode":"PRIVATE_DETAILS_REDACTED","automaticReplayAllowed":false}', flush=True)
        sys.exit(2)
