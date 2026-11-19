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

import base64, math, signal
import urllib.parse
from zoneinfo import ZoneInfo
ISSUER = 'https://auth.ouf-lab.it/realms/ouf'
SUBJECT = 'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
ADMIN = 'https://api.ouf-lab.it/api/trusted-human/v1/authorization'
BASE_REF = 'ouf-lab-authorization:56'
BASE_HASH = 'c52e856c8d95032f6942e1618fb0102f0b704acc5f41f044648e9466aaf9d323'
BASE_RESPONSE = '59856645ba247267a1e4839a4620f4ad70fe42d46d64fe6b7775b59c379ab912'
BASE_CATALOGUE = 'ad928f1916a8b417aa0b2bde567ddf0924223863778ea96b22e98f4e8fb0f2d7'
CONTEXT = '/etc/ouf/deploy-snapshots/managed-profile-descriptor-publication-policy56-20261028-v1'
MISSING = ('ouf.onboarding.quarantine.release',)
EXISTING = ('ouf.managed-source.preview', 'ouf.managed-source.file.profile')
LIMITS = {'ownerGets': 160, 'administrativeWrites': 3, 'previewPosts': 2,
          'responseBytes': 5*1024*1024, 'totalBytes': 32*1024*1024,
          'reviewAndExecutionSeconds': 900, 'totalSeconds': 1800,
          'readAttemptsPerStage': 8, 'iamMetadataGets': 1, 'iamPosts': 121}
TTY_SHA256 = '3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5'
TTY_CODE = '"""Exact HUMAN approval with visible native terminal line editing.\n\nWrong lines are input mistakes, not authority claims. They may be corrected only\ninside the original finite review window. No grant, counter or deadline reset.\nOnly counts/states are persisted. Terminal echo stays on the actual TTY, not logs.\n"""\nimport os\nimport re\nimport select\nimport stat\nimport termios\nimport time\n\nclass TerminalReviewError(Exception): pass\n\ndef require(value, code):\n    if not value: raise TerminalReviewError(code)\n\ndef read_exact(review_hash, guard, *, emit, progress, fd=None, clock=time.monotonic, heartbeat=10):\n    require(isinstance(review_hash,str) and re.fullmatch(\'[a-f0-9]{64}\',review_hash),\'EXACT_REVIEW_HASH_REQUIRED\')\n    require(0 < heartbeat <= 10,\'FINITE_TERMINAL_HEARTBEAT_REQUIRED\')\n    owned=fd is None\n    if owned:fd=os.open(\'/dev/tty\',os.O_RDWR|os.O_NOCTTY|os.O_CLOEXEC|os.O_NOFOLLOW)\n    previous=None\n    try:\n        require(os.isatty(fd) and stat.S_ISCHR(os.fstat(fd).st_mode),\'CONTROLLING_REVIEW_TTY_REQUIRED\')\n        if owned:require(os.tcgetpgrp(fd)==os.getpgrp(),\'FOREGROUND_REVIEW_TERMINAL_REQUIRED\')\n        previous=termios.tcgetattr(fd)\n        selected=[list(x) if isinstance(x,list) else x for x in previous]\n        selected[0]=(selected[0]|termios.ICRNL)&~(termios.INLCR|termios.IGNCR)\n        selected[3]|=termios.ICANON|termios.ECHO|termios.ECHOE|termios.ECHOK|termios.ISIG\n        selected[6][termios.VERASE]=b\'\\x7f\';selected[6][termios.VKILL]=b\'\\x15\'\n        # TCSANOW does not discard input already pasted at the prompt.\n        termios.tcsetattr(fd,termios.TCSANOW,selected)\n        expected=(\'APPROVO \'+review_hash).encode(\'ascii\')\n        buf=bytearray();oversized=False;last=clock();rejected=0\n        def state(name,n=0,enter=False):\n            progress({\'state\':name,\'receivedBytes\':n,\'enterReceived\':enter,\'rejectedLines\':rejected})\n        state(\'WAITING_INPUT\')\n        emit(\'Input visibile. Incolla la riga APPROVO e premi Invio. Backspace cancella; Ctrl+U svuota la riga.\')\n        emit(\'Una riga errata resta correggibile qui entro la stessa scadenza; non rilanciare il comando.\')\n        while True:\n            guard()\n            ready,_,_=select.select([fd],[],[],.2)\n            if ready:\n                raw=os.read(fd,4096)\n                require(bool(raw),\'REVIEW_TERMINAL_EOF\')\n                # Canonical mode delivers a completed line, with native editing\n                # already applied. Never decide on a partially pasted line.\n                newline=raw.find(b\'\\n\')\n                content=raw if newline<0 else raw[:newline]\n                if len(buf)+len(content)>4096:oversized=True\n                if not oversized:buf.extend(content)\n                if newline>=0:\n                    guard()\n                    if not oversized and bytes(buf)==expected and raw[newline+1:] in (b\'\',b\'\\n\'):\n                        state(\'LINE_RECEIVED\',len(buf),True)\n                        emit(\'Riga esatta ricevuta con Invio. Verifico la revisione privata.\')\n                        return\n                    if buf or oversized:\n                        rejected+=1\n                        state(\'LINE_REJECTED\',min(4097,len(buf)+(4097 if oversized else 0)),True)\n                        emit(\'Riga non valida: nessuna approvazione acquisita. Incolla nuovamente la sola riga APPROVO e premi Invio.\')\n                    buf.clear();oversized=False;state(\'WAITING_INPUT\')\n            if clock()-last>=heartbeat:\n                guard()\n                emit(\'Attendo la riga APPROVO e Invio; puoi modificarla con Backspace o cancellarla con Ctrl+U. Scadenza invariata.\')\n                last=clock()\n    finally:\n        if previous is not None:termios.tcsetattr(fd,termios.TCSANOW,previous)\n        if owned:os.close(fd)\n'

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
    require(cap in MISSING + EXISTING, 'EXACT_DESCRIPTOR_REQUIRED')
    return {'ownerRef': 'onboarding', 'descriptor': {
        'capabilityId': cap, 'operation': 'READ' if cap == EXISTING[0] else 'COMMAND',
        'requiredScope': cap, 'allowedActors': ['HUMAN']}}

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
        self.row = {'schema': 'ouf.managed-profile-descriptor-publication-journal.v1',
                    'state': 'CLAIMED', 'effects': {}, 'reads': {}, 'counts': {},
                    'budgetReset': False, 'automaticReplayAllowed': False}
        self.save()

    def write(self, name, value, exclusive=False):
        require(name in ('state.json', 'review.json', 'result.json', 'owner-create-response.json',
                         'owner-publish-response.json') or re.fullmatch(r'response-[0-9]{5}\.json', name), 'EXACT_PRIVATE_FILE_REQUIRED')
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
        self.hardAlarm = False
        self.opener = urllib.request.build_opener(NoRedirect())

    def guard(self):
        require(self.clock() < self.deadline, 'FINITE_HUMAN_WINDOW_EXPIRED')
        if self.hardAlarm:
            signal.alarm(max(1, math.ceil(self.deadline-self.clock())))
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
            if not preview:
                key = ('REGISTER:'+body['descriptor']['capabilityId'] if path == '/capabilities'
                       else 'CREATE_DRAFT' if path == '/policies' else 'PUBLISH_DRAFT')
                require(self.journal.row['effects'].get(key, {}).get('state') == 'CLAIMED',
                        'EXACT_DURABLE_MUTATION_CLAIM_REQUIRED')
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
            reply = error  # Persist exact bounded response before status/shape guards.
        except (TimeoutError, ConnectionError, urllib.error.URLError) as error:
            reason = getattr(error, 'reason', error)
            if method == 'GET' and isinstance(reason, (TimeoutError, ConnectionError)):
                raise Transient() from None
            raise Stop('ADMIN_TRANSPORT_OUTCOME_REQUIRES_RECONCILIATION') from None
        with reply:
            data = reply.read(LIMITS['responseBytes']+1)
            self.counts['bytes'] += len(data)
            self.journal.row['counts'] = dict(self.counts)
            self.journal.save()
            envelope = {'schema': 'ouf.owner-response-retained.v1', 'method': method, 'path': path,
                        'status': reply.code, 'etag': next((v for k, v in reply.headers.items() if k.lower() == 'etag'), None),
                        'bodyUtf8': data.decode('utf-8', errors='replace'), 'truncated': len(data) > LIMITS['responseBytes']}
            ordinal = sum(self.counts[k] for k in ('ownerGets','administrativeWrites','previewPosts'))
            self.journal.write('response-%05d.json'%ordinal, envelope, exclusive=True)
            if method == 'POST' and (path == '/policies' or publish):
                self.journal.write('owner-create-response.json' if path == '/policies' else 'owner-publish-response.json',
                                   envelope, exclusive=True)
            require(reply.geturl() == ADMIN+path, 'ADMIN_REDIRECT_DENIED')
            require(len(data) <= LIMITS['responseBytes'] and self.counts['bytes'] <= LIMITS['totalBytes'],
                    'ADMIN_RESPONSE_BUDGET_EXHAUSTED')
            if reply.code >= 400:
                if method == 'GET' and reply.code in (408,429,502,503,504):
                    retry = reply.headers.get('Retry-After')
                    try:
                        delay = 0 if retry is None else float(retry) if retry.isdigit() else parsedate_to_datetime(retry).timestamp()-self.wall()
                        require(0 <= delay < 86400, 'INVALID_RETRY_AFTER')
                    except (ValueError,TypeError,OverflowError): raise Stop('INVALID_RETRY_AFTER') from None
                    raise Transient(delay)
                raise Stop('ADMIN_HTTP_'+str(reply.code)+'_NO_AUTOMATIC_REPLAY')
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
            and policy['bundleId'] == 'ouf-lab-authorization' and policy['version'] == 56
            and isinstance(policy['capabilities'], list) and isinstance(policy['grants'], list), 'EXACT_POLICY_SHAPE_REQUIRED')
    caps = {row['capabilityId']: row for row in policy['capabilities']}
    require(len(caps) == len(policy['capabilities']) and len(caps) <= 10000
            and all(caps.get(cap) == registration(cap)['descriptor'] for cap in EXISTING)
            and not set(MISSING) & set(caps), 'EXACT_SINGLE_MISSING_ACTIVE_DESCRIPTOR_REQUIRED')
    return policy

def prepare(active, catalogue, expires_at):
    policy = baseline(active)
    for cap in EXISTING+MISSING:
        if cap in catalogue:
            require(catalogue[cap] == registration(cap), 'REGISTERED_DESCRIPTOR_SEMANTICS_CONFLICT')
    require(digest(catalogue) == BASE_CATALOGUE, 'EXACT_OBSERVED_REGISTERED_CATALOGUE_REQUIRED')
    require(all(catalogue.get(cap) == registration(cap) for cap in EXISTING), 'EXISTING_MANAGED_DESCRIPTORS_REQUIRED')
    require(not set(MISSING) & set(catalogue), 'EXACT_SINGLE_REGISTRATION_ADDITION_REQUIRED')
    candidate = copy.deepcopy(policy)
    candidate.update(version=57, publishedAt=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
    candidate['capabilities'] += [registration(cap)['descriptor'] for cap in MISSING]
    return {'schema': 'ouf.managed-profile-descriptor-publication-review.v1', 'nonce': str(uuid.uuid4()),
            'account': 'ouf-admin', 'basePolicyRef': BASE_REF, 'basePolicyHash': BASE_HASH,
            'baseResponseHash': BASE_RESPONSE, 'baseCatalogueHash': BASE_CATALOGUE, 'expiresAt': expires_at, 'limits': copy.deepcopy(LIMITS),
            'registrationAdditions': [registration(cap) for cap in MISSING if cap not in catalogue],
            'activatedDescriptorIds': list(MISSING), 'candidatePolicy': candidate,
            'baselineCapabilitiesHash': digest(policy['capabilities']), 'baselineGrantsHash': digest(policy['grants']),
            'baselineGrantCount': len(policy['grants']), 'humanBudgetsGranted': 0, 'resumes': 0, 'newGrants': 0, 'roleCatalogueMutations': 0,
            'iamConfigurationMutations': 0, 'sourceActivations': 0, 'acquisitionsExecuted': 0,
            'applicationE2EProven': False, 'releaseAcceptance': False}

def approve(plan,journal,t,*,fd=None,emit=None):
    emit=emit or (lambda s:print(s,flush=True))
    require(fd is None or os.isatty(fd),'REAL_REVIEW_TTY_REQUIRED')
    journal.write('review.json',plan,exclusive=True)
    review_hash=digest(plan)
    journal.row.update(state='REVIEW_PREPARED',reviewHash=review_hash);journal.save()
    emit('Revisione privata: '+str(journal.path/'review.json'))
    emit('SOLA registrazione descriptor e pubblicazione ACTIVE56 → 57; nessun permesso concesso.')
    for cap in MISSING:
        emit('  '+cap+'; owner=onboarding; COMMAND; scope='+cap+'; HUMAN')
    emit('Tutti i '+str(plan['baselineGrantCount'])+' grant esistenti, capability, ruoli e assegnazioni preservati.')
    emit('Massimi:1 registrazione,1 draft,2 preview,1 pubblicazione;160 GET;32MiB cumulativi.')
    emit('Budget/resume/job/upload/acquisizioni/Engine/SQL/Registry/IAM configuration:0.')
    emit('Scadenza concreta: '+datetime.fromtimestamp(plan['expiresAt'],ZoneInfo('Europe/Rome')).isoformat()+' (Europe/Rome)')
    emit('STOP o risposta ambigua: prove conservate; non rilanciare. Nessuna accettazione E2E/release.')
    emit('Inserisci ESCLUSIVAMENTE la riga seguente, senza aggiungere testo:')
    emit('APPROVO '+review_hash)
    emit('Conferma:')
    def input_progress(value):
        journal.row['ttyInput']=value;journal.save()
    try:
        terminal_reader()['read_exact'](review_hash,t.guard,emit=emit,progress=input_progress,fd=fd)
    except BaseException as error:
        if type(error).__name__=='TerminalReviewError':raise Stop(str(error)) from None
        raise
    journal.verify_review(review_hash)
    journal.row.update(state='HUMAN_APPROVED',humanReviewApproved=True);journal.save()
    t.approve(plan)
    emit('APPROVAZIONE ACQUISITA. Avvio i soli controlli finali e il delta descriptor approvato.')

def validate_draft(value, plan, state='DRAFT'):
    require(isinstance(value, dict) and isinstance(value.get('id'), str)
            and str(uuid.UUID(value['id'])) == value['id'] and type(value.get('revision')) is int
            and value['revision'] >= 0 and value.get('state') == state and value.get('baseActiveRef') == BASE_REF
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
    require(digest(registered(transport, 'approved-catalogue')) == plan['baseCatalogueHash'], 'REGISTERED_CATALOGUE_CHANGED_AFTER_REVIEW')
    for row in plan['registrationAdditions']:
        key = 'REGISTER:'+row['descriptor']['capabilityId']
        journal.effect(key, row)
        status, _, _ = transport.request('/capabilities', method='POST', body=row)
        require(status == 201, 'REGISTRATION_ACK_REQUIRED')
        # Remain CLAIMED until the independent registration read-back succeeds.
    after_reg = registered(transport, 'registration-readback')
    require(set(after_reg) == set(catalogue) | set(MISSING) and all(after_reg.get(cap) == value for cap, value in catalogue.items())
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
    final_draft = transport.get('before-publish-draft', '/policies/'+draft['id'])
    validate_draft(final_draft, plan)
    require(final_draft['revision'] == draft['revision'], 'DRAFT_REVISION_CHANGED')
    baseline(transport.get('publish-dispatch-active', '/policies/active'))
    journal.effect('PUBLISH_DRAFT', {'id': draft['id'], 'revision': draft['revision'], 'draftHash': journal.row['ownerDraftHash']})
    status, published, _ = transport.request('/policies/'+draft['id']+':publish', method='POST', revision=draft['revision'])
    require(status == 200, 'PUBLICATION_ACK_REQUIRED')
    require(next((v for k,v in _.items() if k.lower() == 'etag'), None) == '"'+str(draft['revision']+1)+'"', 'PUBLICATION_ETAG_REQUIRED')
    validate_draft(published, plan, state='PUBLISHED')
    require(published['revision'] == draft['revision']+1, 'PUBLICATION_REVISION_REQUIRED')
    current = transport.get('published-active', '/policies/active')
    candidate, actual = plan['candidatePolicy'], current.get('policy', {})
    require(current.get('policyRef') == 'ouf-lab-authorization:57'
            and actual.get('bundleId') == candidate['bundleId'] and actual.get('version') == 57
            and actual.get('capabilities') == candidate['capabilities'] and actual.get('grants') == candidate['grants']
            and isinstance(actual.get('publishedAt'), str) and isinstance(current.get('contentHash'), str),
            'PUBLISHED_ACTIVE_PRESERVATION_NOT_PROVEN')
    journal.applied('PUBLISH_DRAFT')
    result = {'schema': 'ouf.managed-profile-descriptor-publication-result.v1',
              'status': 'MANAGED_PROFILE_DESCRIPTOR_PUBLISHED_GRANTS_UNCHANGED', 'complete': True,
              'policyRef': current['policyRef'], 'policyHash': current['contentHash'],
              'reviewHash': digest(plan), 'ownerDraftHash': journal.row['ownerDraftHash'],
              'draftId': draft['id'], 'registeredByThisOperation': len(plan['registrationAdditions']),
              'activatedDescriptors': list(MISSING), 'preexistingDescriptorsPreserved': True,
              'allGrantsPreserved': True, 'grantsHash': digest(actual['grants']),
              'roleCatalogueMutations': 0, 'iamConfigurationMutations': 0,
              'mcpOAuthScopesVerified': False, 'newGrantsGranted': 0, 'humanBudgetsGranted': 0, 'resumes': 0, 'newJobs': 0, 'uploads': 0, 'sqlSessions': 0, 'fileContentReads': 0, 'signingKeyReads': 0,
              'counts': dict(transport.counts), 'iamCounts': journal.row.get('iamCounts'),
              'humanReviewApproved': True, 'automaticReplayAllowed': False, 'budgetReset': False,
              'runtimeAuthorityIssued': False, 'sourceActivations': 0, 'acquisitionsExecuted': 0,
              'engineRequests': 0, 'newCredentialFileReads': 0, 'registryWorkerTouched': False,
              'applicationE2EProven': False, 'releaseAcceptance': False}
    journal.row['state'] = 'COMPLETE'
    journal.save()
    journal.write('result.json', result, exclusive=True)
    return result

def terminal_reader():
    require(hashlib.sha256(TTY_CODE.encode()).hexdigest()==TTY_SHA256,'EXACT_EMBEDDED_TERMINAL_READER_REQUIRED')
    namespace={'__name__':'protected_terminal_review'}
    exec(compile(TTY_CODE,'<protected-terminal-review>','exec'),namespace)
    return namespace

class IamTransport:
    def __init__(self, *, clock=time.monotonic, reserve=None):
        self.clock = clock
        self.deadline = clock() + 600
        self.counts = {"iamGets": 0, "iamPosts": 0, "ownerGets": 0, "bytes": 0}
        self.opener = urllib.request.build_opener(NoRedirect())
        self.reserve = reserve or (lambda counts: None)

    def request(self, url, *, form=None, token=None):
        require(self.clock() < self.deadline, "FINITE_READ_EXPIRED")
        metadata = url == ISSUER + "/.well-known/openid-configuration"
        iam_post = url in (ISSUER + "/protocol/openid-connect/auth/device",
                           ISSUER + "/protocol/openid-connect/token")
        owner = url == ADMIN + "/policies/active" or url in {
            ADMIN + "/capabilities?limit=200&offset=" + str(n)
            for n in range(0, 10000, 200)}
        require((metadata and form is None and token is None)
                or (iam_post and form is not None and token is None)
                or (owner and form is None and isinstance(token, str) and bool(token)),
                "EXACT_READ_ENDPOINT_REQUIRED")
        kind = "ownerGets" if owner else "iamPosts" if iam_post else "iamGets"
        maximum = {"ownerGets": 52, "iamPosts": 121, "iamGets": 1}[kind]
        require(self.counts[kind] < maximum, "FINITE_REQUEST_LIMIT")
        self.counts[kind] += 1  # reserve before dispatch, including failed calls
        self.reserve(dict(self.counts))
        body = None if form is None else urllib.parse.urlencode(form).encode("ascii")
        headers = {"Accept": "application/json"}
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="GET" if body is None else "POST")
        try:
            response = self.opener.open(req, timeout=min(20, max(.1, self.deadline-self.clock())))
        except urllib.error.HTTPError as exc:
            # Only OAuth protocol errors are interpreted; owner errors are never echoed.
            if not iam_post or exc.code not in (400, 429):
                raise Stop("OWNER_HTTP_" + str(exc.code) if owner else "IAM_HTTP_FAILURE") from None
            response = exc
        except (OSError, urllib.error.URLError, TimeoutError):
            raise Stop("READ_TRANSPORT_STOP_NO_RETRY") from None
        with response:
            require(response.geturl() == url, "REDIRECT_DENIED")
            raw = response.read(2_000_001)
            self.counts["bytes"] += len(raw)
            self.reserve(dict(self.counts))
            require(len(raw) <= 2_000_000 and self.counts["bytes"] <= 16_000_000,
                    "BOUNDED_RESPONSE_REQUIRED")
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise Stop("INVALID_OWNER_JSON") from None
            return response.code, data

def login(transport, *, sleep=time.sleep, emit=None, wall=time.time):
    emit = emit or (lambda message: print(message, flush=True))
    status, metadata = transport.request(ISSUER + "/.well-known/openid-configuration")
    require(status == 200 and isinstance(metadata, dict) and metadata.get("issuer") == ISSUER,
            "EXACT_ISSUER_REQUIRED")
    device = ISSUER + "/protocol/openid-connect/auth/device"
    endpoint = ISSUER + "/protocol/openid-connect/token"
    require(metadata.get("device_authorization_endpoint") == device
            and metadata.get("token_endpoint") == endpoint, "EXACT_IAM_ENDPOINTS_REQUIRED")
    status, start = transport.request(device, form={"client_id": "ouf-human-admin",
                                                   "scope": "openid authorization.policy.admin"})
    require(status == 200 and isinstance(start, dict), "DEVICE_START_FAILED")
    uri = start.get("verification_uri")
    require(uri == ISSUER + "/device" and isinstance(start.get("user_code"), str)
            and 0 < len(start["user_code"]) <= 32
            and all(c.isalnum() or c == "-" for c in start["user_code"])
            and isinstance(start.get("device_code"), str)
            and 0 < len(start["device_code"]) <= 4096,
            "EXACT_DEVICE_RESPONSE_REQUIRED")
    expires = start.get("expires_in")
    interval = start.get("interval", 5)
    require(type(expires) is int and expires > 0 and type(interval) is int and interval > 0,
            "FINITE_DEVICE_WINDOW_REQUIRED")
    deadline = min(transport.deadline, transport.clock() + min(expires, 600))
    interval = max(5, min(interval, 30))
    emit("Apri nel browser: " + uri)
    emit("Codice da inserire solo nel browser: " + start["user_code"])
    emit("Accedi con ouf-admin. Non incollare codice o token in chat. Preflight policy e nuova review HUMAN nel terminale prima del SOLO delta descriptor. Nessun grant, budget o resume.")
    for _ in range(120):
        require(transport.clock() + interval < deadline, "DEVICE_WINDOW_EXPIRED")
        sleep(interval)
        status, reply = transport.request(endpoint, form={
            "client_id": "ouf-human-admin",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"]})
        require(isinstance(reply, dict), "INVALID_TOKEN_RESPONSE")
        if status == 200:
            token = reply.get("access_token")
            require(isinstance(token, str) and 0 < len(token) <= 16384
                    and not any(c.isspace() for c in token), "BOUNDED_TOKEN_REQUIRED")
            try:
                parts = token.split(".")
                require(len(parts) == 3, "TOKEN_CONTEXT_REQUIRED")
                claims = json.loads(base64.urlsafe_b64decode(parts[1]+"="*(-len(parts[1]) % 4)))
            except (ValueError, UnicodeError, TypeError):
                raise Stop("TOKEN_CONTEXT_REQUIRED") from None
            # This local check selects the account; the owner verifies JWT authenticity.
            require(isinstance(claims, dict) and claims.get("iss") == ISSUER
                    and claims.get("sub") == SUBJECT and claims.get("tenant_id") == "ouf-lab"
                    and claims.get("ouf_actor_type") == "HUMAN"
                    and type(claims.get("exp")) in (int, float) and claims["exp"] > wall()
                    and "authorization.policy.admin" in str(claims.get("scope", "")).split(),
                    "EXACT_OUF_ADMIN_CONTEXT_REQUIRED")
            return token
        error = reply.get("error")
        if error == "slow_down":
            interval = min(30, interval + 5)
        elif error != "authorization_pending":
            raise Stop("DEVICE_LOGIN_STOP_NO_RETRY")
    raise Stop("DEVICE_POLL_LIMIT")

class Logger:
    def __init__(self, path):
        self.original = sys.stdout
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.file = os.fdopen(fd, "w", buffering=1)

    def write(self, value):
        self.file.write(value); self.file.flush(); os.fsync(self.file.fileno())
        return self.original.write(value)

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno()); self.original.flush()

    def isatty(self):
        return self.original.isatty()

    def fileno(self):
        return self.original.fileno()

def ancestry(path):
    for parent in (path, *path.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0
                and not st.st_mode & 0o022, "ROOT_READ_SCOPE_ANCESTRY_REQUIRED")

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ONE_ISOLATED_ROOT_DESCRIPTOR_PUBLISHER_REQUIRED')
    require(sys.stdin.isatty() and sys.stdout.isatty(), 'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
    code = Path(__file__).resolve()
    ancestry(code.parent)
    st = code.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o400, 'PROTECTED_PUBLISHER_ROOT400_REQUIRED')
    ancestry(Path(CONTEXT).parent)
    require(not os.path.lexists(CONTEXT), 'PUBLICATION_SCOPE_EXISTS_RECONCILE_NO_REPLAY')
    journal = Journal()
    sys.stdout = Logger(code.parent/'operator.log')
    print('PrivateContext='+str(journal.path), flush=True)
    started = time.monotonic()
    transport = None
    def expired(*_): raise Stop('FINITE_DESCRIPTOR_PUBLICATION_WINDOW_EXPIRED')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(600)
    try:
        def reserve_iam(counts):
            journal.row['iamCounts'] = counts; journal.save()
        iam = IamTransport(reserve=reserve_iam)
        token = login(iam)
        claims = json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'='*(-len(token.split('.')[1])%4)))
        transport = Transport(token,journal)
        total_deadline = started + LIMITS['totalSeconds']
        token_deadline = time.monotonic()+max(0,claims['exp']-time.time()-15)
        transport.deadline = min(transport.deadline,total_deadline,token_deadline)
        transport.hardAlarm = True; transport.guard()
        active = transport.get('baseline-active','/policies/active'); baseline(active)
        catalogue = registered(transport,'baseline-catalogue')
        require(digest(catalogue) == BASE_CATALOGUE,'EXACT_OBSERVED_REGISTERED_CATALOGUE_REQUIRED')
        require(transport.get('baseline-verify','/policies/active') == active,'BASELINE_CHANGED_DURING_PREFLIGHT')
        transport.deadline = min(time.monotonic()+LIMITS['reviewAndExecutionSeconds'],total_deadline,token_deadline)
        transport.guard()
        require(transport.deadline-time.monotonic() > 60,'FRESH_REVIEW_WINDOW_REQUIRED')
        plan = prepare(active,catalogue,time.time()+transport.deadline-time.monotonic())
        plan['controllerSHA256'] = hashlib.sha256(code.read_bytes()).hexdigest()
        plan['countsAtReview'] = dict(transport.counts)
        approve(plan,journal,transport)
        result = execute(plan,catalogue,journal,transport)
        del token
        print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    except BaseException:
        journal.row['state'] = 'STOP_RECONCILE'
        journal.save()
        raise
    finally:
        signal.alarm(0)

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

