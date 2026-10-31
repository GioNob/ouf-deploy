#!/usr/bin/env python3
"""Exact retained-file read only. No login, API, SQL, old main, or authority.

Only metadata/hashes/field types are projected. Review and owner responses stay private.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import uuid

CONTEXT = '/home/oufadmin/ouf-acquisition-descriptor-publication-20261025'
CODE = '/usr/local/lib/ouf-acquisition-descriptor-publication-1cbb40dd80d9e258/publish.py'
CODE_HASH = '1cbb40dd80d9e258d55de530096fb139f7ae193df1a62c912ea24509f43ca284'
REVIEW_HASH = '5a31ae519ef9ee4e14cf9258f91739ba27aa07a290f5f07b277cb8d3a44de911'
CAPS = ('ingestion.contract.read', 'ingestion.lineage.read', 'urban.object.read',
        'lineage.object.read', 'lineage.property.read')


class Stop(Exception): pass


def require(value, code):
    if not value: raise Stop(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def audit_guard(context, code, child):
    reads = {str(context/'review.json'), str(context/'state.json'), str(code)}
    writes = {str(child/'claim.json'), str(child/'result.json')}
    def guard(event, args):
        if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in ('os.system','os.fork','os.posix_spawn','os.exec','exec'):
            raise Stop('READ_ONLY_NETWORK_PROCESS_EXEC_DENIED')
        if event in ('os.listdir','os.scandir','os.remove','os.rmdir','os.rename','os.link','os.symlink',
                     'os.chown','os.chmod','os.truncate','os.utime','os.setxattr','os.removexattr'):
            raise Stop('READ_ONLY_UNRELATED_FILESYSTEM_ACTION_DENIED')
        if event == 'os.mkdir' and str(args[0]) != str(child):
            raise Stop('EXACT_DIAGNOSTIC_CHILD_REQUIRED')
        if event == 'open':
            path, mode, flags = args
            if isinstance(path, int): return
            writing = bool((flags or 0) & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            if not writing and (flags or 0) & os.O_DIRECTORY and str(path) in (str(context), str(child)):
                return
            require(str(path) in (writes if writing else reads), 'EXACT_RETAINED_READ_SCOPE_REQUIRED')
    return guard


def read_exact(path, owner, mode, maximum, counts):
    require(counts['fileReads'] < 3, 'RETAINED_FILE_READ_LIMIT')
    counts['fileReads'] += 1
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= maximum,
                'EXACT_RETAINED_FILE_CUSTODY_REQUIRED')
        raw = os.read(fd, maximum+1)
        after = os.fstat(fd)
        fields = lambda info: (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        require(fields(before) == fields(after) and len(raw) == before.st_size, 'RETAINED_FILE_CHANGED')
        counts['bytes'] += len(raw)
        return raw
    finally:
        os.close(fd)


def observe(context=CONTEXT, code=CODE, owner=None, expected_review=REVIEW_HASH):
    context, code = Path(context), Path(code)
    owner = os.geteuid() if owner is None else owner
    info = os.lstat(context)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) == 0o700,
            'EXACT_RETAINED_CONTEXT_REQUIRED')
    counts = {'fileReads':0, 'bytes':0}
    require(hashlib.sha256(read_exact(code, 0, 0o444, 65536, counts)).hexdigest() == CODE_HASH,
            'EXACT_STOPPED_CONTROLLER_HASH_REQUIRED')
    review = json.loads(read_exact(context/'review.json', owner, 0o600, 6*1024*1024, counts))
    journal = json.loads(read_exact(context/'state.json', owner, 0o600, 131072, counts))
    require(digest(review) == expected_review and journal.get('reviewHash') == expected_review
            and journal.get('humanReviewApproved') is True and journal.get('state') == 'STOP_RECONCILE'
            and journal.get('budgetReset') is False and journal.get('automaticReplayAllowed') is False,
            'EXACT_APPROVED_STOPPED_REVIEW_REQUIRED')
    candidate = review.get('candidatePolicy', {})
    require(candidate.get('bundleId') == 'ouf-lab-authorization' and candidate.get('version') == 49
            and review.get('baselineGrantCount') == 106 and len(candidate.get('grants', [])) == 106
            and digest(candidate['grants']) == review.get('baselineGrantsHash')
            and review.get('activatedDescriptorIds') == list(CAPS)
            and review.get('newGrants') == 0 and review.get('roleCatalogueMutations') == 0,
            'EXACT_RETAINED_CANDIDATE_REQUIRED')
    effects = journal.get('effects')
    permitted = {'REGISTER:'+cap for cap in CAPS}|{'CREATE_DRAFT','PUBLISH_DRAFT'}
    require(isinstance(effects, dict) and set(effects) <= permitted, 'BOUNDED_RETAINED_EFFECTS_REQUIRED')
    projected = []
    for key, value in effects.items():
        require(value.get('state') in ('CLAIMED','APPLIED') and re.fullmatch('[a-f0-9]{64}', str(value.get('bodyHash'))),
                'EXACT_RETAINED_EFFECT_STATE_REQUIRED')
        if key == 'CREATE_DRAFT':
            require(value['bodyHash'] == digest(candidate), 'RETAINED_CREATE_BODY_HASH_MISMATCH')
        projected.append({'stage':key,'state':value['state'],'bodyHash':value['bodyHash']})
    draft_id = journal.get('draftId')
    if draft_id is not None:
        require(isinstance(draft_id, str) and str(uuid.UUID(draft_id)) == draft_id, 'RETAINED_DRAFT_ID_INVALID')
        require(type(journal.get('draftRevision')) is int and journal['draftRevision'] >= 0, 'RETAINED_DRAFT_REVISION_INVALID')
    read_stages = []
    for key, value in journal.get('reads', {}).items():
        require(re.fullmatch(r'(baseline-active|baseline-verify|approved-active|before-draft-active|draft-readback|before-publish-active|published-active|baseline-registration:[0-9]{1,5}|registration-readback:[0-9]{1,5})', key)
                and type(value.get('attempts')) is int and 1 <= value['attempts'] <= 8
                and value.get('state') in ('ATTEMPTING','RETRY_WAIT','COMPLETE'), 'EXACT_RETAINED_READ_STAGE_REQUIRED')
        read_stages.append({'stage':key,'attempts':value['attempts'],'state':value['state']})
    retained_counts = journal.get('counts', {})
    require(set(retained_counts) == {'ownerGets','administrativeWrites','previewPosts','bytes'}
            and all(type(value) is int and value >= 0 for value in retained_counts.values()), 'RETAINED_COUNTS_REQUIRED')
    date_types = {}
    for grant in candidate['grants']:
        kind = type(grant.get('validFrom')).__name__
        date_types[kind] = date_types.get(kind, 0)+1
    return {'schema':'ouf.acquisition-descriptor-retained-stop-read.v1',
            'status':'RETAINED_DESCRIPTOR_PUBLICATION_STOP_OBSERVED', 'complete':True,
            'reviewHash':expected_review,'retainedState':journal['state'], 'humanReviewApprovedRetained':True,
            'effects':projected,'readStages':read_stages,'retainedCounts':retained_counts,
            'allFiveRegistrationsAppliedInRetainedJournal':all(effects.get('REGISTER:'+cap,{}).get('state') == 'APPLIED' for cap in CAPS),
            'draftIdRetained':draft_id is not None,'draftId':draft_id,'draftRevision':journal.get('draftRevision'),
            'createDispatchClaimed':effects.get('CREATE_DRAFT',{}).get('state') == 'CLAIMED',
            'publishDispatchRecorded':'PUBLISH_DRAFT' in effects,
            'originalControllerPersistsRawCreateResponse':False,
            'ownerResponseFilePresent':(context/'owner-create-response.json').exists(),
            'candidatePolicyHash':digest(candidate),'candidateGrantCount':106,
            'candidatePublishedAtType':type(candidate.get('publishedAt')).__name__,'grantValidFromTypes':date_types,
            'metadataReadCounts':counts,'oldFilesWritten':0,'networkRequests':0,'oauthRequests':0,
            'sqlSessions':0,'engineRequests':0,'runtimeAuthorityIssued':False,'continuationAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        require(stat.S_IMODE(os.fstat(output.fileno()).st_mode) == 0o600, 'DIAGNOSTIC_PRIVATE_MODE_REQUIRED')
        output.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        output.flush(); os.fsync(output.fileno())


def main():
    require(len(sys.argv) == 1 and os.geteuid() != 0, 'OPERATOR_ONLY_RETAINED_READ_REQUIRED')
    context, code = Path(CONTEXT), Path(CODE)
    child = context/'retained-draft-read-v1'
    sys.addaudithook(audit_guard(context, code, child))
    info = os.lstat(context)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'EXACT_RETAINED_CONTEXT_REQUIRED')
    try:
        os.mkdir(child, 0o700)
    except FileExistsError:
        raise Stop('RETAINED_READ_SCOPE_CONSUMED_NO_REPLAY') from None
    def sync_dir(path):
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    sync_dir(context)
    private_write(child/'claim.json', {'state':'CLAIMED','automaticReplayAllowed':False,'budgetReset':False})
    sync_dir(child)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('FINITE_RETAINED_READ_EXPIRED')))
    signal.alarm(60)
    result = observe()
    private_write(child/'result.json', result)
    sync_dir(child)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    print('Directory='+str(child), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Stop as error:
        print(json.dumps({'status':'STOP_RECONCILE','reasonCode':str(error),'automaticReplayAllowed':False,'continuationAuthorized':False}), flush=True)
        sys.exit(2)
    except Exception:
        print('{"status":"STOP_RECONCILE","reasonCode":"PRIVATE_DETAILS_REDACTED","automaticReplayAllowed":false}', flush=True)
        sys.exit(2)
