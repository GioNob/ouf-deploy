"""Retained DB selection STOP reconciliation. Files only; no runtime authority."""

import hashlib,json,os,re,signal,stat,sys

from pathlib import Path

CONTEXT = Path('/etc/ouf/deploy-snapshots/ingestion-profile-publication-execution-0gd3mwft')

OWNER = Path('/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd')

OWNER_PLAN = 'e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938'

OWNER_RESULT = '7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'

SOURCE = 'ccbba4ebd986e98b465df733bce0149f8e730fb2'

class Denied(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Denied(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(value):
    return sha(encoded(value))

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    def bad(_):
        raise Denied('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad)

def metadata(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read(path, expected=None, maximum=8388608, projection=False):
    """FD-relative no-follow traversal; retain and recheck every ancestor FD."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXACT_PATH_REQUIRED')
    if projection:
        require(path == Path('/opt/ouf/installation/active-projection.json'), 'EXACT_PROJECTION_PATH_REQUIRED')
    descriptors = []
    ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        current = Path('/')
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            current /= name
            if projection and current == Path('/opt/ouf'):
                require(info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o750,
                        'APPROVED_OUF_PARENT_CUSTODY_REQUIRED')
            else:
                require(info.st_uid == 0 and not info.st_mode & 0o022, 'ROOT_ANCESTRY_REQUIRED')
            if projection and current == path.parent:
                require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                        'PRIVATE_INSTALLATION_DIRECTORY_REQUIRED')
            identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode)
            ancestors.append((parent, name, child, identity(info)))
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'PRIVATE_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and metadata(info) == metadata(os.fstat(fd))
                == metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'FILE_CHANGED_DURING_READ')
        require(expected is None or sha(raw) == expected, 'RETAINED_FILE_HASH_DRIFT')
        for ancestor, name, child, pin in ancestors:
            require(pin == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)), 'ANCESTRY_CHANGED_DURING_READ')
        return raw, list(metadata(info))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)

def parsed(path, expected=None, maximum=8388608):
    return decode(read(path, expected, maximum)[0])


def inspect_selection(parse):
    plan = parse(OWNER / 'execution-plan.json', OWNER_PLAN)
    result = parse(OWNER / 'update-result.json', OWNER_RESULT)
    require(result['complete'] is True and result['planHash'] == OWNER_PLAN,
            'COMPLETED_OWNER7_PLAN_REQUIRED')
    package = parse(CONTEXT / 'package.json')
    require(package['sourceCommit'] == SOURCE
            and package['closure']['declaration']['moduleCount'] == 244,
            'COMPLETED_PUBLICATION_PACKAGE_REQUIRED')
    review = parse(CONTEXT / 'review.json')
    decision = parse(CONTEXT / 'decision.json')
    require(review['sourceClosureHash'] == digest(package['closure'])
            and decision['reviewHash'] == digest(review),
            'PUBLICATION_SOURCE_SELECTION_BINDING_REQUIRED')
    require(parse(CONTEXT / 'runtime.claim.json') ==
            {'packageHash': digest(package), 'automaticReplayAllowed': False},
            'CONSUMED_PUBLICATION_CLAIM_REQUIRED')
    case = parse(CONTEXT / 'case.json', package['fileHashes']['case.json'])
    require(digest(case) == package['executionPins']['caseSha256']
            and case['humanBinding'] == plan['humanBinding'], 'EXACT_COMPLETED_CASE_REQUIRED')
    original = parse(case['originalBinding']['path'], case['originalBinding']['sha256'])
    require(type(original) is dict and type(original.get('engine')) is dict
            and type(original.get('databasePlan')) is dict
            and type(original.get('cohortPlan')) is dict,
            'BOUNDED_RETAINED_ORIGINAL_STRUCTURE_REQUIRED')
    engine = original['engine']
    current = plan['engine']
    checks = {
        'originalSchemaMatchesPreparedInputsV1': original.get('schema') == 'ouf.chatbot-file-cohort-prepared-inputs.v1',
        'originalEngineMatchesCompletedOwner7': engine == current,
        'originalDatabasePlanMatchesCohortHash': digest(original['databasePlan']) == original['cohortPlan'].get('databasePlanHash'),
    }
    return {
        'originalBindingBytesVerified': True,
        'checks': checks,
        'allOriginalPreflightSelectionPredicatesMatch': all(checks.values()),
        'engineComparison': {
            'fieldNamesMatch': set(engine) == set(current),
            'socketPathMatches': engine.get('socketPath') == current.get('socketPath'),
            'socketBindingMatches': engine.get('socketBinding') == current.get('socketBinding'),
        },
        'databasePlanSchemaMatchesCohortV1': original['databasePlan'].get('schema') == 'ouf.chatbot-cohort-database-plan.v1',
        'consumedPublicationClaimRetained': True,
        'completedOwner7PlanBound': True,
    }


def reconcile(reader=read):
    snapshots = {}
    def parse(path, expected=None):
        key = str(path)
        require(key not in snapshots, 'UNIQUE_RETAINED_DOCUMENT_REQUIRED')
        raw, meta = reader(path, expected)
        snapshots[key] = (sha(raw), meta)
        return decode(raw)
    facts = inspect_selection(parse)
    for path, (expected, meta) in snapshots.items():
        raw, again = reader(path, expected)
        require(again == meta and sha(raw) == expected, 'RETAINED_SELECTION_CHANGED_DURING_RECONCILIATION')
    return {
        'schema': 'ouf.ingestion-db-selection-reconcile.v1',
        'status': 'RECONCILED_METADATA_ONLY', 'complete': True,
        'predecessorReasonCode': 'EXACT_ORIGINAL_DATABASE_PLAN_REQUIRED',
        'retainedSelectionRechecked': True, **facts,
        'readOnly': True, 'engineGetRequests': 0, 'databaseCalls': 0,
        'oauthRequests': 0, 'ownerRequests': 0, 'gatewayRequests': 0,
        'credentialJournalsRead': 0, 'bearerFilesOpened': 0,
        'credentialValuesPrinted': False, 'credentialHashesPrinted': False,
        'journalWrites': 0, 'containerLifecycleOperations': 0,
        'completedOwnerActionReplayed': False, 'completedPublicationReplayed': False,
        'dbPreflightReplayed': False, 'runtimeAuthorityIssued': False,
        'databaseAdmissionProven': False, 'newLoginPerformed': False,
        'refreshPerformed': False, 'budgetReset': False, 'windowExtended': False,
        'automaticReplayAllowed': False, 'completedTechnicalPhases': 8,
        'functionalMilestonesProven': 4, 'notReleaseAcceptance': True,
    }


def main():
    require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    def expired(*_): raise Denied('FINITE_SELECTION_RECONCILIATION_DEADLINE')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(40)
    print(encoded(reconcile()).decode(), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(encoded({'schema': 'ouf.ingestion-db-selection-reconcile.v1',
            'complete': False, 'status': 'STOP_RECONCILE', 'readOnly': True,
            'reasonCode': str(error) if type(error) is Denied else 'PRIVATE_DETAILS_REDACTED',
            'engineGetRequests': 0, 'databaseCalls': 0, 'oauthRequests': 0,
            'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False,
            'budgetReset': False, 'completedTechnicalPhases': 8,
            'functionalMilestonesProven': 4}).decode(), flush=True)
        raise SystemExit(2)
