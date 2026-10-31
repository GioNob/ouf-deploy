"""CI-only taps plus a bounded service-log read strictly after a failed read.

Snapshot taps add no reads. Post-failure logs are separate, non-atomic evidence;
they never retry observation or change the original result or owner state.
"""
import json,re,subprocess

STATES={'LEASE_READY','LEASE_UPDATING','QUIESCING','QUIESCED','BLOCKED'}
ABSENT=object()
WORKER_STATES={'NEW','ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED',
    'CANCELLED','ATTEMPTING','PUBLISHING'}


def after_failure_status(unit,emit,read=subprocess.run):
    """Only minimized states already emitted by this disposable owned service."""
    result={'schema':'ouf.ci-worker-status-after-read-failure.v1',
        'timing':'AFTER_FAILED_READ_NOT_ATOMIC_WITH_PUBLICATION_SNAPSHOT',
        'status':'UNAVAILABLE','records':[],'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
    try:
        if type(unit) is not str or re.fullmatch('ouf-admitted-worker-[A-Za-z0-9_-]{1,32}[.]service',unit) is None:
            raise ValueError()
        reply=read(['/usr/bin/journalctl','--unit='+unit,'--no-pager','--lines=64','--output=cat'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,
            env={'PATH':'/usr/bin:/usr/sbin:/bin','LC_ALL':'C'})
        if reply.returncode!=0 or type(reply.stdout) is not bytes or len(reply.stdout)>65536:raise ValueError()
        prefix='OUF_DISCOVERY_LEASE_WORKER_STATUS='
        def unique(rows):
            value=dict(rows)
            if len(value)!=len(rows):raise ValueError()
            return value
        records=[]
        for line in reply.stdout.decode('ascii').splitlines()[-64:]:
            if not line.startswith(prefix):continue
            try:
                v=json.loads(line[len(prefix):],object_pairs_hook=unique)
                if (type(v) is not dict or set(v)!={'state','reason','attempts','renewals','incidentRef','ready','live',
                    'applicationReady','runtimeAuthorityIssued'} or v['state'] not in WORKER_STATES
                    or type(v['reason']) is not str or re.fullmatch('[A-Z][A-Z0-9_]{0,120}',v['reason']) is None
                    or any(type(v[k]) is not int or not 0<=v[k]<2**63 for k in ('attempts','renewals'))
                    or type(v['incidentRef']) is not str or re.fullmatch('[0-9a-f]{64}',v['incidentRef']) is None
                    or v['ready'] is not (v['state']=='ACTIVE') or v['live'] is not True
                    or v['applicationReady'] is not False or v['runtimeAuthorityIssued'] is not False):continue
                records.append({k:v[k] for k in ('state','reason','attempts','renewals','ready','live')})
            except (ValueError,TypeError):continue
        result.update(status='CAPTURED',records=records[-32:])
    except Exception:pass
    try:emit('CI_WORKER_STATUS_AFTER_READ_FAILURE='+json.dumps(result,sort_keys=True))
    except Exception:pass


def capture(actual,coordinator,path,identity,emit):
    journal=coordinator.journal;backend=coordinator.owner.backend;read_sets=backend.read_sets
    prior_journal=vars(coordinator).get('journal',ABSENT)
    prior_sets=vars(backend).get('read_sets',ABSENT);events=[]
    def journal_tap():
        value=journal();state=value.get('state');authorized=value.get('leaseAuthorized')
        events.append({'kind':'coordination','state':state if state in STATES else 'UNPROVEN',
            'leaseAuthorized':authorized if type(authorized) is bool else None})
        return value
    def sets_tap(configuration):
        value=read_sets(configuration)
        expected={(family,i) for family in ('inet','bridge') for i in range(len(configuration['providerFlows']))}
        events.append({'kind':'sets','expectedKeyCount':len(expected),
            'exactExpectedKeys':type(value) is dict and set(value)==expected,
            'allFamiliesPositive':type(value) is dict and all(type(v) is dict and bool(v) for v in value.values())})
        return value
    coordinator.journal=journal_tap;backend.read_sets=sets_tap
    try:return actual(coordinator,path,identity)
    except Exception:
        try:emit('CI_PUBLICATION_READ_SNAPSHOT='+json.dumps({'events':events[:3]},sort_keys=True))
        except Exception:pass
        raise
    finally:
        if prior_journal is ABSENT:del coordinator.journal
        else:coordinator.journal=prior_journal
        if prior_sets is ABSENT:del backend.read_sets
        else:backend.read_sets=prior_sets
