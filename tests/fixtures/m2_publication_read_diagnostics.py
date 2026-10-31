"""CI-only observation taps. No extra reads, retries or owner effects."""
import json

STATES={'LEASE_READY','LEASE_UPDATING','QUIESCING','QUIESCED','BLOCKED'}
ABSENT=object()


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
