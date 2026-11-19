"""One current-boot successor of the exact cancelled postboot token owner.

No old session is revived. New attempts, if explicitly signed later, are added
to the consumed cumulative count, while the original first grant stays intact.
"""
import copy
from .contract import (CONTEXT, RECORDS, PROFILE, HISTORY, LEGACY, SOURCE_FILES,
                       compile_scope, digest, require, integer, hashed, path)

SCHEMA = 'ouf.semantic-registry-postboot-successor-owner-context.v1'


def compile_successor(context):
    fields = {'schema', 'lineageReceipt', 'predecessorJournalPath', 'retainedRecords', 'ownerInputs',
              'recovery', 'sourceClosureHash', 'sourceFiles', 'budget', 'predecessorContext',
              'resumptionInputs', 'resumptionBinding'}
    require(set(context) == fields and context['schema'] == SCHEMA,
            'EXACT_CURRENT_BOOT_SUCCESSOR_CONTEXT_REQUIRED')
    previous = context['predecessorContext']
    require(type(previous) is dict and previous.get('schema') == CONTEXT,
            'ONE_ORIGINAL_POSTBOOT_PREDECESSOR_ONLY')
    prior = compile_scope(previous)
    inputs = context['resumptionInputs']
    require(context['resumptionBinding']['sha256'] == digest(inputs)
            and context['predecessorJournalPath'] == prior['journalPath']
            and context['retainedRecords'] == dict(inputs['retainedOwnerRecords'], **{'recovery.json':inputs['retainedOwnerJournal']})
            and context['recovery'] == previous['recovery']
            and context['ownerInputs'] == previous['ownerInputs']
            and context['lineageReceipt'] == previous['lineageReceipt'],
            'SAME_CURRENT_BOOT_PREDECESSOR_INPUTS_AND_CREDENTIAL_REQUIRED')
    retained = context['retainedRecords']
    require(set(retained) == set(RECORDS) and retained['owner-session.json'] == prior,
            'EXACT_PREDECESSOR_POSTBOOT_SESSION_REQUIRED')
    row, marker, first = retained['recovery.json'], retained['owner-admission.json'], retained['owner-first-grant.json']
    require(row.get('state') == 'CANCELLED' and row.get('reason') == 'CANCELLED_BY_OWNER'
            and marker.get('state') == 'BLOCKED'
            and all(row.get(k) == marker.get(k) == prior[k] for k in ('contextRef','generationRef'))
            and row.get('workerSessionHash') == digest(prior) and row.get('policyHash') == digest(prior['policy'])
            and row.get('renewalProfile') == PROFILE and row.get('controlledHistoryProfile') == HISTORY
            and row.get('legacyHistory') == LEGACY and row.get('bootId') == prior['currentSessionBootId']
            and row.get('retainedFirstGrantBootId') == prior['retainedFirstGrantBootId']
            and row.get('firstGrantReceiptHash') == digest(first) == prior['firstGrantReceiptHash']
            and first == previous['retainedRecords']['owner-first-grant.json']
            and row.get('controlledPredecessorGrantAttempts') == prior['predecessorGrantAttempts'] == 319
            and integer(row.get('attempts'),1,1) and row.get('controlledCumulativeGrantAttempts') == 320
            and row.get('gateGeneration') == inputs['retainedNativeJournal']['newGeneration']
            and inputs['retainedFence'] == prior['fenceBinding'],
            'CANCELLED_POSTBOOT_ACCOUNTING_FIRST_GRANT_AND_GENERATION_REQUIRED')
    budget = context['budget']
    require(type(budget) is dict and set(budget) == {'maximumGrantAttempts','maximumSeconds','attemptTimeoutSeconds','intervalSeconds'}
            and integer(budget['maximumGrantAttempts'],1,1) and integer(budget['maximumSeconds'],1,900)
            and integer(budget['attemptTimeoutSeconds'],1,min(30,budget['maximumSeconds']))
            and integer(budget['intervalSeconds'],1,3600), 'ONE_EXPLICIT_PROPOSED_SUCCESSOR_GRANT_ONLY')
    source = context['sourceFiles']
    require(hashed(context['sourceClosureHash']) and type(source) is dict and set(source)==SOURCE_FILES,
            'COMPLETE_SUCCESSOR_SOURCE_BINDING_REQUIRED')
    for item in source.values():
        require(type(item) is dict and set(item)=={'path','sha256','metadata','ancestors'} and hashed(item['sha256']),
                'EXACT_SUCCESSOR_SOURCE_PROFILE_REQUIRED')
        path(item['path'])
    h = digest(context); predecessor = path(prior['journalPath'])
    journal = str(predecessor.parent/('semantic-postboot-worker-'+h))
    ref = digest({'operation':'REGISTRY_POSTBOOT_EXISTING_CREDENTIAL_OWNER','contextHash':h})
    gen = digest({'contextRef':ref,'bootId':context['recovery']['bootId'],'recovery':context['recovery']})
    policy={'delays':[5,15,60,300,900],'max_attempts':1,'max_elapsed':budget['maximumSeconds'],
            'attempt_timeout':budget['attemptTimeoutSeconds'],'jitter':.2}
    following = {'path':prior['fenceBinding']['path'],'value':{
        'schema':'ouf.semantic-postboot-owner-fence.v1','logicalOwnerScopeHash':prior['logicalOwnerScopeHash'],
        'reviewHash':h,'journalPath':journal,'predecessorWorkerHash':digest(row),
        'bootId':context['recovery']['bootId'],'recoveryLogicalOperationRef':context['recovery']['logicalOperationRef'],'active':True}}
    result=copy.deepcopy(prior)
    result.update(operation='INSTALL_CURRENT_BOOT_SUCCESSOR_WITHOUT_PREFIX_OR_FIRST_GRANT_REPLAY',
        contextHash=h,sourceClosureHash=context['sourceClosureHash'],sourceFilesHash=digest(source),
        contextRef=ref,generationRef=gen,journalPath=journal,predecessorJournalPath=str(predecessor),
        predecessorRecordHashes={name:digest(retained[name]) for name in RECORDS},
        predecessorGrantAttempts=320,maximumCumulativeGrantAttempts=321,policy=policy,
        intervalSeconds=budget['intervalSeconds'],predecessorFenceBinding=copy.deepcopy(prior['fenceBinding']),fenceBinding=following,
        predecessorPostbootScopeHash=digest(prior),resumptionInputsHash=context['resumptionBinding']['sha256'])
    return result
