"""Initialize exactly one successor journal after current terminal consent.

No OAuth request, credential reuse, refresh, or runtime authority. An interrupted
claim remains consumed; rerunning this operation is forbidden, not a recovery.
"""
import copy
import json
import os
from pathlib import Path
import time
import uuid
from tools.ingestion_rollout_execution import private_file
from tools.ingestion_rollout_execution.contract import require,digest,encoded
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from iam_owner_action import publish
from tools.governed_human_successor.contract import compile_review,public_history
from tools.governed_human_successor.session import validate_consent

def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def predecessor_row(binding):
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'DUPLICATE_PREDECESSOR_JOURNAL_FIELD');result[key]=value
        return result
    return json.loads(private_file.read(binding),object_pairs_hook=unique)

def initialize(review,decision,predecessor_journal,selection,history):
    now=time.time();validate_consent(review,decision,now)
    require(now<decision['approvedAt']+60,'FRESH_TERMINAL_CONSENT_BEFORE_SUCCESSOR_CLAIM_REQUIRED')
    private_file.validate(predecessor_journal)
    previous=Path(review['predecessorDirectory'])
    require(predecessor_journal['path']==str(previous/'recovery.json'),
            'EXACT_PREDECESSOR_JOURNAL_PATH_REQUIRED')
    old=Journal(previous)
    destination=previous.parent/('human-successor-'+digest(review))
    with old.invocation():
        row=predecessor_row(predecessor_journal)
        expected=compile_review(selection,row,history,review['operationBinding'],review['sourceClosureHash'],
            now=now,monotonic=time.monotonic(),boot_id=boot_id())
        require(review==expected,'PREDECESSOR_CHANGED_AFTER_SUCCESSOR_REVIEW')
        claim={'schema':'ouf.human-explicit-successor-claim.v1','reviewHash':digest(review),
            'decisionHash':digest(decision),'destination':str(destination),
            'priorOAuthAttempts':review['priorOAuthAttempts'],
            'maximumCumulativeOAuthAttempts':review['maximumCumulativeOAuthAttempts'],
            'expiresAt':decision['expiresAt'],'automaticReplayAllowed':False,'budgetReset':False,
            'runtimeAuthorityIssued':False}
        with protected_directory(previous)as directory:
            require(publish(directory,'successor-window.claim.json',encoded(claim)),
                    'SUCCESSOR_CLAIM_ALREADY_CONSUMED_RECONCILE_ONLY')
        with protected_directory(destination.parent)as directory:
            os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
        retry=copy.deepcopy(row['binding']['retryProfile']);retry['id']='ouf.human.explicit-successor.v1'
        binding={**copy.deepcopy(row['binding']),
            'sessionId':str(uuid.UUID(digest(decision)[:32])),
            'sessionDirectory':str(destination),'tokenPath':str(destination/'human-access.jwt'),
            'createdAt':decision['approvedAt'],'expiresAt':decision['expiresAt'],'retryProfile':retry}
        journal=Journal(destination)
        journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
            'bootId':row['bootId'],'monotonicDeadline':time.monotonic()+decision['expiresAt']-time.time(),
            'lastObservedAt':time.time(),'attempts':row['attempts'],'state':'NEW','budgetReset':False,
            'governedWindowRenewal':{'review':copy.deepcopy(review),'decision':copy.deepcopy(decision)}})
        # Never read a predecessor bearer or copy a token/refresh into the new row.
        require(public_history(predecessor_row(predecessor_journal))==public_history(row),
                'PREDECESSOR_HISTORY_CHANGED_DURING_SUCCESSOR_INITIALIZATION')
    return binding
