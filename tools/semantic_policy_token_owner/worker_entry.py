"""Concrete finite worker composition and live pause loop; no installer/defaults.

The sealed loader supplies exact typed inputs and existing retained records.
This module does not provision credentials, initialize/reset journals, sign,
mask units, create scopes or execute the V11 cutover. No HUMAN authority is
derived from development delegation or successful component tests.
"""
import dataclasses
import signal
import threading
import time
from tools.semantic_lease_recovery.bounded_recovery import Policy,fingerprint
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant,TokenRenewalAdapter,protected_directory,check
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery,RenewalWorker
from tools.semantic_policy_token_owner.reporter import OwnerReporter

def build_worker(binding,credential,profile,transport,journal,policy,context_ref,generation_ref,
                 manifest,authority,authority_raw,*,interval_seconds,clock=lambda:(time.time(),time.monotonic())):
    check(type(binding) is Binding and type(credential) is CredentialFile and type(profile) is IamProfile
          and type(transport) is PinnedIamOpener and type(journal) is Journal and type(policy) is Policy)
    # All immutable schedule/operation inputs must already be in the retained
    # record. Startup cannot silently adopt a new budget, scope or context.
    row=journal.read()
    check(row['contextRef']==context_ref and row['generationRef']==generation_ref
          and row['policyHash']==fingerprint(dataclasses.asdict(policy))
          and row.get('renewalProfile')==ScheduledRecovery.PROFILE
          and row.get('intervalSeconds')==interval_seconds)
    admission=OnlineIamAdmission(profile,credential,transport,clock)
    owner=InstalledTokenOwner(binding,credential,admission,journal,context_ref,generation_ref,manifest,authority,authority_raw)
    adapter=TokenRenewalAdapter(binding,credential,owner,HttpsGrant(clock,opener=transport),clock)
    recovery=ScheduledRecovery(journal,adapter,policy,context_ref,generation_ref,clock,__import__('random').SystemRandom().random,interval_seconds=interval_seconds)
    recovery.validate(row)
    return RenewalWorker(recovery)

def serve(worker,stop,reporter):
    check(type(worker) is RenewalWorker and type(stop) is threading.Event and type(reporter) is OwnerReporter
          and reporter.journal is worker.r.journal)
    # Exclusive invocation fence spans this process lifetime. Journal CAS and
    # status publication remain short; no shared DB/lease lock spans a wait.
    with protected_directory(worker.r.journal.root),worker.r.journal.invocation():
        worker.active_here=False
        try:
            while not stop.is_set():
                try:
                    row=worker._advance();reporter.report(worker.status(row));delay=worker.wait_seconds(row)
                except Exception:
                    worker.active_here=False
                    try:
                        # A failed log callback after a successful status write
                        # must not leave a durable ACTIVE observation while the
                        # owner has parked. Preserve counters, revoke the marker
                        # and publish BLOCKED when storage remains trustworthy.
                        row=worker.r.pause(worker.r.journal.read(),'BLOCKED','LOCAL_AUTHORITY_UNPROVEN')
                        reporter.report(worker.status(row))
                    except Exception:
                        try:worker.r.adapter.pause()
                        except Exception:pass
                    reporter.unavailable();delay=worker.heartbeat
                    # Do not automatically resume an unproven journal/observer
                    # failure in this invocation. Preserve state and liveness.
                    while not stop.wait(delay):reporter.unavailable()
                    break
                if stop.wait(delay):break
            try:
                row=worker.r.step(cancelled=True);reporter.report(worker.status(row))
            except Exception:reporter.unavailable()
        finally:
            worker.active_here=False
            try:worker.r.adapter.pause()
            except Exception:reporter.unavailable()

def run(worker,emit=print):
    stop=threading.Event();previous={}
    for sig in (signal.SIGTERM,signal.SIGINT):
        previous[sig]=signal.signal(sig,lambda *_:stop.set())
    try:return serve(worker,stop,OwnerReporter(worker.r.journal,emit))
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)
