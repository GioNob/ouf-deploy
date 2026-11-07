"""Disposable CI controls of actual sealed-worker recovery-lock interference.

No installed generation is adopted or restarted. The negative control consumes
its own fresh fixture and must remain denied; it is not installation acceptance.
"""
import json,os,time
from pathlib import Path
from unittest.mock import patch
from tools.m2_discovery_installation_profile import lease_observation_inputs as inputs
from recovery_journal import Journal


def record(path):return json.loads(Path(path).read_bytes())


def snapshot_progress(configuration,anchor):
    view,_,_=inputs.build_observed(configuration,anchor);reader=view.r.journal
    before=record(reader.root/'recovery.json');entered=[];progress=[];read=os.read
    def held(fd,size):
        if not entered and size==65537:
            entered.append(True);raw=read(fd,size);held_record=json.loads(raw);end=time.monotonic()+10
            while time.monotonic()<end:
                row=record(reader.root/'recovery.json')
                if row['publicationCount']>held_record['publicationCount']:
                    progress.append(row);break
                assert row['state']=='ACTIVE',row['reason'];time.sleep(.01)
            assert progress,'CI_SNAPSHOT_READER_BLOCKED_WORKER_PROGRESS'
            return raw
        return read(fd,size)
    with patch.object(inputs.os,'read',side_effect=held):
        try:reader.read();raise AssertionError('CI_ATOMIC_RECOVERY_CHANGE_WAS_ACCEPTED')
        except BlockingIOError as error:assert error.args==('DISCOVERY_RECOVERY_CHANGED_DURING_READ',)
    after=progress[0]
    assert all(after[k]==before[k] for k in ('attempts','startedWall','startedMonotonic','contextRef','generationRef','policyHash'))
    return {'heldSnapshotFdAcrossActualRenewal':True,'atomicChangeWasReadContentionOnly':True,
        'originalRecoveryClocksAndAttemptCountPreserved':True,'publicationAdvancedWithoutReaderLock':True}


def exclusive_negative_control(configuration,anchor,observe):
    view,_,_=inputs.build_observed(configuration,anchor);host=Journal(view.r.journal.root)
    # An OLD host read holds this exclusive transaction for its read body.
    # The fault is intentional, bounded, and only in this disposable CI mode.
    acquisition_end=time.monotonic()+5
    while True:
        entered=False
        try:
            with host.transaction():
                entered=True;before=host.private_read();assert before['state']=='ACTIVE'
                end=time.monotonic()+10
                while time.monotonic()<end:
                    coordination=record(host.root/'coordination.json')
                    if coordination['state']=='QUIESCED':break
                    time.sleep(.01)
                assert coordination['state']=='QUIESCED' and coordination['leaseAuthorized'] is False
                assert host.private_read()==before,'CI_EXPECTED_BLOCKED_RECOVERY_CAS_DID_NOT_REPRODUCE'
                assert all(not row for row in view.c.owner.backend.read_sets(view.c.configuration).values())
                # Retain the injected reader lock THROUGH the causal read.
                # Releasing it earlier can let a late blocked-checkpoint CAS
                # change the state before the original denial is observed.
                try:observe();raise AssertionError('CI_REVOKED_LEASE_WAS_ACCEPTED')
                except ValueError as error:assert error.args==('CURRENT_OWNED_DISCOVERY_LEASE_PUBLICATION_REQUIRED',)
            break
        except BlockingIOError:
            if entered or time.monotonic()>=acquisition_end:raise
            time.sleep(.001)
    after=view.r.journal.read();assert after==before
    return {'schema':'ouf.m2-exclusive-recovery-reader-negative-control.v1',
        'actualExclusiveReaderForcesKernelRevocation':True,'activeRecoveryCheckpointRetainedBecauseCasBlocked':True,
        'originalReadDenialReproduced':True,'workerAdmissionStillRequired':True,
        'noManagerRedispatchOrWorkerRearm':True,'noRecoveryClockAttemptOrPublicationReset':True,
        'notInstallationAcceptance':True,'fullCohortProven':False,'applicationE2EProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
