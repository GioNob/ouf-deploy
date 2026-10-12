"""Derive the retained installation scope from the selected private intake.

No publication, current liveness claim, native command, key read or authority.
The sealed target installer must authenticate the NEW execution mandate before
using the derived scope. Selected historical input cannot authorize itself.
"""
from pathlib import Path
from r12_retirement_adapter import parse
from transition_journal import require,hash_value

BASE=Path('/etc/ouf/deploy-snapshots')
R12=BASE/'semantic-resilient-lease-recovery-r12-y048hyms'
GUARD=BASE/'semantic-coordinated-boot-install-v2-e4repg0a'
CONTEXT=BASE/'semantic-provider-v2-approved-context-mf9x0eqd'
CLAIM='/etc/ouf/provider-resilient-lease-recovery-r12.claim'
UNIT='ouf-semantic-provider-lease-resilient-r12.service'
EXPECTED_AUTH='9730f8006a4257cbd2bf7576e6d0e49e41258360e0ca367f3e37852d57826e2b'
EXPECTED_OWNER='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
EXPECTED_EXECUTION='fd9f88c7b9c3863a8952c65a8f34dd4a3b31aca0a82828e92c89c2d66869a703'

def derive(intake_binding,custody,retained_programs):
    require(type(intake_binding) is dict and set(intake_binding)=={'path','sha256'} and hash_value(intake_binding['sha256']),'EXACT_SELECTED_RETIREMENT_INTAKE_REQUIRED')
    path=Path(intake_binding['path']);raw=custody.file_bytes(path,0,{0o600},expected=intake_binding['sha256']);manifest=parse(raw)
    require(path==BASE/('semantic-native-v11-intake-'+intake_binding['sha256'])/'intake.json'
            and manifest.get('schema')=='ouf.native-v11-atomic-review-intake.v1'
            and manifest.get('collectionKind')=='EXISTING_COORDINATOR_AND_CUMULATIVE_HISTORY_INPUTS'
            and manifest.get('observationsAreHistorical') is True
            and all(manifest.get(k) is False for k in ('runtimeAuthorityIssued','applicationCutoverAuthorized','productionApplyReady')),'EXACT_SELECTED_HISTORICAL_COORDINATION_INTAKE_REQUIRED')
    files=manifest['fileHashes'];bindings=manifest['bindings']
    expected={'r12-authorization.json':EXPECTED_AUTH,'existing-coordinator.json':EXPECTED_OWNER,'retained-execution-configuration.json':EXPECTED_EXECUTION}
    require(all(files.get(k)==v for k,v in expected.items()) and bindings.get('r12AuthorizationHash')==EXPECTED_AUTH
            and bindings.get('coordinatorConfigurationHash')==EXPECTED_OWNER and bindings.get('executionConfigurationHash')==EXPECTED_EXECUTION,'REVIEWED_RETAINED_INSTALLATION_BINDING_CHANGED')
    def selected(name):return parse(custody.file_bytes(path.parent/name,0,{0o600},expected=files[name]))
    auth=selected('r12-authorization.json');worker=selected('r12-worker-status.json');invocation=selected('r12-worker-invocation.json');history=selected('r12-recovery-history.json')
    require(type(retained_programs) is dict and len(retained_programs)==15 and auth.get('programHashes')==retained_programs
            and auth.get('serviceUnit')==UNIT and auth.get('contextRef')==bindings.get('r12ContextRef')
            and auth.get('generationRef')==bindings.get('r12GenerationRef') and auth.get('incidentRef')==bindings.get('r12IncidentRef')
            and invocation=={'contextRef':auth['contextRef'],'pid':worker.get('workerPid'),'hostBootId':auth['hostBootId']}
            and history.get('contextRef')==auth['contextRef'] and history.get('generationRef')==auth['generationRef']
            and history.get('attempts')==bindings.get('recoveryAttempts') and history.get('publicationCount')==bindings.get('leasePublicationCount'),'REVIEWED_RETAINED_HISTORY_OR_SOURCE_DRIFT')
    require(custody.file_bytes(path,0,{0o600},expected=intake_binding['sha256'])==raw,'RETIREMENT_SCOPE_INPUT_CHANGED')
    return {'intakeBinding':dict(intake_binding),'authorizationBinding':{'path':str(R12/'authorization.json'),'sha256':EXPECTED_AUTH},
            'coordinatorBinding':{'path':str(GUARD/'coordinated-configuration.json'),'sha256':EXPECTED_OWNER},
            'executionBinding':{'path':str(CONTEXT/'execution-configuration.json'),'sha256':EXPECTED_EXECUTION},
            'r12Root':str(R12),'activationClaimPath':CLAIM,'ownerSourceRoot':str(GUARD/'source'),
            'programHashes':dict(retained_programs),'unit':UNIT,'workerPid':worker['workerPid'],'hostBootId':auth['hostBootId']}
