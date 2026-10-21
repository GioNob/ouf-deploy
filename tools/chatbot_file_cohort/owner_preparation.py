"""Collect the complete finite token-owner input in the single private intake.

Only retained evidence, current IAM metadata and authenticated discovery are
read. This module neither obtains a SERVICE token nor initializes histories,
rotates credentials, signs authority or changes a service.
"""
import copy
import dataclasses
import os
from pathlib import Path
import re
import resource
import ssl
import subprocess
import tempfile
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
import iam_install_inputs_probe as discovery
import migration_root_custody as custody
import legacy_retirement as legacy
from accounting_gap_session import boot_identity
from credential_reestablishment import stable_registration
from iam_audience_transaction import MapperAdmin, equivalent
from tools.semantic_lease_recovery.bounded_recovery import Policy
from tools.semantic_policy_token_owner.producer import Binding
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener

ROOT_RECEIPT = '8b7698791f95d84454a65eb9e80ad3061e9d4c32d6efc427930859320e1f8b0d'
ROOT_SOURCE = '9b78689d3bc4144a005abd5ab7cf8365a7c99e67a0057dfc84d2d27447479623'
RETAINED = {
    'host': ('policy-token-migration-host-inputs-'+legacy.HOST_HASH+'.private.json',legacy.HOST_HASH),
    'snapshot': ('policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json',
                 '7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927'),
    'candidate': ('policy-token-iam-binding-b825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b.private.json',
                  'b825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b'),
    'audience': ('policy-token-introspection-review-4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76.private.json',
                 '4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76'),
}


def bounded_output():
    resource.setrlimit(resource.RLIMIT_FSIZE,(262145,262145))


def policy_metadata(docker_binding, engine_path):
    """Use the already established GET contract including global metadata."""
    deadline=time.monotonic()+45;result={}
    for name,query in (('policies','include-global-policies=true'),('profiles','include-global-profiles=true')):
        remaining=deadline-time.monotonic()
        evidence.require(remaining>0,'CURRENT_CLIENT_POLICY_READ_DEADLINE')
        argv=[docker_binding['path'],'--host','unix://'+engine_path,'exec','ouf-keycloak',
            '/opt/keycloak/bin/kcadm.sh','get','client-policies/'+name,
            '--server','http://localhost:8080','-r','ouf','-q',query]
        with tempfile.TemporaryFile() as output:
            reply=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
                timeout=min(15,remaining),preexec_fn=bounded_output,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            output.seek(0);raw=output.read(262145)
        evidence.require(reply.returncode==0 and 0<len(raw)<=262144,'CURRENT_CLIENT_POLICY_READ_UNAVAILABLE')
        value=evidence.decode(raw)
        expected={name,'global'+name.capitalize()}
        evidence.require(type(value) is dict and set(value)==expected
            and all(type(rows) is list and len(rows)<=128 and all(type(row) is dict for row in rows)
                    for rows in value.values()),'COMPLETE_CURRENT_CLIENT_POLICY_METADATA_REQUIRED')
        result[name]=value
    # The retained target has no enabled realm/global policies. Unknown or newly
    # enabled policy effects cannot silently change a reviewed secret rotation.
    for rows in result['policies'].values():
        evidence.require(all(type(row.get('enabled')) is bool and row['enabled'] is False for row in rows),
                         'ENABLED_CLIENT_POLICY_CHANGED_REQUIRES_REVIEW')
    return result


def reconciled_metadata(snapshot,current,audience_plan):
    """Retain only the one previously applied and reconciled audience delta."""
    evidence.require(audience_plan.get('schema')=='ouf.policy-token-introspection-audience-review-plan.v1'
        and audience_plan.get('snapshotHash')==RETAINED['snapshot'][1],
        'RETAINED_AUDIENCE_REVIEW_REQUIRED')
    change=audience_plan.get('changeProposal',{})
    desired=change.get('proposedMapper')
    evidence.require(change.get('operation')=='ADD_EXACT_CALLER_AUDIENCE_MAPPER'
        and change.get('resource')=='clients/'+snapshot['client']['id']+'/protocol-mappers/models'
        and type(desired) is dict,'EXACT_RETAINED_AUDIENCE_CHANGE_REQUIRED')
    candidate=copy.deepcopy(current)
    rows=candidate['client']['protocolMappers']
    matches=[m for m in rows if m.get('name')==desired.get('name') or m.get('id')==desired.get('id')]
    evidence.require(len(matches)==1 and equivalent(matches[0],desired),
                     'PREVIOUSLY_APPLIED_CALLER_AUDIENCE_NOT_RECONCILED')
    candidate['client']['protocolMappers']=[m for m in rows if m['id']!=matches[0]['id']]
    evidence.require(candidate==snapshot,'CURRENT_COMPLETE_IAM_BASELINE_DRIFT')
    return evidence.sha(evidence.encoded(matches[0]))


def compile_owner_inputs(candidate,snapshot,registration,peers,root_identities,host_binding,
                         source_commit,source_closure_hash,cohort_id):
    evidence.require(candidate.get('schema')=='ouf.policy-token-iam-binding-candidate.v3'
        and candidate.get('snapshotHash')==RETAINED['snapshot'][1]
        and candidate.get('reviewReasons')==[] and candidate.get('metadataOnlyNoBearerAdmission') is True
        and candidate.get('runtimeAuthorityIssued') is False and candidate.get('productionApplyReady') is False,
        'EXACT_RETAINED_REVIEWED_IAM_BINDING_REQUIRED')
    reference=candidate['reference'];client=snapshot['client']
    registration=stable_registration(registration)
    evidence.require(registration['id']==client['id'] and registration['clientId']==candidate['clientId']
        and candidate['candidateSubjectId']==snapshot['serviceAccount']['id']
        and candidate['issuer']==reference['issuer']==discovery.ISSUER and reference['actor']=='SERVICE',
        'CURRENT_OWNER_CLIENT_SUBJECT_AND_ISSUER_REQUIRED')
    for name in ('enabled','serviceAccountsEnabled','publicClient','clientAuthenticatorType','protocol'):
        evidence.require(registration[name]==client[name],'CURRENT_OWNER_CORE_CHANGED')
    evidence.require(re.fullmatch('[0-9a-f]{40}',source_commit)
        and re.fullmatch('[0-9a-f]{64}',source_closure_hash)
        and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',cohort_id),
        'EXACT_CURRENT_COHORT_AND_SOURCE_IDENTITIES_REQUIRED')
    profile=IamProfile(candidate['issuer'],candidate['issuer']+'/protocol/openid-connect/token',
        candidate['issuer']+'/protocol/openid-connect/token/introspect',candidate['clientId'],
        candidate['candidateSubjectId'],reference['tenant'],reference['audience'],
        tuple(candidate['requestedScopes']),tuple(candidate['candidateAllowedScopeEnvelope']),tuple(peers))
    binding=Binding(profile.token_endpoint,profile.client_id,' '.join(profile.required_scopes),
        str(Path(root_identities['durableRecovery']['path'])/'token-output'),'token.jwt',10001)
    profile.match(binding)
    context=evidence.sha(evidence.encoded({'cohortId':cohort_id,'sourceClosureHash':source_closure_hash,
        'logicalOperation':'FIRST_COMPLETE_TOKEN_OWNER_INSTALLATION','clientId':profile.client_id}))
    generation=evidence.sha(evidence.encoded({'contextRef':context,'bootId':boot_identity(),
        'roots':root_identities,'completedRootEvidenceHash':ROOT_RECEIPT}))
    return {'hostInputBinding':host_binding,'rootEvidenceHash':ROOT_RECEIPT,'rootCreationSourceClosureHash':ROOT_SOURCE,
        'registration':registration,'binding':dataclasses.asdict(binding),'iamProfile':dataclasses.asdict(profile),
        'tlsTrustSetHash':PinnedIamOpener(profile).trust_digest(),'sourceCommit':source_commit,
        'policy':dataclasses.asdict(Policy(max_elapsed=3600)),
        'contextRef':context,'generationRef':generation,'intervalSeconds':60}


def prepare_owner(*,source_commit,source_closure_hash,cohort_id,docker_binding,engine_path):
    evidence.require(governance.executable(docker_binding['path'])==docker_binding
        and docker_binding['path']=='/usr/bin/docker' and os.environ.get('DOCKER_HOST')=='unix://'+engine_path,
        'SELECTED_NATIVE_OWNER_METADATA_CHANNEL_REQUIRED')
    with evidence.protected_parent() as directory:
        raw={key:evidence.read_member(directory,name) for key,(name,_) in RETAINED.items()}
        evidence.require(all(evidence.sha(raw[key])==digest for key,(_,digest) in RETAINED.items()),
                         'RETAINED_OWNER_PREPARATION_EVIDENCE_CHANGED')
        values={key:evidence.decode(body) for key,body in raw.items()}
        evidence.require(values['host']['kernelBootId']==boot_identity(),'RETAINED_OWNER_KERNEL_BOOT_CHANGED')
        with custody.completed_roots(raw['host'],ROOT_RECEIPT,ROOT_SOURCE) as roots:
            selected=values['snapshot']['client']['id'];admin=MapperAdmin(selected)
            admin.deadline=time.monotonic()+120
            current=admin.baseline(values['snapshot'])
            audience_hash=reconciled_metadata(values['snapshot'],current,values['audience'])
            # ClientRepresentation can contain a secret field. Strip it in
            # memory immediately; never retain, print or request client-secret.
            registration=stable_registration(evidence.decode(admin.command('get',resource='clients/'+selected)))
            policies=policy_metadata(docker_binding,engine_path)
            peers=discovery.addresses();context=ssl.create_default_context()
            report={'discoveryGetAttempts':0}
            observations=[discovery.peer_discovery(address,context,report) for address in peers]
            evidence.require(discovery.addresses()==peers,'CURRENT_OWNER_PEER_SET_CHANGED')
            owner=compile_owner_inputs(values['candidate'],values['snapshot'],registration,peers,roots,
                {'path':str(evidence.PARENT/RETAINED['host'][0]),'sha256':RETAINED['host'][1]},
                source_commit,source_closure_hash,cohort_id)
            evidence.require(stable_registration(evidence.decode(admin.command('get',resource='clients/'+selected)))==registration,
                             'CURRENT_OWNER_REGISTRATION_CHANGED_DURING_PREPARATION')
        evidence.require(all(evidence.read_member(directory,RETAINED[key][0])==body for key,body in raw.items()),
                         'RETAINED_OWNER_EVIDENCE_CHANGED_DURING_PREPARATION')
    return {'owner':owner,'evidence':{'schema':'ouf.chatbot-file-cohort-owner-inputs.v1',
        'retainedHashes':{key:value[1] for key,value in RETAINED.items()},
        'currentIamBaselineHash':evidence.sha(evidence.encoded(current)),
        'reconciledCallerAudienceHash':audience_hash,'clientPolicyMetadataHash':evidence.sha(evidence.encoded(policies)),
        'httpsPeers':observations,'runtimeAuthorityIssued':False,'tokenGrantRequests':0,
        'iamMutations':0,'budgetReset':False,'historicalAccountingReconciled':False,'notReleaseAcceptance':True}}
