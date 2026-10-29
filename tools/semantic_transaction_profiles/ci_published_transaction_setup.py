"""Disposable native CI: signed inputs through the actual publisher and broker.

Only the caller-owned kernel tables, role keys, image and target identities are
synthetic. No fixture creates transaction files or result directories, and no
CI broker intercepts a runtime invocation. This is never target authorization.
"""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from unittest.mock import patch

import authenticate_provider_transaction as authentication
import issue_provider_transaction_authority as issuance
from assemble_provider_profiles import digest, encoded
from guarded_runtime_switch import verify_installed_plan
from publish_provider_transaction import publish_plan, producer_result_directories
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, VerificationBudget


def prepare(root, source, python, commands, lock, inputs, networks, kernels,
            cids, seal, image, empty_adapter, run, suffix, tables,*,seals_by_role=None):
    def private(path, value):
        path.write_bytes(encoded(value)); path.chmod(0o600)

    def bind(path):
        return {'path': str(path), 'sha256': digest(Path(path).read_bytes())}

    # Root-owned, independent role custody. No target key is accessible here.
    authority_root = root/'ci-authority'; authority_root.mkdir(mode=0o700)
    signatures = authority_root/'signatures'; signatures.mkdir(mode=0o700)
    authorities = {'installationRef':'ci-installation', 'entityRef':'ci-entity',
        'intentIssuerRef':'ci-installer', 'approvalIssuerRef':'ci-installer', 'attestorRef':'ci-node-verifier'}
    now = int(time.time()); keys = {}; grants = []
    for role, issuer, scopes in (
        ('installer', authorities['approvalIssuerRef'], ['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
        ('attestor', authorities['attestorRef'], ['CREATION_ATTESTATION'])):
        key = authority_root/(role+'.pem')
        run(commands['openssl'], 'genpkey', '-algorithm', 'ED25519', '-out', str(key)); key.chmod(0o600)
        public = run(commands['openssl'], 'pkey', '-in', str(key), '-pubout', '-outform', 'DER').stdout
        if public[:12] != bytes.fromhex('302a300506032b6570032100'):
            raise RuntimeError('CI_ED25519_PUBLIC_KEY_REQUIRED')
        keys[role] = key
        grants.append({'keyRef':role+'-ci-key', 'issuerRef':issuer, 'roles':scopes,
            'publicKey':public[12:].hex(), 'notBefore':now-30, 'expiresAt':now+600, 'state':'ACTIVE'})
    policy = authority_root/'trust.json'
    private(policy, {'schema':'ouf.semantic-deployment-trust-policy.v1',
        'installationRef':authorities['installationRef'], 'entityRef':authorities['entityRef'], 'keys':grants})
    crypto = {'policyBinding':bind(policy), 'signatureDirectory':str(signatures),
        'opensslBinding':{**bind(commands['openssl']), 'version':run(commands['openssl'],'version').stdout.decode().split()[1]}}
    authority = {'authorities':authorities, 'keyBindings':{role:bind(key) for role,key in keys.items()},
                 'keyRefs':{role:role+'-ci-key' for role in keys}}
    closure = json.loads(Path(__file__).with_name('intake-source-closure.json').read_bytes())
    sources = {name.removeprefix('source/'):(source/name.removeprefix('source/')).read_bytes()
               for name in closure['sourceHashes'] if name.startswith('source/')}
    observer = Path(__file__).with_name('frame-observer.py').read_bytes()
    source_hash = digest(encoded({**{p:digest(raw) for p,raw in sources.items()}, 'frame-observer.py':digest(observer)}))
    runtime = bind(commands['runc']); python_binding = bind(python)
    targets = {role:{'containerId':cids[i], 'imageManifestDigest':image, 'imageConfigDigest':image,
                     'runtimeSeal':copy.deepcopy(seals_by_role[role] if seals_by_role else seal)} for i,role in enumerate(('adapter','southbound'))}
    declarations = [{'containerId':cids[i], 'applicationHash':digest(encoded(inputs[i]['framePolicy']['expectedOci'])),
                     'networkBindings':networks[i]} for i in range(2)]

    records = {}; mandates = {}
    for i,role in enumerate(('adapter','southbound')):
        cid = cids[i]; tx = digest(('ci-'+cid).encode()); shared = 'ccs_'+suffix+str(i)
        kernel = kernels[i]; tables.extend([shared,kernel['tableName']])
        run(commands['nft'],'-f','-',payload=materialize(kernel,empty_provider_sets=True)['nftRules'].encode())
        native = {f:json.loads(run(commands['nft'],'-j','list','table',f,kernel['tableName']).stdout) for f in ('inet','bridge')}
        coordination = {'transactionId':tx, 'configurationHash':digest(encoded(kernel)), 'leaseStructureHash':structure_hash(native)}
        coordination_path = authority_root/('coordination-'+role+'.json')
        private(coordination_path, {'schema':'ouf.semantic-lease-coordination.v1', **coordination,
            'state':'QUIESCED', 'leaseAuthorized':False, 'startAuthorized':False, 'leaseAddresses':[[]]})
        flow = {'purpose':'GATEWAY_ADAPTER', 'authorityRef':'ci-infrastructure',
            'source':networks[0][0]['ipv4'], 'destination':networks[1][0]['ipv4'], 'protocol':'tcp', 'port':9443,
            'peerIngress':{'kind':'CREATED_CANDIDATE', 'declaration':declarations[1-i], 'bindingRef':networks[1-i][0]['bindingRef']}}
        candidate = {'containerId':cid, 'transactionId':tx, 'networkBindings':networks[i],
                     'transport':[flow], 'tableName':shared, 'runtimeBinding':runtime}
        native_commands = {k:commands[k] for k in ('nft','ip','nsenter','unshare','mount','umount')}
        preparer = {'schema':'ouf.semantic-admission-preparer-template.v1', 'pythonPath':python, 'pythonHash':python_binding['sha256'],
            'commands':native_commands, 'commandHashes':{k:bind(v)['sha256'] for k,v in native_commands.items()},
            'candidate':candidate, 'kernel':kernel,
            'dns':{'resolvers':['127.0.0.1'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1},
            'coordinationBinding':coordination, 'coordinationJournal':str(coordination_path), 'lockFile':str(lock),
            'budgetSeconds':5, 'hostNetworkNamespace':os.stat('/proc/self/ns/net').st_ino}
        built = datetime.fromtimestamp(now-60,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        values = {**inputs[i], 'preparerTemplate':preparer,
            'deploymentConstraints':{'scope':'DISPOSABLE_CI_ONLY','containerId':cid},
            'provenanceEvidence':{'scope':'OFFLINE_CI_IMAGE_ONLY'},
            'dependencyEvidence':{'schema':'ouf.semantic-provider-dependency-evidence.v1','role':role,'imageConfigDigest':image,
                'databasePin':{'status':'active','schemaVersion':'v6.1.10','built':built,'path':'disposable-ci.tar.zst','checksum':'sha256:'+'a'*64},
                'reportSha256':'b'*64,'inventorySha256':'c'*64,'sourceArtifactSha256':'d'*64,
                'scanDatabaseBuilt':built,'scanDatabaseSchemaVersion':'v6.1.10',
                'severityCounts':{k:0 for k in ('Critical','High','Medium','Low','Negligible','Unknown')},
                'packageAlertCount':0,'ignoredMatchCount':0}}
        raw = {name:encoded(value) for name,value in values.items()}
        mandate = {'schema':'ouf.semantic-provider-transaction-role-mandate.v1', 'role':role,
            'installationRef':authorities['installationRef'], 'entityRef':authorities['entityRef'], **targets[role],
            'inputHashes':{k:digest(v) for k,v in raw.items()}, 'sourceClosureHash':source_hash,
            'roleSigningScopes':issuance.SCOPES, 'state':'ACTIVE',
            'decision':'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION',
            'transactionId':tx, 'approvalRef':'ci-mandate-'+cid, 'issuedAt':now, 'expiresAt':now+240}
        mandate_path = authority_root/(role+'-root-mandate.json'); private(mandate_path,mandate)
        mandates[role] = bind(mandate_path); records[role] = raw
    with patch.object(authentication,'TARGETS',targets), patch.object(authentication,'AUTHORITIES',authorities), \
         patch.object(issuance,'TARGETS',targets), patch.object(issuance,'AUTHORITIES',authorities):
        for validate_only in (True,False):
            for role in records:
                directory = authority_root/role
                if not validate_only: directory.mkdir(mode=0o700)
                verifier = DetachedAuthenticator(crypto['policyBinding'],crypto['signatureDirectory'],
                    crypto['opensslBinding'],budget=VerificationBudget(18))
                issued = issuance.issue_role_authority(role,mandates[role],mandates[role]['sha256'],
                    records[role],authority,sources,observer,verifier,directory,validate_only=validate_only)
                if not validate_only:
                    records[role].update({name:Path(binding['path']).read_bytes() for name,binding in issued['records'].items()})
    destination = root/'published'
    verifier = DetachedAuthenticator(crypto['policyBinding'],crypto['signatureDirectory'],crypto['opensslBinding'])
    # Constant selection is patched only in this CI process. Authenticator,
    # compiler, publication and child production programs are unmodified.
    with patch.object(authentication,'TARGETS',targets), patch.object(authentication,'AUTHORITIES',authorities):
        plan = authentication.build_install_plan(str(destination),str(destination/'source'),records,
            authority,sources,observer,python_binding,crypto,verifier,empty_adapter)
    publish_plan(destination,plan,sources,observer)
    verify_installed_plan(plan)
    for path in producer_result_directories(plan['adapterConfiguration']):
        if list(path.iterdir()) or path.stat().st_mode & 0o777 != 0o700:
            raise RuntimeError('CI_PRODUCTION_PUBLISHER_RESULT_DIRECTORY_REQUIRED')
    if plan['adapterConfiguration']['admissionPath'] != str(destination/'source/scripts/semantic_provider_deployment_broker.py'):
        raise RuntimeError('CI_PRODUCTION_BROKER_REQUIRED')
    return plan['adapterConfiguration']
