"""Synthetic retained history/Engine responses; real transport, locks and crypto."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

import test_contract
from tools.semantic_registry_operational_owner import installation as install, core
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer


def prepare(fixture, source_root, *, real_unit=False):
    sys.path.insert(0,str(source_root/'tools/semantic_application_cutover'))
    from tools.semantic_live_route_diagnostic.reader import process_ticks
    base=test_contract.Contract();base.setUp();inputs=copy.deepcopy(base.inputs)
    root=fixture.root;native=root/'historical-native';owner=root/'historical-owner'
    native.mkdir(mode=0o700);owner.mkdir(mode=0o700)
    fixture.write(native/'invocation.lock',b'');common=fixture.write(owner/'invocation.lock',b'')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();pid=os.getpid()
    ns=Path('/proc')/str(pid)/'ns/net';s=ns.stat()
    generation=dict(pid=pid,startTicks=process_ticks(pid),bootId=boot,namespaceDevice=s.st_dev,namespaceInode=s.st_ino)
    cid='f'*64;calls=[];responses=[]
    row={'Id':cid,'Image':'sha256:'+'e'*64,'Config':{'Env':[]},'HostConfig':{},'Mounts':[],
         'NetworkSettings':{'Networks':{'synthetic':{'EndpointID':'synthetic-endpoint'}}},'RestartCount':0,
         'State':{'Running':True,'Paused':False,'Restarting':False,'Dead':False,'Pid':pid}}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            calls.append(('GET',self.path))
            value=responses.pop(0) if responses else row
            raw=core.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    socket=root/'fixture-engine.sock'
    server=socketserver.UnixStreamServer(str(socket),Handler);socket.chmod(0o600)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    fixture.addCleanup(lambda:(server.shutdown(),thread.join(2),server.server_close()))
    s=socket.stat()
    context=inputs['prepared']['nativeContext'];context.update(executionRoot=str(native),
        engineBinding={'socketPath':str(socket),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]},
        plan={'stages':[{'intent':{'registryId':cid}}]})
    inputs['prepared']['ownerContext']['ownerInputs']=copy.deepcopy(fixture.config['ownerInputs'])
    scope=inputs['retainedOwnerRecords']['owner-session.json'];scope.update(journalPath=str(owner),
        logicalOwnerScopeHash=hashlib.sha256(str(root).encode()).hexdigest(),currentSessionBootId=boot,
        ownerInputsHash=core.digest(inputs['prepared']['ownerContext']['ownerInputs']))
    legacy=root/'legacy-fence.json';value={'syntheticLegacyFence':True}
    fixture.write(legacy,core.encoded(value));scope['fenceBinding']={'path':str(legacy),'value':value}
    inputs['retainedFence']=copy.deepcopy(scope['fenceBinding'])
    journal=inputs['retainedNativeJournal'];journal.update(bootId=boot,newGeneration=generation)
    old=inputs['retainedOwnerRecords']['recovery.json'];old.update(workerSessionHash=core.digest(scope),bootId=boot,gateGeneration=generation)
    inputs['identity'].update(nativeJournalHash=core.digest(journal),ownerJournalHash=core.digest(old))
    inputs['review']['currentContext']=context;inputs['review']['ownerContext']=inputs['prepared']['ownerContext']
    inputs['review']['scopes']['semanticRegistryPostbootOwner']=scope
    inputs['currentRegistryObservation']=copy.deepcopy(row)
    for name,v in inputs['retainedOwnerRecords'].items():fixture.write(owner/name,core.encoded(v))
    fixture.write(native/'recovery.json',core.encoded(journal));fixture.write(native/'native-reads.json',core.encoded(inputs['retainedNativeReads']))
    programs={'python':fixture.binding(Path(sys.executable).resolve()),'openssl':fixture.config['verification']['openssl'],
              'systemctl':fixture.binding(Path(shutil.which('systemctl')).resolve())}
    authority_inputs={'executables':programs,'authorityProfile':{'syntheticFixtureProfile':True},
        'trustPolicy':fixture.binding(fixture.trust),'context':fixture.ctx,'stdlibHash':'a'*64,'stdlibFileCount':1}
    inputs['review']['authorityInputs']=authority_inputs
    input_file=fixture.write(root/'captured-inputs.json',core.encoded(inputs))
    spec=importlib.util.spec_from_file_location('operational_capsule_builder_fixture',source_root/'scripts/build-registry-operational-owner-capsule.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    capsule,delivery=builder.build('a'*40)
    cap=fixture.write(root/'source-capsule.py',capsule,0o400)
    parent=root/'deployment';parent.mkdir(mode=0o700)
    unit_parent=Path('/etc/systemd/system') if real_unit else root/'unit-files'
    if not real_unit:unit_parent.mkdir(mode=0o755)
    from tools.semantic_registry_operational_owner.store import file_identity
    review=install.make_review(inputs,fixture.binding(input_file),delivery['sourceManifest'],fixture.binding(cap),
        fixture.binding(fixture.ca),parent=str(parent),unit_parent=str(unit_parent),common_identity=list(file_identity(common.stat())),
        authority_inputs=authority_inputs,policy=fixture.policy)
    review_root=root/'review';review_root.mkdir(mode=0o700)
    review_path=fixture.write(review_root/'review.json',core.encoded(review))
    signatures=review_root/'authority';signatures.mkdir(mode=0o700)
    now=int(time.time());raw=core.encoded({'schema':install.AUTHORITY_SCHEMA,'scope':install.review_scope(review),
        'issuedAt':now,'expiresAt':now+900,'installationRef':fixture.ctx['installationRef'],'entityRef':fixture.ctx['entityRef'],
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False})
    human={'schema':install.HUMAN_SCHEMA,'reviewHash':core.digest(review),'authorityHash':hashlib.sha256(raw).hexdigest(),
           'decision':install.DECISION,'state':'ACTIVE','issuedAt':now,'expiresAt':now+900}
    human_path=fixture.write(signatures/'human.json',core.encoded(human))
    verifier=DetachedAuthenticator(fixture.binding(fixture.trust),str(signatures),programs['openssl'])
    for role in('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):
        signer=ExistingEd25519Signer(fixture.binding(fixture.signing_key),'fixture-installer-key',verifier,
            {'role':role,'issuerRef':fixture.ctx['intentIssuerRef'],'installationRef':fixture.ctx['installationRef'],'entityRef':fixture.ctx['entityRef']})
        fixture.write(signatures/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json'),signer.sign(raw))
    authority=install.SignedInstallation(review,raw,fixture.binding(human_path),core.digest(human),verifier)
    attestor=ExistingEd25519Signer(fixture.binding(fixture.signing_key),'fixture-attestor-key',verifier,
        {'role':'CREATION_ATTESTATION','issuerRef':fixture.ctx['attestorRef'],
         'installationRef':fixture.ctx['installationRef'],'entityRef':fixture.ctx['entityRef']})
    return {'review':review,'inputs':inputs,'authority':authority,'attestor':attestor,'calls':calls,'responses':responses,
            'registryRow':row,'legacyFence':legacy,'reviewPath':review_path}
