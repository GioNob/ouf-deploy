"""Disposable Docker gate-window qualification, not provider/OCI/E2E admission.

Parent/child signatures, private journals, Engine calls and process observations
are real. The review, transition predecessor records and application are CI
fixtures. Java is deliberately absent from the Alpine image and never invoked.
"""
import copy,json,os,stat,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as signed
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile import gate_peer_window as m
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile,FILE_ROLES


def cli(*args):
    result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=40,
        env={**os.environ,'DOCKER_API_VERSION':'1.44'})
    if result.returncode:raise RuntimeError('CI_DOCKER_FAILED '+str(args[:2])+' '+result.stderr[-1000:])
    return result.stdout.strip()


def main(provider_creation=False):
    assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    auth=signed.Parent();auth.setUp();root=auth.root;tag=uuid.uuid4().hex[:12]
    network='ouf-gate-ci-'+tag;ids=[];calls=[]
    socket=Path('/var/run/docker.sock').resolve();s=socket.stat()
    engine=m.Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
    native_request=engine.request
    def recorded(method,path,body=None):
        calls.append((method,path));return native_request(method,path,body)
    engine.request=recorded
    try:
        cli('pull','alpine:3.22');image=cli('image','inspect','alpine:3.22','--format','{{.Id}}')
        nid=cli('network','create','--internal',network)
        request,selection,*_=fixture();request['Image']=image
        request['HostConfig']['NetworkMode']=network
        request['NetworkingConfig']={'EndpointsConfig':{network:{'NetworkID':nid}}}
        for i,role in enumerate(FILE_ROLES):
            spec=selection['files'][role];path=root/('material-'+str(i));path.write_bytes(('synthetic-'+role).encode())
            os.chown(path,spec['uid'],spec['gid']);path.chmod(spec['mode'])
            spec['source']=str(path);request['HostConfig']['Mounts'][i]['Source']=str(path)
        for index,key in ((5,'configtree'),(6,'renewable_token')):
            path=root/key;path.mkdir(mode=0o750);os.chown(path,0,10001)
            selection[key]['source']=str(path);request['HostConfig']['Mounts'][index]['Source']=str(path)
        profile=DiscoveryProfile(request,**selection)
        context=m.digest({'ci':tag});transition=object.__new__(m.Transition)
        transition.execution_profile=None;transition.profile_hash=None;transition.context=context
        status,created=engine.request('POST','/v1.44/containers/create?name='+engine.name(transition),request)
        assert status==201;cid=created['Id'];ids.append(cid)
        assert engine.request('POST','/v1.44/containers/'+cid+'/start')[0]==204
        process=m.GatedProcessObservation(request)
        end=time.monotonic()+10
        while True:
            actual=engine.matching_configuration(transition,request,engine.inspect(transition))
            observed=process.observe(actual['State']['Pid'])
            if observed['processKind']=='GATE_WAITING':break
            assert time.monotonic()<end,'NATIVE_GATE_TRAP_NOT_READY';time.sleep(.05)
        assert engine.request('POST','/v1.44/containers/'+cid+'/pause')[0]==204
        initial_binding=engine.runtime_binding(engine.inspect(transition));initial_generation=observed['generation']
        mutations_start=len(calls)

        def window(label):
            child,raw=auth.child(creation_request_hash=m.digest(request))
            evidence=root/('evidence-'+label);evidence.mkdir(mode=0o700);store=m.NativeEvidenceStore(evidence)
            actual=engine.inspect(transition);store.publish('STAGE_PAUSED_REPLACEMENT',actual)
            intents=m.decode(raw)['phaseIntentHashes'];authority_hash=m.hashlib.sha256(raw).hexdigest()
            row={'state':'READY','nextPhase':6,'creationRequestHash':m.digest(request),
                'transitionAuthorityEvidenceHash':authority_hash,'effects':[
                    {'phase':phase,'state':'APPLIED','intentHash':intents[phase],
                     'authorityEvidenceHash':authority_hash,
                     'nativeEvidenceHash':m.digest(actual) if i==5 else 'a'*64}
                    for i,phase in enumerate(m.PHASES[:6])]}
            transition.read=lambda:copy.deepcopy(row)
            directory=root/('window-'+label);directory.mkdir(mode=0o700)
            scope=m.window_scope(m.digest(request),profile.sha256,child.expected['sourceClosureHash'],directory,120)
            auth.review['components']['registryGatePeerWindow']=scope;parent=auth.fixture()
            return m.GatePeerWindow(parent=parent,child=child,child_raw=raw,engine=engine,transition=transition,
                request=request,profile=profile,store=store,directory=directory)

        normal=window('normal')
        with normal.peer_window():
            opened=normal.observe_open();assert opened['runtimeBinding']==initial_binding
            assert opened['generation']==initial_generation and not opened['ociAdmissionGranted']
            assert not opened['applicationSignalAuthorized']
            assert engine.inspect(transition)['State']['Paused'] is False
        assert normal.observe_closed()['state']=='CLOSED'
        try:
            with normal.peer_window():raise AssertionError('CONSUMED_WINDOW_REOPENED')
        except FileExistsError:pass

        failed=window('provider-failure')
        try:
            with failed.peer_window():raise RuntimeError('CI_PROVIDER_ADMISSION_FAILED')
        except RuntimeError as error:assert str(error)=='CI_PROVIDER_ADMISSION_FAILED'
        assert failed.observe_closed()['state']=='CLOSED'

        ambiguous=window('lost-unpause-response')
        def lost_response(method,path,body=None):
            status,value=recorded(method,path,body)
            return (500,value) if method=='POST' and path.endswith('/unpause') else (status,value)
        engine.request=lost_response
        try:
            with ambiguous.peer_window():raise AssertionError('AMBIGUOUS_OPEN_ENTERED_PROVIDER_ACTION')
        except ValueError as error:assert 'UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION' in str(error)
        finally:engine.request=recorded
        assert ambiguous.observe_closed()['state']=='CLOSED'
        before=len(calls)
        try:ambiguous.unpause_once();raise AssertionError('AMBIGUOUS_UNPAUSE_RETRANSMITTED')
        except ValueError:pass
        assert not any(method=='POST' for method,_ in calls[before:])

        provider_results=[]
        if provider_creation:
            from fixtures.m2_provider_creation_native import qualify
            provider_results=qualify(auth,window,engine,image,network,nid,ids,cli)
        final=engine.inspect(transition);assert final['State']['Paused'] is True
        assert engine.runtime_binding(final)==initial_binding
        assert process.observe(final['State']['Pid'])['generation']==initial_generation
        assert process.observe(final['State']['Pid'])['processKind']=='GATE_WAITING'
        effects=[path.rsplit('/',1)[-1] for method,path in calls[mutations_start:] if method=='POST' and path.endswith(('/unpause','/pause'))]
        assert effects==['unpause','pause']*(3+len(provider_results)),effects
        assert transition.read()['nextPhase']==6
        print(json.dumps({'schema':'ouf.m2-discovery-gate-peer-window-native-ci.v1','dockerVersion':'29.8.1',
            'realParentAndChildEd25519Signatures':True,'realPrivateJournals':True,
            'nativeSameGenerationGateObservation':True,'nativeUnpausePausePairs':3+len(provider_results),
            'providerCreationResults':provider_results,'providerCreationFixtureUsesUnstartedRuntimeAlias':provider_creation,
            'providerFailureContained':True,'ambiguousUnpauseContainedWithoutReplay':True,
            'nonRootCapabilitiesEmptyAndNoNewPrivileges':True,'javaExecOrSignalIssued':False,
            'syntheticReviewAndTransitionPredecessors':True,'providerAdmissionProven':False,
            'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
        subprocess.run(['docker','network','rm',network],capture_output=True,timeout=20)
        auth.doCleanups()


if __name__=='__main__':
    assert sys.argv[1:] in ([],['--provider-creation'])
    main(provider_creation=sys.argv[1:]==['--provider-creation'])
