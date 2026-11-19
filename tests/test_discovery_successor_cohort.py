import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.semantic_cohort_admission import compose_successor_cohort as m


def fixture():
    # Real operator NIC/flow topology; synthetic independent launch/OCI and
    # authority references. No VPS private documents or real new CID is claimed.
    receipt=json.loads((ROOT/'evidence/discovery-generation-sources-read-operator-20261109.json').read_bytes())
    inputs={};recipes={}
    for role in m.ROLES:
        row=receipt['roles'][role];old=row['historicalContainerId']
        baseline=json.loads((ROOT/'tools/semantic_frame_compiler'/('containerd-overlayfs-'+role+'.json')).read_bytes())
        context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':old,
            'bundleParent':'/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
            'metadataParent':'/var/lib/docker/containers','networkNamespaceParent':'/run/docker/netns',
            'networkNamespaceName':None,'cgroupDriver':'systemd','rootfsPath':'/var/lib/docker/rootfs/overlayfs/'+old,
            'storageParent':'/var/lib/docker'}
        policy=m.compile_policy(baseline['template'],baseline['launch'],context)
        recipes[role]={'template':baseline['template'],'launch':baseline['launch'],'context':context,'policy':policy}
        row['installedPolicyBinding']['sha256']=m.digest(policy);row['installedApplicationHash']=m.digest(policy['expectedOci'])
    for role,other in (('adapter','southbound'),('southbound','adapter')):
        row=receipt['roles'][role];peer=receipt['roles'][other]
        row['peers']=[{'containerId':peer['historicalContainerId'],'applicationHash':peer['installedApplicationHash'],
                       'networkBindings':copy.deepcopy(peer['networkBindings'])}]
        flows=copy.deepcopy(row['transport'])
        for flow in flows:
            flow['authorityRef']='fixture-installation-authority'
            p=flow['peerIngress']
            if p['kind']=='CREATED_CANDIDATE':
                flow['peerIngress']={'kind':p['kind'],'bindingRef':p['bindingRef'],'declaration':copy.deepcopy(row['peers'][0])}
        row['transportSha256']=m.digest(flows)
        candidate={'containerId':row['historicalContainerId'],'transactionId':'old-'+role,
            'networkBindings':copy.deepcopy(row['networkBindings']),'transport':flows,'tableName':row['tableName'],
            'runtimeBinding':{'path':'/usr/bin/runc','sha256':'f'*64}}
        template={'schema':'ouf.semantic-admission-preparer-template.v1','pythonPath':'/usr/bin/python3','pythonHash':'a'*64,
            'commands':{'fixture':'no-command'},'commandHashes':{'fixture':'b'*64},'candidate':candidate,
            'kernel':{'fixture':'kernel'},'dns':{'fixture':'dns'},'coordinationBinding':{'transactionId':'old-coordinator'},
            'coordinationJournal':'/etc/ouf/old-coordinator.json','lockFile':'/run/guard.lock',
            'budgetSeconds':12,'hostNetworkNamespace':'/proc/1/ns/net'}
        selection={k:copy.deepcopy(template[k]) for k in m.COORDINATION}
        selection['coordinationBinding']['transactionId']='successor-coordinator'
        selection['coordinationJournal']='/etc/ouf/new-coordinator.json'
        inputs[role]={'schema':'ouf.discovery-role-generation-inputs.v1','role':role,'state':'UNSIGNED_INPUTS_ONLY',
            'historicalIdentityReuseAllowed':False,'runtimeConfigurationProduced':False,'startAuthorized':False,
            'historicalTemplate':template,'successorCoordination':selection}
    semantic={'containerId':'5'*64,'applicationHash':'6'*64,'networkBindings':[
        {'interface':'eth0','bridge':'br-113b5f0a3c53','mac':'b2:96:a1:e2:c1:8d','ipv4':'172.18.0.6',
         'workloadRef':'ouf-semantic','bindingRef':'semantic-backend'}]}
    args={'new_container_ids':{'adapter':'3'*64,'southbound':'4'*64},
          'new_transactions':{'adapter':'fresh-adapter','southbound':'fresh-southbound'},'semantic_declaration':semantic}
    return receipt,inputs,recipes,args


class SuccessorCohort(unittest.TestCase):
    def compile(self,change=None):
        receipt,inputs,recipes,args=fixture()
        if change:change(receipt,inputs,recipes,args)
        return m.compile_successor_pair(receipt,inputs,recipes,**args)

    def test_operator_receipt_exact_digest_and_closed_topology(self):
        r=json.loads((ROOT/'evidence/discovery-generation-sources-read-operator-20261109.json').read_bytes())
        self.assertEqual('8a0ed83e6cbbcd4f46802d610c5382a57605381242896a0145174f7fe2a31d3d',
                         __import__('hashlib').sha256(m.canonical(r)+b'\n').hexdigest())
        self.assertEqual([2,3],[len(r['roles'][k]['networkBindings']) for k in m.ROLES])
        self.assertEqual({'kind':'BRIDGE_PORT','ifindex':1377},r['roles']['southbound']['transport'][1]['peerIngress'])

    def test_complete_pair_recompiles_frames_and_binds_three_identities(self):
        receipt,inputs,recipes,args=fixture();original=copy.deepcopy((receipt,inputs,recipes,args))
        out=m.compile_successor_pair(receipt,inputs,recipes,**args)
        self.assertEqual(original,(receipt,inputs,recipes,args))
        for role,other in (('adapter','southbound'),('southbound','adapter')):
            row=out['roles'][role];new=row['preparerTemplate'];old=inputs[role]['historicalTemplate']
            self.assertEqual(args['new_container_ids'][role],new['candidate']['containerId'])
            self.assertEqual(args['new_transactions'][role],new['candidate']['transactionId'])
            self.assertEqual(old['candidate']['networkBindings'],new['candidate']['networkBindings'])
            self.assertEqual(inputs[role]['successorCoordination'],{k:new[k] for k in m.COORDINATION})
            expected=m.compile_policy(recipes[role]['template'],recipes[role]['launch'],row['dockerContext'])
            self.assertEqual(expected,row['framePolicy'])
            peer=new['candidate']['transport'][0]['peerIngress']['declaration']
            self.assertEqual(args['new_container_ids'][other],peer['containerId'])
            self.assertEqual(out['roles'][other]['applicationHash'],peer['applicationHash'])
            self.assertNotEqual(receipt['roles'][role]['installedApplicationHash'],row['applicationHash'])
            for a,b in zip(old['candidate']['transport'],new['candidate']['transport']):
                self.assertEqual({k:v for k,v in a.items() if k!='peerIngress'},{k:v for k,v in b.items() if k!='peerIngress'})
        semantic=out['roles']['southbound']['preparerTemplate']['candidate']['transport'][1]['peerIngress']
        self.assertEqual({'kind':'CREATED_CANDIDATE','declaration':args['semantic_declaration'],
                          'bindingRef':'semantic-backend'},semantic)
        self.assertNotIn('"ifindex"',json.dumps(out))
        self.assertNotIn('rootfsSeal',json.dumps(out))
        for key in ('creationOwnershipVerified','inputCustodyAuthenticated','semanticExpectationAuthenticated',
                    'currentPeersObserved','rootfsExpectationsProduced','historicalRootfsSealsReused',
                    'runtimeConfigurationProduced','authorityIssued','providerAdmissionProven','leaseAuthorized','startAuthorized'):
            self.assertIs(out[key],False)
        self.assertEqual(0,out['signaturesProduced'])

    def test_historical_duplicate_or_peer_cid_cannot_become_new_identity(self):
        for value in ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67','4'*64,'5'*64):
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.compile(lambda r,i,p,a:a['new_container_ids'].__setitem__('adapter',value))

    def test_old_role_old_coordinator_selected_coordinator_and_duplicate_transactions_rejected(self):
        for value in ('old-adapter','old-southbound','old-coordinator','successor-coordinator','fresh-southbound'):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'FRESH_DISTINCT_ROLE_TRANSACTIONS_REQUIRED'):
                self.compile(lambda r,i,p,a:a['new_transactions'].__setitem__('adapter',value))

    def test_mixed_or_changed_coordinator_kernel_cannot_be_selected(self):
        for kind in ('mixed','kernel','journal'):
            def changed(r,i,p,a):
                if kind=='mixed':i['adapter']['successorCoordination']['coordinationBinding']['transactionId']='different'
                else:
                    for role in m.ROLES:
                        s=i[role]['successorCoordination']
                        if kind=='kernel':s['kernel']={'changed':True}
                        else:s['coordinationJournal']=i[role]['historicalTemplate']['coordinationJournal']
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.compile(changed)

    def test_observed_or_changed_recipe_cannot_replace_independent_template(self):
        for kind in ('observed','policy','startup'):
            def changed(r,i,p,a):
                if kind=='observed':p['adapter']['observedOci']={}
                elif kind=='policy':p['adapter']['policy']['expectedOci']['process']['cwd']='/changed'
                else:p['adapter']['launch']['startup']['args']=['changed']
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.compile(changed)

    def test_borrowed_namespace_and_unknown_root_layout_rejected(self):
        context=fixture()[2]['adapter']['context']
        for key,value in (('networkNamespaceName','a'*12),('rootfsPath','/var/lib/docker/unknown')):
            mutated=copy.deepcopy(context);mutated[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.successor_context(mutated,'9'*64)

    def test_numeric_semantic_peer_or_missing_full_oci_hash_rejected(self):
        for value in ({'kind':'BRIDGE_PORT','ifindex':1377},{'containerId':'5'*64,'networkBindings':[]}):
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.compile(lambda r,i,p,a:a.__setitem__('semantic_declaration',value))

    def test_current_semantic_scope_cannot_move_to_another_network(self):
        for key,value in (('ipv4','172.18.0.7'),('bridge','oufsp-int')):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'EXACT_SEMANTIC_BACKEND_SCOPE_REQUIRED'):
                self.compile(lambda r,i,p,a:a['semantic_declaration']['networkBindings'][0].__setitem__(key,value))

    def test_modified_historical_index_refused_even_with_rehashed_transport(self):
        def changed(r,i,p,a):
            flows=i['southbound']['historicalTemplate']['candidate']['transport'];flows[1]['peerIngress']['ifindex']=1378
            r['roles']['southbound']['transportSha256']=m.digest(flows)
        with self.assertRaisesRegex(ValueError,'EXACT_HISTORICAL_SEMANTIC_FLOW_REQUIRED'):self.compile(changed)

    def test_extra_flow_refused_even_with_rehashed_receipt(self):
        def changed(r,i,p,a):
            flows=i['southbound']['historicalTemplate']['candidate']['transport'];flows.append(copy.deepcopy(flows[-1]))
            r['roles']['southbound']['transportSha256']=m.digest(flows)
        with self.assertRaisesRegex(ValueError,'EXACT_SOURCE_FLOW_COUNT_REQUIRED'):self.compile(changed)


if __name__=='__main__':unittest.main()
