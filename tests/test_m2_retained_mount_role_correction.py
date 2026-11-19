"""Regression: real producer schema permits arbitrary/shadow inventory aliases.

Root-private predecessor/metadata are real; unit Engine and process pins modeled.
The fixed production roster is independently checked against the accepted public
receipt; no real private target input is included in repository fixtures.
"""
import copy, json, os, sys, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.m2_discovery_installation_profile import retained_mount_role_correction as m
from tools.m2_discovery_installation_profile import retained_mount_capture as old
import test_m2_retained_mount_capture as fixture

FAILURE={'automaticReplayAllowed':False,'reasonCode':'EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED',
    'runtimeAuthorityIssued':False,'schema':'ouf.m2-retained-mount-capture-result.v1','scopeConsumed':True,
    'status':'STOP_RECONCILE','targetApplyAuthorized':False}


def alias_fixture(seed):
    roles=sorted(old.ROLES)
    # Misleading valid role labels deliberately point at other roles. Runtime
    # must select exact IDs, never the alias or container Name.
    aliases={r:roles[(i+1)%13] for i,r in enumerate(roles)}
    aliases[roles[-1]]='retained::inventory-v38'
    seed['observations']={aliases[r]:v for r,v in seed['observations'].items()}
    seed['processPins']={aliases[r]:v for r,v in seed['processPins'].items()}
    return aliases


def roster_for(seed,aliases):
    return {r:{'containerId':seed['observations'][a]['Id'],
        'nativeBindingHash':m.digest(m.stable_binding(seed['observations'][a])),
        'generation':seed['processPins'][a]} for r,a in aliases.items()}


class RoleCorrection(unittest.TestCase):
    def prepared(self):
        case=fixture.RetainedMetadata();self.addCleanup(case.doCleanups)
        c,args,seed,root,mounted,mutable,reads=case.prepared()
        predecessor=c.scope
        aliases=alias_fixture(seed)
        args['seed_path'].write_bytes(m.encoded(seed));args['seed_hash']=m.digest(seed)
        # Execute the actual frozen failing guard; do not invent an effect-free
        # success receipt. It must fail before the Engine is constructed.
        with self.assertRaisesRegex(ValueError,'EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED'):
            old.collect(c,**args)
        self.assertEqual(c.counts['engineGets'],0);self.assertFalse(reads)
        c.put('result.json',FAILURE)
        corrected=m.RetainedCapture(root/'correction')
        args.update(predecessor_root=predecessor,roster=roster_for(seed,aliases))
        # Original fixture Engine selected a dictionary that alias_fixture
        # replaced; retain the same rows in that dictionary for native drifts.
        class Engine:
            def __init__(engine,capture,binding,ids):engine.c=capture;engine.ids=set(ids)
            def get(engine,cid):
                self.assertIn(cid,engine.ids);reads.append(cid);engine.c.counts['engineGets']+=1
                return copy.deepcopy(next(v for v in seed['observations'].values() if v['Id']==cid))
        args['engine_factory']=Engine
        return corrected,args,seed,root,mounted,reads,aliases

    def rewrite(self,args,seed):
        args['seed_path'].write_bytes(m.encoded(seed));args['seed_hash']=m.digest(seed)

    def test_real_frozen_failure_then_id_selected_shadow_aliases_twenty_gets(self):
        c,args,seed,_,mounted,reads,aliases=self.prepared()
        predecessor=args['predecessor_root'];before={p.name:p.read_bytes() for p in predecessor.iterdir()}
        actual_open=os.open
        allowed={str(args['seed_path']),str(predecessor/'capture.claim.json'),str(predecessor/'result.json')}
        def no_mount_content(path,flags,*a,**kw):
            if not flags & (os.O_PATH|os.O_DIRECTORY|os.O_WRONLY|os.O_RDWR):
                self.assertIn(str(path),allowed)
            return actual_open(path,flags,*a,**kw)
        with patch.object(old.os,'open',side_effect=no_mount_content):result=m.collect(c,**args)
        self.assertEqual(len(reads),20);self.assertEqual(result['cumulativeControlAttempts'],2)
        self.assertEqual(result['cumulativeEngineGetAttempts'],20);self.assertTrue(result['predecessorPreserved'])
        private=json.loads((c.scope/'retained-mounts.private.json').read_bytes())
        self.assertEqual(private['inventoryRoleMap'],aliases)
        self.assertEqual(set(private['peers']),old.RETAINED)
        for role,row in private['peers'].items():self.assertEqual(row['containerId'],args['roster'][role]['containerId'])
        self.assertEqual(before,{p.name:p.read_bytes() for p in predecessor.iterdir()})
        self.assertEqual(result['counts']['mountFileContentBytesRead'],0)
        self.assertNotIn(str(mounted),json.dumps(result));self.assertFalse(result['targetApplyAuthorized'])
        self.assertEqual(result['counts']['metadataReads'],3)
        self.assertFalse(private['budgetProfile']['predecessorClockResumed'])
        self.assertFalse(private['budgetProfile']['runtimeBudgetsGranted'])

    def test_production_roster_exactly_matches_hash_bound_accepted_public_receipt(self):
        evidence=json.loads((ROOT/'evidence/m2-discovery-current-bindings-target-20261029.json').read_text())
        receipt=evidence['receipt'];self.assertEqual(m.digest(receipt),m.PUBLIC_ROSTER_HASH)
        self.assertEqual(receipt['inputsHash'],m.SEED_HASH)
        indexed={b['containerId']:b for b in receipt['bindings']}
        self.assertEqual(len(indexed),13);self.assertEqual(set(m.ROSTER),old.ROLES)
        self.assertEqual({v['containerId'] for v in m.ROSTER.values()},set(indexed))
        for role,v in m.ROSTER.items():
            self.assertEqual(v,{k:indexed[v['containerId']][k] for k in v})
            name=indexed[v['containerId']]['name']
            if role=='semantic':self.assertTrue(name.startswith('/ouf-semantic-cutover-'))
            else:self.assertEqual(name,'/ouf-gateway-operational-owner' if role=='gateway-owner' else '/ouf-'+role)
        self.assertEqual(m.digest(FAILURE),m.PREDECESSOR_HASH)
        import hashlib
        self.assertEqual(hashlib.sha256(Path(old.__file__).read_bytes()).hexdigest(),m.PREDECESSOR_SOURCE_SHA256)

    def test_duplicate_missing_or_wrong_role_id_rejected_before_engine(self):
        for kind in ('duplicate','missing','outside-id'):
            c,args,seed,_,_,reads,aliases=self.prepared();a,b=list(seed['observations'])[:2]
            if kind=='duplicate':seed['observations'][b]['Id']=seed['observations'][a]['Id']
            elif kind=='missing':del seed['observations'][b];del seed['processPins'][b]
            else:seed['observations'][b]['Id']='f'*64
            self.rewrite(args,seed)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.collect(c,**args)
            self.assertFalse(reads)

    def test_full_configuration_network_image_pid_and_pin_are_bound(self):
        for kind in ('config','network','image','pid','pin'):
            c,args,seed,_,_,reads,aliases=self.prepared();alias=aliases['onboarding'];row=seed['observations'][alias]
            if kind=='config':row['Config']['Env']=['CHANGED']
            elif kind=='network':row['NetworkSettings']['changed']=True
            elif kind=='image':row['Image']='sha256:'+'f'*64
            elif kind=='pid':row['State']['Pid']+=1
            else:seed['processPins'][alias]['startTicks']+=1
            # Do not mutate the expected roster generation by shared reference.
            args['roster']=copy.deepcopy(args['roster'])
            if kind=='pin':args['roster']['onboarding']['generation']['startTicks']-=1
            self.rewrite(args,seed)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.collect(c,**args)
            self.assertFalse(reads)

    def test_bad_predecessor_extra_output_permissions_hash_reason_or_claim_never_reads_engine(self):
        for kind in ('extra','mode','hash','reason','claim','missing'):
            c,args,_,_,_,reads,_=self.prepared();p=args['predecessor_root']
            if kind=='extra':(p/'retained-mounts.private.json').write_text('{}')
            elif kind=='mode':p.chmod(0o755)
            elif kind in ('hash','reason'):
                value=copy.deepcopy(FAILURE);value['reasonCode']='OTHER_FAILURE' if kind=='reason' else value['reasonCode'];value['unknown']=True
                (p/'result.json').write_bytes(m.encoded(value))
            elif kind=='claim':(p/'capture.claim.json').write_bytes(m.encoded({'automaticReplayAllowed':True}))
            else:(p/'result.json').unlink()
            with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):m.collect(c,**args)
            self.assertFalse(reads);self.assertFalse((c.scope/'retained-mounts.private.json').exists())

    def test_hash_schema_flags_or_role_keyed_seed_are_not_alternative_corrective_inputs(self):
        for kind in ('hash','schema','authority','domain','role-keys'):
            c,args,seed,_,_,reads,aliases=self.prepared()
            if kind=='hash':args['seed_hash']='0'*64
            elif kind=='schema':seed['schema']='different'
            elif kind=='authority':seed['runtimeAuthorityIssued']=True
            elif kind=='domain':seed['processPins']['unknown']=seed['processPins'].pop(next(iter(seed['processPins'])))
            else:
                seed['observations']={r:seed['observations'][a] for r,a in aliases.items()}
                seed['processPins']={r:seed['processPins'][a] for r,a in aliases.items()}
            if kind!='hash':self.rewrite(args,seed)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.collect(c,**args)
            self.assertFalse(reads)

    def test_current_pins_static_drift_and_predecessor_drift_stop_without_retry(self):
        for kind in ('pin','static','predecessor','network'):
            c,args,_,_,mounted,reads,_=self.prepared();original=args['engine_factory']
            if kind=='pin':args['pin']=lambda pid:{'pid':pid,'changed':True}
            class Changed(original):
                def get(engine,cid):
                    actual=super().get(cid)
                    if engine.c.counts['engineGets']==11:
                        if kind=='static':(mounted/'credential').chmod(0o400)
                        elif kind=='predecessor':(args['predecessor_root']/'unexpected').touch()
                        elif kind=='network':actual['NetworkSettings']['changed']=True
                    return actual
            args['engine_factory']=Changed
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.collect(c,**args)
            self.assertFalse((c.scope/'retained-mounts.private.json').exists())
            if kind=='pin':self.assertFalse(reads)
            else:self.assertLessEqual(len(reads),20)

    def test_corrective_scope_is_also_create_once_and_effectful_failure_never_retries(self):
        c,args,_,_,_,reads,_=self.prepared()
        with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.RetainedCapture(c.scope)
        original=args['engine_factory']
        class Down(original):
            def get(engine,cid):reads.append(cid);raise TimeoutError('fixture')
        args['engine_factory']=Down
        with self.assertRaises(TimeoutError):m.collect(c,**args)
        self.assertEqual(len(reads),1);self.assertTrue((c.scope/'predecessor-reconciliation.json').exists())
        self.assertFalse((c.scope/'retained-mounts.private.json').exists())


if __name__=='__main__':unittest.main()
