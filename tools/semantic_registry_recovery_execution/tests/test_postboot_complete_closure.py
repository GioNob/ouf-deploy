"""Complete real source graph/import and source-custody integration only.

No preparation, IAM, authority issuance, Docker or service call is performed.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]

CHILD = r'''
import hashlib,importlib.util,json,pathlib,sys,threading
root=pathlib.Path(sys.argv[1])
p=root/'tools/semantic_registry_recovery_execution/delivery.py'
s=importlib.util.spec_from_file_location('complete_postboot_delivery_fixture',p)
d=importlib.util.module_from_spec(s);s.loader.exec_module(d)
r,raw=d.loader_module(root);sources=d.collect_sources(root,r)
commit='a'*40
declaration=r.declaration(commit,sources,raw,{'ouf-deploy':commit})
entry,manifest=r.load_entry(commit,sources,raw,r.digest(declaration),{'ouf-deploy':commit})
assert all(name in sys.modules for name in sources)
assert entry.__name__==r.ENTRY
from tools.semantic_registry_recovery_execution import authorization,postboot_authority,postboot_factory,bootstrap,postboot_prepare
from tools.semantic_registry_postboot_owner import owner,contract
from file_only_profile import FileOnlyProfile
assert postboot_authority.CutoverAuthority is authorization.cutover_type()
assert postboot_authority.FileOnlyProfile is FileOnlyProfile
assert owner.BootstrapGateWitness is bootstrap.BootstrapGateWitness
case=json.loads((root/'releases/semantic-registry-postboot-case-20261023.json').read_bytes())
assert case['schema']==entry.SCHEMA and set(case)=={'schema','preparation'}
postboot_prepare.validate_case(case['preparation'])
receipt=case['preparation']['lineageReceipt']
terminal=contract.terminal(receipt)
assert terminal['candidateOrdinal']==6 and terminal['controlledCumulativeGrantAttempts']==319
assert terminal['recoveryHash']=='aed77a73d69ea8d865df1097a9d9e5c3e230445ae8a7fd95857575318fb473ab'
assert terminal['sessionHash']=='386d52ccc5847aa17c08d879df4f58e52902bf3c8423712e85a14c377d3aa468'
assert case['preparation']['predecessorJournalPath'].endswith('/semantic-functional-worker-4d73f23481b322c6fc046734f9a50a7251ddafe5d6d3d794129d9728305e8ad6')
assert receipt['historicalInputsHash']==case['preparation']['retainedInputs']['sha256']
assert receipt['historicalReviewHash']==case['preparation']['historicalReview']['sha256']
assert case['preparation']['proposedOwnerBudget']['maximumGrantAttempts']==1
prepared=postboot_prepare.prepared_root(case['preparation'],manifest,'00000000-1111-2222-3333-444444444444')
assert prepared==postboot_prepare.prepared_root(case['preparation'],manifest,'00000000-1111-2222-3333-444444444444')
assert str(prepared.parent)==case['preparation']['privateParent']
def profile(path):
 s=path.stat()
 metadata=[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 ancestry=[]
 for parent in reversed(path.parents):
  q=parent.stat();ancestry.append({'path':str(parent),'identity':[q.st_dev,q.st_ino,q.st_uid,q.st_gid,q.st_mode]})
 return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'metadata':metadata,'ancestors':ancestry}
context={'sourceFiles':{name:profile(root/r.source_path(name)) for name in contract.SOURCE_FILES}}
before={name:id(sys.modules[name]) for name in sources}
errors=[]
def guarded():
 try:owner.source_guard(context)
 except BaseException as error:errors.append(type(error).__name__+':'+str(error))
threads=[threading.Thread(target=guarded) for _ in range(3)]
for thread in threads:thread.start()
for thread in threads:thread.join(5);assert not thread.is_alive()
assert not errors,errors
assert before=={name:id(sys.modules[name]) for name in sources}
assert all(getattr(sys.modules[name],'__qualified_source_sha256__')==manifest['sourceHashes'][name] for name in sources)
print(json.dumps({'modules':len(sources),'sourceBytes':sum(map(len,sources.values())),'guardedSources':len(contract.SOURCE_FILES),'loadedBeforeThreads':True,'nativeEffects':0}))
'''


class CompleteClosure(unittest.TestCase):
    def test_actual_closed_graph_preload_typed_identity_and_concurrent_source_custody(self):
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-', str(ROOT)], input=CHILD.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd='/')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b'')
        receipt = json.loads(result.stdout)
        self.assertGreater(receipt['modules'], 90)
        self.assertEqual(receipt['guardedSources'], 11)
        self.assertEqual(receipt['nativeEffects'], 0)
        self.assertTrue(receipt['loadedBeforeThreads'])

    def test_real_capsule_rejects_invalid_case_without_target_action(self):
        path = ROOT / 'tools/semantic_registry_recovery_execution/delivery.py'
        spec = importlib.util.spec_from_file_location('complete_capsule_generator', path)
        delivery = importlib.util.module_from_spec(spec); spec.loader.exec_module(delivery)
        capsule, declaration = delivery.generate(ROOT, {'schema': 'INVALID_FIXTURE_ONLY'}, 'a'*40,
                                                {'ouf-deploy': 'a'*40})
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-', 'prepare'], input=capsule,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd='/')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b'')
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['reasonCode'], 'EXACT_POSTBOOT_OPERATOR_CASE_REQUIRED')
        self.assertFalse(receipt['runtimeEffectsMayBePartial'])
        self.assertFalse(declaration['runtimeAuthorityIssued'])


if __name__ == '__main__':
    unittest.main()
