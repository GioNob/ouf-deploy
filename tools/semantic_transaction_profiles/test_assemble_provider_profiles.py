import copy
import json
from pathlib import Path
import unittest

from assemble_provider_profiles import (AssemblyDenied, approved_runtime_seal,
                                        assemble_profiles, digest, encoded)


class ProfilesTest(unittest.TestCase):
    def setUp(self):
        self.cid = 'a' * 64
        self.policy = {'expectedOci': {'root': {'path': '/rootfs', 'readonly': True}}}
        self.seal = {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': 'b' * 64, 'entries': 10, 'bytes': 100}
        self.comparison = {'status': 'IMAGE_EQUIVALENCE_PASS', 'imageEquivalent': True, 'roles': [{
            'containerId': self.cid, 'neverStarted': True, 'exportMountReleased': True,
            'actualSeal': self.seal, 'imageEquivalence': {'equivalent': True,
             'actualImageSeal': 'c' * 64, 'differences': {'differentEntryCount': 0}}}]}
        self.authorization = {'containerId': self.cid,
            'applicationHash': digest(encoded(self.policy['expectedOci'])),
            'artifactHash': digest(encoded(self.policy)), 'rootfsSeal': copy.deepcopy(self.seal)}

    def test_portable_digest_cannot_replace_node_seal(self):
        self.authorization['rootfsSeal']['sha256'] = 'c' * 64
        with self.assertRaisesRegex(AssemblyDenied, 'AUTHORIZATION_RUNTIME_SEAL_DRIFT'):
            approved_runtime_seal(self.comparison, self.cid, self.policy, self.authorization)

    def test_equivalence_does_not_synthesize_acceptance(self):
        actual = approved_runtime_seal(self.comparison, self.cid, self.policy, self.authorization)
        self.assertEqual(actual, self.seal)
        self.assertNotIn('accepted', actual)
        self.policy['expectedOci']['root']['readonly'] = False
        with self.assertRaisesRegex(AssemblyDenied, 'AUTHORIZATION_COMPLETE_FRAME_SCOPE_DRIFT'):
            approved_runtime_seal(self.comparison, self.cid, self.policy, self.authorization)

    def inputs(self):
        source = Path(__file__).parent.parent / 'semantic_cohort_admission' / 'cohort-draft'
        if not source.exists():
            source = Path(__file__).parent / 'cohort-draft'
        sources = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob('*.py')}
        authorities = {'installationRef': 'lab', 'entityRef': 'entity', 'intentIssuerRef': 'installer',
                       'approvalIssuerRef': 'installer', 'attestorRef': 'node'}
        authority = {'authorities': authorities,
                     'keyBindings': {k: {'path': '/existing/' + k, 'sha256': 'd' * 64}
                                     for k in ('installer', 'attestor')},
                     'keyRefs': {'installer': 'installer-key', 'attestor': 'node-key'}}
        candidate = {'containerId': self.cid, 'transactionId': 'e' * 64,
                     'networkBindings': [], 'transport': [], 'tableName': 'guard',
                     'runtimeBinding': {'path': '/usr/bin/runc', 'sha256': 'f' * 64}}
        intent = {'schema': 'ouf.semantic-deployment-intent.v1', 'installationRef': 'lab',
                  'entityRef': 'entity', 'issuerRef': 'installer', 'containerId': self.cid,
                  'transactionId': 'e' * 64, 'runtimeExecutableHash': 'f' * 64,
                  'artifactHash': digest(encoded(self.policy)),
                  'transportHash': digest(encoded({k: candidate[k] for k in ('networkBindings', 'transport', 'tableName')}))}
        template = {'candidate': candidate, 'commands': {'ip': '/usr/bin/ip', 'nsenter': '/usr/bin/nsenter'},
                    'commandHashes': {'ip': '1' * 64, 'nsenter': '2' * 64}}
        return dict(root='/private/candidate', source_root='/private/source', sources=sources, authority=authority,
                    python={'path': '/usr/bin/python3', 'sha256': '3' * 64},
                    crypto={'policyBinding': {'path': '/existing/policy', 'sha256': '4' * 64},
                            'signatureDirectory': '/private/signatures',
                            'opensslBinding': {'path': '/usr/bin/openssl', 'sha256': '5' * 64}},
                    intent_binding={'path': '/private/intent.json', 'sha256': digest(encoded(intent))},
                    intent=intent, template=template, final_mandate_binding={'path': '/private/final.json', 'sha256': '6' * 64},
                    observer_binding={'configuration': {'path': '/private/frame.json', 'sha256': intent['artifactHash']}},
                    runtime_parents=['/run'], bundle_parents=['/private'],
                    rootfs_limits={'maxEntries': 100000, 'maxDepth': 64, 'maxBytes': 8589934592})

    def test_broker_uses_exact_generated_producer_bytes_and_closures(self):
        inputs = self.inputs()
        files = assemble_profiles(**inputs)
        for role, filename in [('attestation', 'attestation-producer.json'), ('approval', 'approval-producer.json')]:
            binding = files['broker.json']['producers'][role]['configuration']
            self.assertEqual(binding['sha256'], digest(encoded(files[filename])))
            for path, sha in files[filename]['sourceHashes'].items():
                self.assertEqual(sha, digest(inputs['sources'][path]))
        self.assertEqual(files['attestation-producer.json']['schema'], 'ouf.semantic-node-attestor.v4')
        self.assertEqual(files['broker-state.json']['state'], 'STAGED')
        self.assertIsNone(files['deployment.json']['generation'])
        self.assertNotIn('startAuthorized', files['broker.json'])

    def test_signed_transport_drift_fails_with_diagnosis(self):
        inputs = self.inputs()
        inputs['template']['candidate']['tableName'] = 'changed'
        with self.assertRaises(AssemblyDenied) as raised:
            assemble_profiles(**inputs)
        self.assertEqual(raised.exception.diagnosis['reason'], 'SIGNED_TRANSPORT_SCOPE_DRIFT')
        self.assertFalse(raised.exception.diagnosis['secretValuesPrinted'])

    def test_broker_and_both_initial_journals_use_the_selected_installation_runtime_parent(self):
        inputs=self.inputs();inputs['runtime_parents']=['/private/installation/runtime']
        files=assemble_profiles(**inputs);broker=files['broker.json']
        self.assertEqual(broker['runtimeRootParent'],'/private/installation/runtime')
        self.assertEqual(files['attestation-producer.json']['runtimeRootParents'],inputs['runtime_parents'])
        for name in ('broker-state.json','deployment.json'):
            self.assertEqual(files[name]['configurationHash'],digest(encoded(broker)))
        self.assertNotEqual(broker['runtimeRootParent'],'/run')

    def test_ambiguous_or_unapproved_runtime_parent_cannot_fall_back_to_host_default(self):
        inputs=self.inputs();inputs['runtime_parents']=['/private/runtime-a','/private/runtime-b']
        with self.assertRaisesRegex(AssemblyDenied,'UNAMBIGUOUS_BROKER_RUNTIME_PARENT'):
            assemble_profiles(**inputs)
        with self.assertRaisesRegex(AssemblyDenied,'OUTSIDE_APPROVED_NODE_PARENTS'):
            assemble_profiles(**inputs,broker_runtime_root_parent='/run')
        files=assemble_profiles(**inputs,broker_runtime_root_parent='/private/runtime-b')
        self.assertEqual(files['broker.json']['runtimeRootParent'],'/private/runtime-b')


if __name__ == '__main__':
    unittest.main()
