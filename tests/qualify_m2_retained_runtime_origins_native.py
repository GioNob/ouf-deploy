"""Source identity reads from thirteen actual original Docker29 exports."""
import io,json,sys,tarfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
import qualify_m2_retained_image_graph_native as fixture
from retained_image_bytes import package
from tools.m2_discovery_installation_profile import retained_runtime_origins as m
from tools.m2_discovery_installation_profile import retained_selected_image_identity as identity
from tools.m2_discovery_installation_profile import retained_image_reader as reader


class NativeOrigins(unittest.TestCase):
    fixture_per_role_images=True
    @classmethod
    def setUpClass(cls):fixture.NativeGraph.setUpClass.__func__(cls)

    def test_a_thirteen_original_config_identities_match_verified_byte_proofs_without_engine_layer_read_or_writes(self):
        observer=reader.RetainedArchiveReader();seed,rows=observer.material();observer.roots(seed)
        before={str(p):m.attrs(p.lstat()) for p in self.root.rglob('*')};count=0
        with patch.object(fixture.fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK_DURING_ORIGIN_JOIN')):
            for role,row in sorted(rows.items()):
                raw=(observer.path.parent/row['filename']).read_bytes()
                proof=identity.verified_selected_image(io.BytesIO(raw),row['sha256'],row['imageIdRequested'],row['bytes'],
                    {'os':'linux','architecture':'amd64'},identity.VerificationBudget())
                with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
                    config_name=json.loads(tar.extractfile('manifest.json').read())[0]['Config']
                opened=[];original=tarfile.TarFile.extractfile
                def only_identity(tar,member,*args,**kwargs):
                    name=member.name if hasattr(member,'name') else member
                    self.assertIn(name,{'manifest.json',config_name});opened.append(name)
                    return original(tar,member,*args,**kwargs)
                with patch.object(identity,'verified_selected_image',side_effect=AssertionError('NO_BYTE_VERIFICATION_REPLAY')), \
                        patch.object(tarfile.TarFile,'extractfile',only_identity):
                    labels,size=m.config_identity(io.BytesIO(raw),proof,observer.budget)
                self.assertEqual(opened,['manifest.json',config_name])
                self.assertIsInstance(labels,dict);self.assertGreater(size,0);count+=1
            observer.roots(seed)
        self.assertEqual(count,13);self.assertEqual(before,{str(p):m.attrs(p.lstat()) for p in self.root.rglob('*')})
        print(json.dumps({'actualOriginalConfigurationsBoundToByteProof':count,'priorScopesUnchanged':True,
            'newEngineGetsDuringOriginJoin':0,'runtimeAuthorityIssued':False},sort_keys=True))

    def test_b_actual_original_classic_and_configuration_removal_or_corruption_cannot_be_origin_evidence(self):
        import hashlib,tarfile
        observer=reader.RetainedArchiveReader();_,rows=observer.material();row=rows['semantic']
        raw=(observer.path.parent/row['filename']).read_bytes()
        proof=identity.verified_selected_image(io.BytesIO(raw),row['sha256'],row['imageIdRequested'],row['bytes'],
            {'os':'linux','architecture':'amd64'},identity.VerificationBudget())
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
            members=[(r.name,tar.extractfile(r).read()) for r in tar if r.isfile()]
        config=json.loads(dict(members)['manifest.json'])[0]['Config']
        for name in ('manifest.json',config):
            for change in ('omit','corrupt'):
                changed=package([(k,(b'{}' if k==name else v)) for k,v in members if k!=name or change!='omit'])
                with self.assertRaises(ValueError):m.config_identity(io.BytesIO(changed),proof,identity.VerificationBudget())


if __name__=='__main__':unittest.main()
