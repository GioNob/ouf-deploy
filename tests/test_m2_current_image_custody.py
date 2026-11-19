"""Keep generic source guards and admit only the actual reviewed MCP origin."""
import hashlib, io, json, sys, unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT),str(ROOT/'tests')]
import test_image_custody as fixture
from tools.m2_discovery_installation_profile import current_image_custody as m


class CurrentImageCustody(unittest.TestCase):
    def test_ordinary_image_audits_and_the_legacy_public_interface_remain_exact(self):
        original = fixture.fixture(); expected = fixture.audit(original)
        self.assertEqual(m.archive(io.BytesIO(original[0]), original[1], original[2], fixture.SOURCE), expected)
        for name, value in vars(m._legacy).items():
            if not name.startswith('_') and name != 'archive': self.assertIs(getattr(m,name), value)
        with self.assertRaisesRegex(ValueError, 'SOURCE_LABEL_DRIFT'):
            m.archive(io.BytesIO(original[0]), original[1], original[2], 'b'*40)

    def test_unregistered_mcp_source_archive_or_mutated_ci_binding_denies_before_bytes(self):
        class NoRead:
            def seek(self,*args): raise AssertionError('NO_UNREGISTERED_ARCHIVE_READ')
        for sha, source in [('0'*64,m.MCP_SOURCE),(next(iter(m.MCP_ARCHIVES)),'b'*40)]:
            with self.assertRaisesRegex(ValueError, 'EXACT_CURRENT_MCP_CI_ARCHIVE'):
                m.archive(NoRead(),sha,m.MCP_IMAGE,source)
        with patch.dict(m.MCP_BINDING,{'stagedReceiptHash':'0'*64}), self.assertRaisesRegex(ValueError,'EXACT_CURRENT_MCP'):
            m.archive(NoRead(),next(iter(m.MCP_ARCHIVES)),m.MCP_IMAGE,m.MCP_SOURCE)
        with self.assertRaises(TypeError):
            m.archive(NoRead(),next(iter(m.MCP_ARCHIVES)),m.MCP_IMAGE,m.MCP_SOURCE,ci_source_binding={})

    def test_exact_mcp_binding_reuses_the_prior_artifact_receipt_without_changing_the_frozen_helper(self):
        receipt=json.loads((ROOT/'releases/managed-profile-control-mcp-image-custody-20261027.json').read_bytes())
        self.assertEqual(m.MCP_BINDING,receipt['imageAudit']['qualifiedCiSourceBinding'])
        self.assertEqual(m.MCP_ARCHIVES,{receipt['expandedArchiveSha256'],receipt['derivedArchiveSha256']})
        self.assertEqual(hashlib.sha256((ROOT/'tools/acquisition_read_native/image_custody.py').read_bytes()).hexdigest(),m.QUALIFIED_HELPER_SHA256)
        frozen=json.loads((ROOT/'tools/m2_discovery_installation_profile/current_review_sources.json').read_bytes())['image_custody']
        self.assertEqual(hashlib.sha256((ROOT/frozen['path']).read_bytes()).hexdigest(),frozen['sha256'])


def actual_mcp(original, target):
    """Real public image/transport bytes; no Engine, credentials or authority."""
    receipt=json.loads((ROOT/'releases/managed-profile-control-mcp-image-custody-20261027.json').read_bytes())
    with Path(original).open('rb') as source:
        audit=m.archive(source,receipt['expandedArchiveSha256'],m.MCP_IMAGE,m.MCP_SOURCE)
        expected={k:v for k,v in receipt['imageAudit'].items() if k!='nativeIdentity'}
        if audit!=expected: raise ValueError('EXACT_EXISTING_CI_SOURCE_AUDIT_REQUIRED')
        with Path(target).open('x+b') as output: derived=m.tagless_archive(source,output,audit,containerd=True)
    if derived['derivedArchiveSha256']!=receipt['derivedArchiveSha256']:
        raise ValueError('EXACT_EXISTING_NATIVE_ENVELOPE_REQUIRED')
    with Path(target).open('rb') as source:
        again=m.archive(source,derived['derivedArchiveSha256'],m.MCP_IMAGE,m.MCP_SOURCE)
    if m.native_identity(again)['nativeImageId']!=receipt['nativeImageId']:
        raise ValueError('EXACT_CURRENT_MCP_NATIVE_IDENTITY_REQUIRED')
    if again['targetApplyAuthorized'] is not False: raise ValueError('NO_RUNTIME_AUTHORITY_FROM_SOURCE_BINDING')


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--actual-mcp': actual_mcp(sys.argv[2],sys.argv[3])
    else: unittest.main()
