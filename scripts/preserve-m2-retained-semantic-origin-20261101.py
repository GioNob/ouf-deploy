#!/usr/bin/env python3
"""Authenticate the original semantic module/config; no image build or target I/O."""
import hashlib,io,json,os,shutil,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner')]
from tools.chatbot_file_cohort.package_custody import extract_cohort
from tools.semantic_application_cutover.image_custody import archive,native_identity
ZIP_SHA='144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300'
PRODUCER='8bff54a52a0ce15daccaf2aee932004f106dd178'
SOURCE='eccef11a97367f20e278db40b9ed6f45dd980c37'
CONFIG='sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
ARCHIVE_SHA='a0f1e2252f01a0e4a45c1262f124298000c56d206bdf9953b78bcd6b3ad4017a'
TARGET_RESULT='ca16c7e3799d916517cba7e0c0d0456c57bd949184bd103d3fa3204110768a09'


def require(ok,reason):
    if not ok:raise ValueError(reason)


def preserve(source,output):
    require(os.geteuid()==0 and not output.exists() and source.is_file() and not source.is_symlink()
        and source.stat().st_size==1708479761,'EXACT_ORIGINAL_COMPLETE_COHORT_ZIP_REQUIRED')
    observed=json.loads((ROOT/'evidence/m2-runtime-origin-join-target-20261101.json').read_text())
    receipt=observed['receipt'];encoded=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
    require(hashlib.sha256(encoded(receipt)).hexdigest()==TARGET_RESULT==observed['publicResultCanonicalSha256'],
        'EXACT_SUCCESSFUL_OPERATOR_ORIGIN_JOIN_RECEIPT_REQUIRED')
    binding=next(x for x in receipt['unresolvedOriginBindings'] if x['role']=='semantic')
    require(binding['configurationDigest']==CONFIG,'EXACT_RETAINED_SEMANTIC_CONFIGURATION_REQUIRED')
    output.mkdir(mode=0o700);stage=output/'verified-original';stage.mkdir(mode=0o700)
    package,manifest,origin=extract_cohort(source,ZIP_SHA,PRODUCER,38584614991,stage)
    record=next(x for x in manifest['modules'] if x['module']=='semantic');folder=package/'semantic'
    candidate=json.loads((folder/'candidate-manifest.json').read_bytes());metadata=json.loads((folder/'package-record.json').read_bytes())
    require(record['sourceCommit']==SOURCE and record['imageId']==CONFIG and record['artifactKind']=='DOCKER_SAVE'
        and record['files']['image.docker.tar']==ARCHIVE_SHA
        and candidate=={k:v for k,v in record.items() if k!='files'}
        and metadata['sourceCommit']==SOURCE and metadata['imageId']==CONFIG,
        'SIGNED_ORIGINAL_MODULE_SOURCE_CONFIG_AND_ARCHIVE_MUST_MATCH_RETAINED_RUNTIME')
    with (folder/'image.docker.tar').open('rb') as image:proof=archive(image,ARCHIVE_SHA,CONFIG,SOURCE)
    original_root=[]
    with tarfile.open(folder/'image.docker.tar',mode='r:') as tar:
        members={r.name:r for r in tar};index=tar.extractfile(members['index.json']).read(131073)
        require(len(index)<=131072,'BOUNDED_ORIGINAL_NATIVE_INDEX_REQUIRED')
        original_root=[r['digest'] for r in json.loads(index)['manifests']]
        requested_present='blobs/sha256/'+binding['selectedRuntimeManifestDigest'][7:] in members
    retained=output/'preserved';retained.mkdir(mode=0o700);(retained/'origin').mkdir(mode=0o700)
    for name in ['COHORT_SHA256SUMS','COHORT_SHA256SUMS.sigstore.json','cohort-manifest.json','source-lock.json']:
        shutil.copyfile(package/name,retained/'origin'/name)
    for name in ['package-record.json','candidate-manifest.json','SHA256SUMS','source.tar','source-inventory.json']:
        shutil.copyfile(folder/name,retained/name)
    result={'schema':'ouf.m2-retained-semantic-original-origin.v1','originalArtifactId':11907557440,
        'originalRun':38584614991,'originalZipSha256':ZIP_SHA,'originalZipBytes':1708479761,
        'originalProducer':PRODUCER,'moduleSourceCommit':SOURCE,'originalArchiveSha256':ARCHIVE_SHA,
        'configurationDigest':CONFIG,'retainedRuntimeConfigurationDigest':binding['configurationDigest'],
        'retainedRuntimeNativeManifestDigest':binding['selectedRuntimeManifestDigest'],
        'originalNativeRootDescriptors':original_root,'retainedNativeDigestDocumentPresent':requested_present,
        'qualifiedSchema2Envelope':native_identity(proof),'layerCount':len(proof['layers']),
        'rootfsDiffIds':[v['diffId'] for v in proof['layers']],
        'expandedLayerBytesVerified':sum(v['expandedBytes'] for v in proof['layers']),
        'originalConfigurationAndAllLayerAndExpandedDiffIdBytesVerified':True,
        'configurationAndRootfsContentIdentityMatchesRetained':True,
        'originalSignatureVerified':False,'publicTargetReceiptHash':TARGET_RESULT,
        'privateTargetOriginEvidenceHash':receipt['privateEvidenceHash'],
        'originalPackageOwnerReceipt':origin,'imageRebuilt':False,'imageImported':False,
        'applicationStarted':False,'candidateSelectionChanged':False,'freshVulnerabilityAdmissionProven':False,
        'targetCalls':0,'allRuntimeArtifactMembershipProven':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
    (retained/'semantic-origin-match.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


if __name__=='__main__':
    require(len(sys.argv)==3,'EXACT_ORIGINAL_ZIP_AND_FRESH_OUTPUT_REQUIRED')
    preserve(Path(sys.argv[1]),Path(sys.argv[2]))
