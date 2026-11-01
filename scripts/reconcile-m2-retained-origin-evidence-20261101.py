#!/usr/bin/env python3
"""Join consumed public origin receipts to preserved original CI evidence.

This offline report is not a publisher verifier or an installation admission.
The original image/layer and Sigstore chain verification ran in the named CI job;
this reader checks its exact ZIP, signed member closure and independent Git blobs.
It neither changes the frozen installation compilers nor invokes the VPS.
"""
import argparse
import ast
import base64
from collections import Counter
import gzip
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tarfile
import zipfile

ZIP = 'releases/artifacts/m2-retained-semantic-original-13099216732.zip'
ZIP_SHA = '658a252456e515b9b66fe93505822b24f78d498fd98c463f42da83c2ae5b173e'
TREE = 'releases/m2-retained-semantic-original-source-tree-20261101.json'
OUTPUT = 'releases/m2-retained-runtime-origin-reconciliation-20261101.json'
TARGET = 'ca16c7e3799d916517cba7e0c0d0456c57bd949184bd103d3fa3204110768a09'
SOURCE = 'eccef11a97367f20e278db40b9ed6f45dd980c37'
CONFIG = 'sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
NATIVE = 'sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3'
REMEDIATION_ZIP = 'evidence/artifacts/m2-semantic-high-remediation-41351198866.zip'
REMEDIATION_PUBLISHER_ZIP = 'evidence/artifacts/m2-semantic-remediation-publisher-41351447269.zip'
MINIO_SECURITY_ZIP = 'evidence/artifacts/m2-minio-exact-copy-security-41352708811.zip'
GATEWAY_METADATA_ZIP = 'releases/artifacts/m2-gateway-owner-qualified-metadata-41353205013.zip'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def original_semantic(root, binding):
    raw = (root / ZIP).read_bytes()
    require(len(raw) == 312517 and sha(raw) == ZIP_SHA, 'EXACT_ORIGINAL_CI_EVIDENCE_ZIP_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == 12 and sum(r.file_size for r in archive.infolist()) < 8388608,
                'BOUNDED_ORIGINAL_EVIDENCE_MEMBERS_REQUIRED')
        result = json.loads(archive.read('semantic-origin-match.json'))
        sums = dict((line.split('  ', 1)[1], line.split('  ', 1)[0])
                    for line in archive.read('origin/COHORT_SHA256SUMS').decode().splitlines())
        for name in ('source.tar', 'source-inventory.json', 'candidate-manifest.json', 'package-record.json', 'SHA256SUMS'):
            require(sha(archive.read(name)) == sums['semantic/' + name], 'ORIGINAL_SIGNED_MODULE_MEMBER_CHANGED')
        for name in ('cohort-manifest.json', 'source-lock.json'):
            require(sha(archive.read('origin/' + name)) == sums[name], 'ORIGINAL_SIGNED_COHORT_MEMBER_CHANGED')
        require(archive.read('original-publisher-verification.stderr.txt').strip() == b'Verified OK',
                'RETAINED_HOSTED_COSIGN_SUCCESS_REQUIRED')
        tree = json.loads((root / TREE).read_bytes())
        require(tree['sourceCommit'] == SOURCE and tree['repository'] == 'GioNob/ouf-semantic-registry',
                'EXACT_INDEPENDENT_ORIGINAL_SOURCE_TREE_REQUIRED')
        expected = {r['path']: (r['sha'], r['mode']) for r in tree['tree']}
        inventory = json.loads(archive.read('source-inventory.json'))
        require(expected == {r['path']: (r['sha'], r['mode']) for r in inventory['tree'] if r['type'] == 'blob'}
                and len(expected) == 198, 'SIGNED_SOURCE_INVENTORY_MUST_MATCH_INDEPENDENT_GIT_TREE')
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(archive.read('source.tar')), mode='r:') as source:
            for member in source:
                require(member.isdir() or member.isfile(), 'REGULAR_ORIGINAL_SOURCE_MEMBERS_REQUIRED')
                if not member.isfile():
                    continue
                require(member.name in expected and member.name not in seen and member.size <= 1048576,
                        'EXACT_BOUNDED_UNIQUE_SOURCE_MEMBER_REQUIRED')
                data = source.extractfile(member).read(member.size + 1)
                git_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                mode = '100755' if member.mode & 0o111 else '100644'
                require(len(data) == member.size and (git_blob, mode) == expected[member.name],
                        'ORIGINAL_SOURCE_BYTES_OR_MODE_DIFFER_FROM_GIT')
                seen.add(member.name)
        require(seen == set(expected), 'COMPLETE_ORIGINAL_SOURCE_SET_REQUIRED')
    validate_semantic(result, binding)
    return result, {
        'artifactId': 13099216732, 'runId': 41345531053, 'jobId': 124964417117,
        'workflowSource': 'e155649ff99fcd952822a6475358ced77767ae1a',
        'zipSha256': ZIP_SHA, 'zipBytes': len(raw), 'preservedZip': ZIP,
        'originalSourceFilesIndependentlyMatched': len(seen),
        'originalSourceTreeSha256': sha((root / TREE).read_bytes()),
        'signedPayloadMembersIndependentlyMatched': 7,
        'publisherChainVerifiedInNamedHostedJob': True,
        'publisherChainReverifiedByThisReader': False,
        'fullOriginalImageReadByThisReader': False,
    }


def validate_semantic(result, binding):
    require(result['moduleSourceCommit'] == SOURCE
            and result['configurationDigest'] == binding['configurationDigest'] == CONFIG
            and result['qualifiedSchema2Envelope']['nativeImageId'] == binding['selectedRuntimeManifestDigest'] == NATIVE
            and result['qualifiedSchema2Envelope']['configurationImageId'] == CONFIG,
            'ORIGINAL_SOURCE_CONFIG_AND_NATIVE_ENVELOPE_MUST_ALL_MATCH')
    require(result['publicTargetReceiptHash'] == TARGET
            and result['originalConfigurationAndAllLayerAndExpandedDiffIdBytesVerified'] is True
            and result['configurationAndRootfsContentIdentityMatchesRetained'] is True
            and result['originalSignatureVerified'] is True
            and result['originalArtifactId'] == 11907557440 and result['originalRun'] == 38584614991,
            'EXACT_SUCCESSFUL_ORIGINAL_COHORT_PROOF_REQUIRED')
    require(all(result[k] is False for k in ('runtimeAuthorityIssued', 'targetApplyAuthorized',
            'releaseAcceptance', 'freshVulnerabilityAdmissionProven', 'candidateSelectionChanged')),
            'ORIGINAL_EVIDENCE_MUST_NOT_CONFER_RUNTIME_ADMISSION')


def semantic_remediation(root):
    """Join separately qualified candidate evidence, keeping the target HELD.

    Verify the exact recorded hosted verifier output. This offline reader does
    not itself repeat Sigstore trust-chain or transparency-log verification.
    """
    archives = []
    for path, size, checksum in (
        (REMEDIATION_ZIP, 100936, '4fed16f6a98975dbe02e03a8814b47fea7da76bf3e2abadcb583acaa3d4850eb'),
        (REMEDIATION_PUBLISHER_ZIP, 109538, '4e4551c6c86517025bdffafe2a50f8986c129736ad6f6394ba72e05390bb5ff3')):
        raw = (root/path).read_bytes()
        require(len(raw) == size and sha(raw) == checksum, 'EXACT_REMEDIATION_AND_PUBLISHER_ZIPS_REQUIRED')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require(len(archive.namelist()) == len(set(archive.namelist()))
                    and sum(r.file_size for r in archive.infolist()) <= 2097152, 'BOUNDED_REMEDIATION_EVIDENCE_REQUIRED')
            archives.append({name: archive.read(name) for name in archive.namelist()})
    original, verified = archives
    require(set(original) == {'SHA256SUMS', 'origin-facts.json', 'empty.trivyignore', 'provenance.json',
                             'remediation-result.json', 'trivy-image.json'}
            and set(verified) == set(original)|{'publisher-verification.json'}
            and all(value == verified[name] for name, value in original.items()),
            'IDENTICAL_COMPLETE_REMEDIATION_EVIDENCE_REQUIRED')
    for row in original['SHA256SUMS'].decode().splitlines():
        checksum, name = row.split('  ', 1)
        require(name in original and sha(original[name]) == checksum, 'REMEDIATION_SIGNED_MEMBER_CHANGED')
    results = json.loads(verified['publisher-verification.json'])
    require(type(results) is list and len(results) == 1, 'ONE_HOSTED_PUBLISHER_VERIFICATION_REQUIRED')
    publisher = results[0]['verificationResult']; cert = publisher['signature']['certificate']
    bundle = json.loads(original['provenance.json'])
    statement = json.loads(base64.b64decode(bundle['dsseEnvelope']['payload'], validate=True))
    source = 'c893120beb881320542a1a63d06ec4fec37935ea'
    identity = ('https://github.com/GioNob/ouf-deploy/.github/workflows/m2-semantic-high-remediation.yml'
                '@refs/heads/feat/m2-discovery-complete-profile-20261029')
    require(results[0]['attestation']['bundle'] == bundle and publisher['statement'] == statement
            and cert['subjectAlternativeName'] == cert['buildSignerURI'] == identity
            and cert['sourceRepositoryDigest'] == cert['buildSignerDigest'] == source
            and cert['issuer'] == 'https://token.actions.githubusercontent.com'
            and cert['runnerEnvironment'] == 'github-hosted'
            and cert['sourceRepositoryRef'] == 'refs/heads/feat/m2-discovery-complete-profile-20261029'
            and any(t['type'] == 'Tlog' for t in publisher['verifiedTimestamps'])
            and statement['subject'] == [{'name':'SHA256SUMS', 'digest':{'sha256':sha(original['SHA256SUMS'])}}],
            'EXACT_HOSTED_VERIFIED_REMEDIATION_PUBLISHER_REQUIRED')
    result = json.loads(original['remediation-result.json'])
    scan = json.loads(original['trivy-image.json'])
    counts = dict(Counter(f['Severity'] for r in scan['Results'] for f in r.get('Vulnerabilities', [])))
    require(result['configurationImageId'] == scan['Metadata']['ImageID'] ==
            'sha256:a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f'
            and result['sourceCommit'] == 'c2dae77b42f1811b704465f6ab813c91d808ade4'
            and result['scanSha256'] == sha(original['trivy-image.json'])
            and result['vulnerabilityCounts'] == counts
            and not any(counts.get(s, 0) for s in ('HIGH', 'CRITICAL', 'UNKNOWN'))
            and result['threeRetainedHighFindingsRemediatedInReplacement'] is True
            and result['retainedImageSecurityAdmission'] == 'HELD_HIGH_CRITICAL_UNKNOWN'
            and all(result[k] is False for k in ('candidateSelectionChanged', 'targetImageReplaced',
                    'targetApplyAuthorized', 'runtimeAuthorityIssued', 'releaseAcceptance', 'm2Acceptance')),
            'REMEDIATION_CANDIDATE_MUST_NOT_CLEAR_TARGET_HOLD')
    return dict(result, evidenceZip=REMEDIATION_ZIP, publisherEvidenceZip=REMEDIATION_PUBLISHER_ZIP,
                publisherChainVerifiedInNamedHostedJob=True, publisherChainReverifiedByThisReader=False,
                scanRunId=41351198866, scanJobId=124981513469,
                publisherReadbackRunId=41351447269, publisherReadbackJobId=124982301308,
                scanFreshnessMustBeRecheckedBeforeAdmission=True)


def minio_security(root):
    raw = (root/MINIO_SECURITY_ZIP).read_bytes()
    require(len(raw) == 270309 and sha(raw) == '59786c63c06d53f081a9e66469d0bf8bb05ed2eb7b7030645d48d1570728d2ca',
            'EXACT_HELD_MINIO_SECURITY_EVIDENCE_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) == 5
                and set(names) == {'root.json','selected.json','configuration.json','copy-result.json','trivy-image.json'}
                and sum(r.file_size for r in archive.infolist()) <= 8388608, 'BOUNDED_COMPLETE_MINIO_EVIDENCE_REQUIRED')
        members = {name: archive.read(name) for name in names}
    spec = importlib.util.spec_from_file_location('exact_public_minio_content', root/'scripts/read-m2-minio-exact-copy-20261101.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    layers, diff_ids = reader.verify_descriptors(members['root.json'], members['selected.json'], members['configuration.json'])
    proof, scan = (json.loads(members[n]) for n in ('copy-result.json','trivy-image.json'))
    counts = dict(Counter(f['Severity'] for r in scan['Results'] for f in r.get('Vulnerabilities', [])))
    require(proof['scanSha256'] == sha(members['trivy-image.json'])
            and proof['configurationImageId'] == scan['Metadata']['ImageID'] == reader.CONFIG
            and proof['selectedRuntimeManifestDigest'] == reader.MANIFEST
            and proof['rootIndexDigest'] == reader.ROOT_DIGEST
            and proof['vulnerabilityCounts'] == counts
            and counts.get('CRITICAL') == 9 and counts.get('HIGH') == 127 and counts.get('UNKNOWN') == 8
            and proof['freshSecurityGatePassed'] is False and proof['copyIsNotOriginalVendorPublisher'] is True
            and proof['originalVendorPublisherAuthenticated'] is False
            and proof['runtimeReferenceChanged'] is False and proof['targetOperations'] == 0
            and proof['allSelectedLayerAndExpandedDiffIdsVerified'] is True
            and len(proof['layers']) == len(layers)
            and all(p['ordinal'] == i and p['blobDigest'] == layers[i]['digest']
                    and p['blobBytes'] == layers[i]['size'] and p['diffId'] == diff_ids[i]
                    for i,p in enumerate(proof['layers'])), 'EXACT_CONTENT_RECOVERY_MUST_REMAIN_UNTRUSTED_AND_HELD')
    return dict(proof, evidenceZip=MINIO_SECURITY_ZIP, runId=41352708811, jobId=124986151771,
                securityAdmission='HELD_HIGH_CRITICAL_UNKNOWN', deploymentReachabilityOfFindingsProven=False,
                ownerStorageDirectionRequired=True)


def gateway_candidate(root):
    raw = (root/GATEWAY_METADATA_ZIP).read_bytes()
    require(len(raw) == 339540 and sha(raw) == '0ac3793a0f73dcdcc22e341a1e42129bee830cb5d63c9e9696c7f34a27f33cb6',
            'EXACT_QUALIFIED_GATEWAY_CANDIDATE_METADATA_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())) == 14
                and sum(r.file_size for r in archive.infolist()) <= 8388608, 'BOUNDED_GATEWAY_EVIDENCE_REQUIRED')
        members = {n:archive.read(n) for n in archive.namelist()}
    proof, scan = (json.loads(members[n]) for n in ('candidate.json','trivy-image.json'))
    sums = dict(line.split('  ',1)[::-1] for line in members['SHA256SUMS'].decode().splitlines())
    require(sums['image.docker.tar'] == proof['archiveSha256']
            and sums['scan-input.docker.tar'] == proof['scanInputSha256'], 'SIGNED_GATEWAY_IMAGE_MEMBERS_REQUIRED')
    for name, checksum in sums.items():
        if name not in ('image.docker.tar','scan-input.docker.tar'):
            require(name in members and sha(members[name]) == checksum, 'SIGNED_GATEWAY_METADATA_CHANGED')
    results = json.loads(members['publisher-verification.json'])
    require(type(results) is list and len(results) == 1, 'ONE_GATEWAY_PUBLISHER_VERIFICATION_REQUIRED')
    verification = results[0]['verificationResult']; cert = verification['signature']['certificate']
    bundle = json.loads(members['provenance.json'])
    statement = json.loads(base64.b64decode(bundle['dsseEnvelope']['payload'],validate=True))
    identity = ('https://github.com/GioNob/ouf-deploy/.github/workflows/m2-gateway-owner-candidate.yml'
                '@refs/heads/feat/m2-discovery-complete-profile-20261029')
    require(results[0]['attestation']['bundle'] == bundle and verification['statement'] == statement
            and statement['subject'] == [{'name':'SHA256SUMS','digest':{'sha256':sha(members['SHA256SUMS'])}}]
            and cert['subjectAlternativeName'] == cert['buildSignerURI'] == identity
            and cert['sourceRepositoryDigest'] == cert['buildSignerDigest'] == '48c934d0927aa8049dfaa42a23bfaed12e541439'
            and cert['issuer'] == 'https://token.actions.githubusercontent.com'
            and cert['runnerEnvironment'] == 'github-hosted'
            and any(t['type'] == 'Tlog' for t in verification['verifiedTimestamps']), 'EXACT_VERIFIED_GATEWAY_PUBLISHER_REQUIRED')
    tree_raw = (root/'releases/m2-gateway-owner-security-source-tree-20261101.json').read_bytes()
    require(sha(tree_raw) == '20c5176330674e4459db6afb393a7e4c750f0ea3abfbe75ae7291bbf3d5b39f2',
            'EXACT_INDEPENDENT_GATEWAY_SOURCE_TREE_REQUIRED')
    tree = json.loads(tree_raw)
    expected = {r['path']:(r['sha'],r['mode']) for r in tree['tree']}
    inventory = json.loads(members['source-inventory.json'])
    require(len(expected) == 230 and tree['truncated'] is False
            and expected == {r['path']:(r['sha'],r['mode']) for r in inventory['tree'] if r['type']=='blob'},
            'COMPLETE_230_GATEWAY_SOURCE_BLOBS_REQUIRED')
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(members['source.tar']),mode='r:') as source:
        for entry in source:
            if entry.isdir(): continue
            require(entry.isfile() and entry.name in expected and entry.name not in seen and entry.size <= 2097152,
                    'BOUNDED_REGULAR_GATEWAY_SOURCE_MEMBER_REQUIRED')
            body = source.extractfile(entry).read(entry.size+1)
            git_blob = hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
            require(len(body) == entry.size and (git_blob,'100755' if entry.mode&0o111 else '100644') == expected[entry.name],
                    'GATEWAY_SOURCE_BYTES_OR_MODE_DIFFER_FROM_GIT')
            seen.add(entry.name)
    counts = dict(Counter(f['Severity'] for r in scan['Results'] for f in r.get('Vulnerabilities',[])))
    require(seen == set(expected) and proof['sourceCommit'] == tree['sourceCommit'] == '17439fed7a45d455baa6945ee72a65fa19c14029'
            and proof['configurationImageId'] == scan['Metadata']['ImageID'] == 'sha256:8c2b47b5d7c2ddcf55cfa644ad3b61a397e67c9fc9651dc8a20fea9fbe805906'
            and proof['nativeImageId'] == 'sha256:502ba0e41a67b3db46a2cd08c31ccb7b7cce0faa0e3952e1143e1415f952d25f'
            and proof['scanSha256'] == sha(members['trivy-image.json'])
            and proof['freshScanGatePassed'] is True and not any(counts.get(s,0) for s in ('CRITICAL','HIGH','UNKNOWN'))
            and proof['retainedImageSourceMembershipProven'] is False and proof['candidateSelectionChanged'] is False
            and proof['runtimeAuthorityIssued'] is False and proof['targetApplyAuthorized'] is False,
            'QUALIFIED_NEW_OWNER_MUST_NOT_PROMOTE_RETAINED_IMAGE_OR_AUTHORITY')
    return {k:proof[k] for k in ('schema','sourceRepository','sourceCommit','declaredRetainedSourceCommit','nativeImageId',
        'configurationImageId','archiveSha256','scanInputSha256','applicationJarSha256','baseImage','unitTestReports',
        'freshScanGatePassed','scanSha256','candidateSelectionChanged','retainedImageSourceMembershipProven',
        'imageApplicationReadinessProven','targetOperations','targetApplyAuthorized','runtimeAuthorityIssued','releaseAcceptance')} | {
        'runId':41353205013,'jobId':124987637755,'artifactId':13102047484,
        'originalZipSha256':'9af9def1857cefe917b8889143d81b27cf08f5df587f11547c73c922a368e7da',
        'originalZipBytes':298387448,'preservedMetadata':GATEWAY_METADATA_ZIP,'sourceFilesIndependentlyMatched':230,
        'publisherChainVerifiedInNamedHostedJob':True,'publisherChainReverifiedByThisReader':False,
        'vulnerabilityCounts':counts,'scanFreshnessMustBeRecheckedBeforeAdmission':True}


def reconcile(root):
    target_raw = (root / 'evidence/m2-runtime-origin-join-target-20261101.json').read_bytes()
    target = json.loads(target_raw)
    receipt = target['receipt']
    require(sha(encoded(receipt)) == target['publicResultCanonicalSha256'] == TARGET
            and receipt['status'] == 'VERIFIED_RUNTIME_ROLES_JOINED_ORIGIN_CLAIMS_NOT_ADMITTED'
            and receipt['cumulativeControlAttempts'] == 12 and receipt['cumulativeDirectEngineGets'] == 35
            and receipt['allElevenPriorScopesPreserved'] is True and target['scopeConsumed'] is True,
            'EXACT_CONSUMED_SUCCESSFUL_ORIGIN_JOIN_REQUIRED')
    bindings = {r['role']: r for r in receipt['unresolvedOriginBindings']}
    require(len(receipt['unresolvedOriginBindings']) == 3 and set(bindings) == {'semantic', 'gateway-owner', 'minio'},
            'THREE_EXACT_RESIDUAL_ORIGIN_IDENTITIES_REQUIRED')
    result, proof = original_semantic(root, bindings['semantic'])
    path = root / 'tools/m2_discovery_installation_profile/retained_runtime_origin_profile.py'
    assignments = {node.targets[0].id: ast.literal_eval(node.value)
                   for node in ast.parse(path.read_text()).body if isinstance(node, ast.Assign)}
    profile = assignments['PUBLIC_PROFILE']
    require(sha(encoded(profile)) == assignments['PROFILE_HASH'] == receipt['publicOriginProfileHash'],
            'EXACT_CONSUMED_PUBLIC_ORIGIN_PROFILE_REQUIRED')
    roles = json.loads(json.dumps(profile['roles']))
    for name, binding in bindings.items():
        roles[name].update(configurationDigest=binding['configurationDigest'],
                           selectedRuntimeManifestDigest=binding['selectedRuntimeManifestDigest'])
    roles['semantic'].update(originClass='SIGNED_ORIGINAL_COHORT_CONFIG_AND_NATIVE_ENVELOPE_MATCH',
        sourceCommit=SOURCE, originalArtifactId=11907557440, sourceEvidence=proof,
        currentSecurityScanProven=False)
    scan_proof = json.loads((root/'evidence/m2-retained-semantic-scan-readback-20261101.json').read_bytes())
    require(scan_proof['preservedFullReport'] == 'evidence/artifacts/m2-retained-semantic-trivy-20261101.json.gz',
            'EXACT_PRESERVED_IMAGE_SCAN_REPORT_REQUIRED')
    compressed = (root/scan_proof['preservedFullReport']).read_bytes()
    require(len(compressed) <= 2097152 and sha(compressed) == scan_proof['compressedReportSha256'],
            'BOUNDED_UNCHANGED_COMPRESSED_SCAN_REQUIRED')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as source:
        scan_raw = source.read(2097153)
    require(len(scan_raw) <= 2097152, 'BOUNDED_EXPANDED_IMAGE_SCAN_REQUIRED')
    scan = json.loads(scan_raw)
    counts = dict(Counter(f.get('Severity', 'UNKNOWN') for r in scan['Results']
                          for f in r.get('Vulnerabilities', [])))
    require(sha(scan_raw) == scan_proof['result']['scanSha256'] == 'd86f81872997863a471d858272ee9130c845ade6a6afd7cd22151d54f110acb8'
            and scan['Metadata']['ImageID'] == CONFIG
            and counts == scan_proof['result']['vulnerabilityCounts']
            and scan_proof['result']['freshScanGatePassed'] is False
            and scan_proof['workflowConclusion'] == 'failure',
            'EXACT_IMAGE_BOUND_HELD_SCAN_MUST_REMAIN_HELD')
    roles['semantic'].update(freshScanAdmission='HELD_HIGH_CRITICAL_UNKNOWN',
        freshScanEvidence='evidence/m2-retained-semantic-scan-readback-20261101.json',
        freshScanSha256=sha(scan_raw), vulnerabilityCounts=counts,
        remediationCandidate=semantic_remediation(root))
    roles['gateway-owner'].update(originGap='ORIGINAL_CI_ARTIFACT_HAS_REPORTS_ONLY_NO_EXECUTABLE_MEMBERSHIP',
                                   replacementCandidate=gateway_candidate(root))
    roles['minio'].update(originGap='EXACT_COPY_CONTENT_RECOVERED_ORIGINAL_VENDOR_PUBLISHER_UNAUTHENTICATED',
                          exactCopySecurityEvidence=minio_security(root))
    return {
        'schema': 'ouf.m2-retained-runtime-origin-reconciliation.v1', 'date': '2026-11-01',
        'publicOriginJoinResultHash': TARGET, 'publicOriginJoinRecordSha256': sha(target_raw),
        'privateOriginEvidenceHash': receipt['privateEvidenceHash'],
        'evidenceOrigin': 'OPERATOR_PUBLIC_RECEIPT_PLUS_EXACT_PRESERVED_CI_ARTIFACT_AND_INDEPENDENT_GIT_TREE',
        'roles': roles, 'roleCount': len(roles), 'publicSourceOrDescriptorReferenceBindings': 11,
        'originalSignedSemanticSourceJoined': True, 'remainingOriginGaps': ['gateway-owner', 'minio'],
        'freshSecurityAdmissionOfAllRetainedImagesProven': False,
        'agentReadPrivateTargetProof': False, 'allRuntimeArtifactMembershipProven': False,
        'completePrivateCustodyProven': False, 'currentApplicationConfigurationOrLivenessProven': False,
        'targetControlAttemptsAdded': 0, 'directEngineGets': 0,
        'cumulativeTargetControlsUnchanged': 12, 'cumulativeTargetEngineGetsUnchanged': 35,
        'candidateSelectionChanged': False, 'runtimeAuthorityIssued': False,
        'targetApplyAuthorized': False, 'releaseAcceptance': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = reconcile(root)
    if args.check:
        require(json.loads((root / OUTPUT).read_text()) == report, 'RECONCILED_PUBLIC_ORIGIN_REPORT_CHANGED')
    else:
        (root / OUTPUT).write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('roleCount', 'originalSignedSemanticSourceJoined',
        'remainingOriginGaps', 'targetControlAttemptsAdded', 'runtimeAuthorityIssued')}))
