#!/usr/bin/env python3
"""Join consumed public origin receipts to preserved original CI evidence.

This offline report is not a publisher verifier or an installation admission.
The original image/layer and Sigstore chain verification ran in the named CI job;
this reader checks its exact ZIP, signed member closure and independent Git blobs.
It neither changes the frozen installation compilers nor invokes the VPS.
"""
import argparse
import ast
import hashlib
import io
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
    roles['gateway-owner']['originGap'] = 'ORIGINAL_CI_ARTIFACT_HAS_REPORTS_ONLY_NO_EXECUTABLE_MEMBERSHIP'
    roles['minio']['originGap'] = 'EXACT_SELECTED_REGISTRY_DESCRIPTOR_UNAVAILABLE'
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
