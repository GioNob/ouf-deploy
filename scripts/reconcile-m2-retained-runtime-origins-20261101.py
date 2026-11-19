#!/usr/bin/env python3
"""Reconcile existing public receipts; never read target files or issue authority.

This installation-specific inventory joins public role snapshots, not the private
per-role byte proof. Native image IDs, configuration IDs, publisher identity and
unselected replacements remain distinct. No module in a frozen capsule changes.
"""
import argparse
import hashlib
import json
from pathlib import Path

OUTPUT = 'releases/m2-retained-runtime-origin-inventory-20261101.json'
SELECTED_HASH = '039f03a7593c0b826e6597f755c838f85efa197d17d7df3339512f5ee7c52bcc'
ROLES = {'apisix','caddy','gateway-owner','ingestion','ingestion-evidence-read',
         'keycloak','mcp','minio','onboarding','postgres','semantic','udp','udp-evidence-read'}
REGISTRIES = {'apisix':'docker.io/apache/apisix','caddy':'docker.io/library/caddy',
              'keycloak':'quay.io/keycloak/keycloak','minio':'quay.io/minio/minio',
              'postgres':'docker.io/postgis/postgis'}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def reconcile(root):
    inputs = {}
    def load(name):
        raw = (root/name).read_bytes()
        inputs[name] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    def receipt(name):
        item = load(name)
        require(digest(item['receipt']) == item['publicResultCanonicalSha256'], 'PUBLIC_RECEIPT_HASH_DRIFT')
        return item['receipt']
    selected = receipt('evidence/m2-selected-runtime-target-20261101.json')
    graph = receipt('evidence/m2-image-graph-target-20261101.json')
    original = receipt('evidence/m2-discovery-current-bindings-target-20261029.json')
    retained = receipt('evidence/m2-retained-mount-role-correction-target-20261101.json')['retainedRuntimeImageIds']
    origins = load('releases/m2-current-core-artifact-origins-20261101.json')['roles']
    sidecars = load('evidence/acquisition-redaction-offline-plan-qualified-20261026.json')
    applied = load('evidence/acquisition-redaction-apply-target-20261026.json')['result']
    lock = load('releases/m2-current-core-source-lock-20261101.json')
    historical = load('evidence/docker-readiness-20261007.json')
    scans = load('evidence/m2-current-core-original-scan-result-20261101.json')
    repairs = load('releases/m2-scanned-runtime-repair-origins-20261101.json')
    gateway = load('evidence/m2-catalogue-gateway-source-readback-20261101.json')
    require(digest(selected) == SELECTED_HASH and selected['graphResultHash'] == digest(graph), 'EXACT_CONSUMED_SELECTED_BYTE_RESULT_REQUIRED')
    require(selected['selectedRuntimeBytesProven'] is True and selected['selectedRuntimeContentComplete'] is True
            and selected['allTenPriorScopesPreserved'] is True and selected['imageCount'] == 13
            and selected['cumulativeControlAttempts'] == 11 and selected['cumulativeDirectEngineGets'] == 35,
            'EXACT_SUCCESSFUL_THIRTEEN_IMAGE_RECEIPT_REQUIRED')
    for key in ['automaticReplayAllowed','sourcePublisherAuthenticated','allRuntimeArtifactMembershipProven',
                'completePrivateCustodyProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance']:
        require(selected[key] is False, 'RECEIPT_SCOPE_OR_AUTHORITY_DRIFT')
    require(set(retained) == ROLES-{'mcp','semantic','apisix'}, 'EXACT_TEN_RETAINED_ROLES_REQUIRED')
    observed = {}
    for row in original['bindings']:
        name = row['name']
        role = ('semantic' if name.startswith('/ouf-semantic-cutover-') else
                'gateway-owner' if name == '/ouf-gateway-operational-owner' else name.removeprefix('/ouf-'))
        require(role in ROLES and role not in observed, 'EXACT_UNIQUE_PUBLIC_COHORT_ROLES_REQUIRED')
        observed[role] = row['imageId']
    require(set(observed) == ROLES and len(set(observed.values())) == 13, 'EXACT_THIRTEEN_DISTINCT_ROLE_IMAGES_REQUIRED')
    require(all(observed[r] == v for r,v in retained.items()), 'RETAINED_ROLE_IMAGE_CHANGED_BETWEEN_RECEIPTS')
    rows = {r:{'nativeImageId':observed[r], 'originStatus':'UNRESOLVED',
               'privateSelectedProofRoleJoinPerformed':False, 'publisherAuthenticatedByThisInventory':False}
            for r in sorted(ROLES)}
    for role in ['ingestion','mcp','onboarding','udp']:
        origin = origins[role]
        require(origin['currentRoleFromOperatorPublicReceipt'] is True and origin['nativeImageId'] == observed[role],
                'ORIGINAL_CORE_IMAGE_MUST_MATCH_EXACT_OBSERVED_ROLE')
        rows[role].update(originStatus='QUALIFIED_ORIGINAL_ARCHIVE_NATIVE_ID_MATCH',
            sourceRepository=origin.get('sourceRepository',origin['repository']),sourceCommit=origin['sourceCommit'],
            configurationImageId=origin['configurationImageId'],originArtifactId=origin['artifactId'],
            originZipSha256=origin['zipSha256'],expandedArchiveSha256=origin['expandedArchiveSha256'],
            originalScanStatus=('HELD_HIGH_CRITICAL_UNKNOWN' if role in ['ingestion','udp'] else 'PASS_RECORDED_ORIGINAL_SCAN'))
    require(set(scans['successful']) == {'mcp','onboarding'} and set(scans['heldForActualOsFindings']) == {'ingestion','udp'},
            'PRESERVE_ACTUAL_ORIGINAL_SCAN_OUTCOMES')
    qualification = sidecars['nativeQualification']['identities']['profiles']['containerd']
    require(sidecars['candidateSourceCommits'] == applied['candidateSourceCommits'] and applied['complete'] is True,
            'SAME_QUALIFIED_AND_APPLIED_READ_REPLICA_SOURCES_REQUIRED')
    for owner in ['ingestion','udp']:
        role = owner+'-evidence-read'; proof = qualification[owner]
        require(proof == applied['nativeImages'][owner] and proof['nativeImageId'] == observed[role],
                'READ_REPLICA_MUST_MATCH_QUALIFIED_AND_APPLIED_NATIVE_IMAGE')
        rows[role].update(originStatus='QUALIFIED_AND_APPLIED_READ_REPLICA_NATIVE_ID_MATCH',
            sourceCommit=applied['candidateSourceCommits'][owner],configurationImageId=proof['configurationImageId'],
            derivedArchiveSha256=proof['derivedArchiveSha256'],nativeQualificationRun=sidecars['nativeQualification']['pushRun'],
            currentSecurityScanProven=False)
    for role, repository in REGISTRIES.items():
        matches = {c['configuredImage'] for c in historical['components']
                   if c['name'] == 'ouf-'+role and c['imageId'] == observed[role]}
        require(len(matches) == 1, 'EXACT_HISTORICAL_VENDOR_NAME_AND_NATIVE_ID_REFERENCE_REQUIRED')
        rows[role].update(originStatus='HISTORICAL_VENDOR_REFERENCE_ONLY',registryRepository=repository,
            historicalTagReference=matches.pop(),registryDigestLookupRequired=True,currentSecurityScanProven=False)
    old_gateway = next(m for m in lock['modules'] if m['module'] == 'gateway')
    require(old_gateway['retainedRuntimeImageId'] == observed['gateway-owner'], 'RETAINED_GATEWAY_IMAGE_REFERENCE_DRIFT')
    rows['gateway-owner'].update(originStatus='DECLARED_SOURCE_NOT_EXECUTABLE_IMAGE_MEMBERSHIP',
        declaredSourceCommit=old_gateway['commit'],declaredSourceRepository=old_gateway['repository'],
        currentSecurityScanProven=False)
    candidate = origins['semantic']
    require(candidate['currentRoleFromOperatorPublicReceipt'] is False
            and candidate['qualifiedReplacementCandidateNotYetSelected'] is True
            and candidate['nativeImageId'] != observed['semantic'], 'SEMANTIC_REPLACEMENT_MUST_NOT_BECOME_RETAINED_IMAGE_PROOF')
    require(repairs['roles']['ingestion']['selectedForInstallation'] is False
            and repairs['roles']['udp']['selectedForInstallation'] is False, 'REPAIR_SELECTION_MUST_REMAIN_EXPLICIT')
    return {'schema':'ouf.m2-retained-runtime-public-origin-inventory.v1','date':'2026-11-01',
        'selectedRuntimePublicResultHash':SELECTED_HASH,'selectedRuntimePrivateEvidenceHash':selected['privateEvidenceHash'],
        'inputsSha256':inputs,'roles':rows,'publicRoleSnapshotReconciled':True,'roleCount':13,
        'qualifiedOriginalCoreNativeIdMatches':4,'qualifiedAppliedReadReplicaNativeIdMatches':2,
        'historicalVendorReferences':5,'declaredGatewaySourcesWithoutImageMembership':1,'unresolvedRetainedSemanticOrigins':1,
        'unselectedCandidates':{'semantic':candidate,'runtimeOsRepairs':repairs['roles'],
            'gatewayCatalogueMaterializers':{'sourceCommit':gateway['applicationSourceCommit'],'artifactId':gateway['artifactId'],
                'zipSha256':gateway['zipSha256'],'retainedGatewayOwnerRuntimeImageMembershipProven':False}},
        'privateSelectedProofRoleJoinPerformed':False,'allRuntimeArtifactMembershipProven':False,
        'completePrivateCustodyProven':False,'sourcePublisherAuthenticated':False,
        'currentApplicationConfigurationOrLivenessProven':False,'targetControlAttemptsAdded':0,'directEngineGets':0,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    document = reconcile(root)
    target = root/OUTPUT
    if args.check:
        require(json.loads(target.read_text()) == document,'CHECKED_IN_ORIGIN_INVENTORY_DIFFERS_FROM_ORIGINAL_RECEIPTS')
    else:
        target.write_text(json.dumps(document,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'roleCount':13,'coreArchiveMatches':4,'readReplicaMatches':2,'vendorReferences':5,
                      'privateRoleJoinProven':False,'runtimeAuthorityIssued':False}))


if __name__ == '__main__':
    main()
