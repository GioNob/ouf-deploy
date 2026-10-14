"""Propose actual image/HTTPS bindings, never credentials or runtime authority.

DNS is observation only. Every proposed peer must pass system CA/hostname TLS
and exact issuer discovery; addresses/trust remain unaccepted until governance.
Single90second observation, at most8 discovery GETs, no retry or token endpoint.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import uuid
import iam_binding_candidate as binding

HOST = 'auth.ouf-lab.it'
CONTAINER = 'ouf-keycloak'
ISSUER = 'https://' + HOST + '/realms/ouf'
QUALIFIED_IMAGE = 'sha256:e447933b6a5015646c24a1b927a40202ce07adbadac839e7a1f99c463d68a224'

def docker(args):
    result = subprocess.run(['/usr/bin/docker', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    binding.require(result.returncode == 0, 'SELECTED_KEYCLOAK_ARTIFACT_UNAVAILABLE')
    binding.require(0 < len(result.stdout) <= 262144, 'ARTIFACT_RESPONSE_UNBOUNDED')
    return binding.decode(result.stdout)

def artifact():
    selected = docker(['inspect', '--format', '{"image":{{json .Image}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}', CONTAINER])
    binding.require(type(selected) is dict and set(selected) == {'image', 'running', 'mounts'}
        and selected['running'] is True and re.fullmatch(r'sha256:[0-9a-f]{64}', selected['image'])
        and type(selected['mounts']) is list and len(selected['mounts']) <= 64, 'SELECTED_KEYCLOAK_ARTIFACT_UNPROVEN')
    image = docker(['image', 'inspect', '--format', '{"id":{{json .Id}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}},"digests":{{json .RepoDigests}}}', selected['image']])
    binding.require(image.get('id') == selected['image'], 'SELECTED_IMAGE_ID_CHANGED')
    version = image.get('version')
    if not (type(version) is str and re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){1,3}([.-][A-Za-z0-9]{1,24})?', version)):
        version = None
    code_mount = False
    for mount in selected['mounts']:
        destination = mount.get('Destination') if type(mount) is dict else None
        binding.require(type(destination) is str and destination.startswith('/'), 'CONTAINER_MOUNT_METADATA_UNPROVEN')
        d = Path(destination)
        for code in (Path('/opt/keycloak/lib'), Path('/opt/keycloak/providers'), Path('/opt/keycloak/bin')):
            code_mount |= d == code or d in code.parents or code in d.parents
    return {'imageId': selected['image'], 'declaredVersion': version,
        'matchesQualifiedDisposableImage': selected['image'] == QUALIFIED_IMAGE,
        'codeMountObserved': code_mount, 'targetProviderImplementationProven': False,
        'declaredImageIsNotRunningBytecodeProof': True}

def addresses():
    found = set()
    for family, kind, protocol, canonical, address in socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(address[0])
        binding.require(ip.is_global and family in (socket.AF_INET, socket.AF_INET6), 'PUBLIC_ISSUER_PEER_REQUIRED')
        found.add(str(ip))
    binding.require(1 <= len(found) <= 8, 'BOUNDED_ISSUER_PEER_SET_REQUIRED')
    return sorted(found)

class Connection(http.client.HTTPSConnection):
    def __init__(self, address, context):
        super().__init__(HOST, 443, timeout=8, context=context)
        self.address = address
    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=8)
        try: self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close(); raise

def peer_discovery(address, context, report):
    report['discoveryGetAttempts'] += 1
    connection = Connection(address, context)
    try:
        connection.request('GET', '/realms/ouf/.well-known/openid-configuration',
            headers={'Host': HOST, 'Accept': 'application/json', 'Connection': 'close'})
        certificate = connection.sock.getpeercert(binary_form=True)
        response = connection.getresponse()
        report['lastDiscoveryHttpStatus'] = response.status
        binding.require(response.status == 200, 'EXACT_ISSUER_DISCOVERY_HTTP_DENIED')
        length = response.getheader('Content-Length')
        binding.require(length is None or (length.isdigit() and int(length) <= 131072), 'DISCOVERY_RESPONSE_UNBOUNDED')
        raw = response.read(131073)
        binding.require(0 < len(raw) <= 131072, 'DISCOVERY_RESPONSE_UNBOUNDED')
        metadata = binding.decode(raw)
        binding.require(type(metadata) is dict and metadata.get('issuer') == ISSUER
            and metadata.get('token_endpoint') == ISSUER + '/protocol/openid-connect/token'
            and metadata.get('introspection_endpoint') == ISSUER + '/protocol/openid-connect/token/introspect',
            'EXACT_ISSUER_DISCOVERY_BINDING_MISMATCH')
        return {'address': address, 'certificateSha256': hashlib.sha256(certificate).hexdigest(),
                'caAndHostnameVerified': True, 'issuerDiscoveryMatched': True}
    finally: connection.close()

def observe(path, expected_hash, report):
    path = Path(path)
    binding.require(path.parent == binding.PARENT and re.fullmatch(r'policy-token-iam-binding-[0-9a-f]{64}\.private\.json', path.name)
        and re.fullmatch('[0-9a-f]{64}', expected_hash), 'EXACT_REVIEWED_CANDIDATE_REFERENCE_REQUIRED')
    with binding.protected_parent() as directory:
        raw = binding.read_member(directory, path.name)
        binding.require(binding.sha(raw) == expected_hash, 'RETAINED_CANDIDATE_HASH_MISMATCH')
        candidate = binding.decode(raw)
        binding.require(candidate.get('schema') == 'ouf.policy-token-iam-binding-candidate.v3'
            and candidate.get('issuer') == ISSUER and candidate.get('reviewReasons') == []
            and all(candidate.get(k) is False for k in ('runtimeAuthorityIssued', 'productionApplyReady',
                      'credentialProvenanceAccepted', 'historicalAccountingReconciled')),
            'EXACT_REVIEWED_CANDIDATE_REQUIRED')
        report['phase'] = 'KEYCLOAK_ARTIFACT_OBSERVATION'; image = artifact()
        report['phase'] = 'HTTPS_PEER_OBSERVATION'; peers = addresses()
        context = ssl.create_default_context()
        trust = sorted(c.hex() for c in context.get_ca_certs(binary_form=True))
        binding.require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname and trust, 'SYSTEM_TLS_TRUST_UNPROVEN')
        observations = [peer_discovery(address, context, report) for address in peers]
        report['phase'] = 'PROPOSAL_STABILITY_CHECK'
        binding.require(addresses() == peers and artifact() == image, 'OBSERVED_INSTALL_BINDING_CHANGED')
        binding.require(binding.read_member(directory, path.name) == raw, 'RETAINED_CANDIDATE_CHANGED')
        proposal = {'schema': 'ouf.policy-token-install-input-proposal.v1', 'bindingCandidateHash': expected_hash,
            'bindingCandidate': candidate, 'issuerArtifact': image, 'httpsPeers': observations,
            'tlsTrustSetHash': binding.sha(binding.encoded(trust)), 'peerAddressesProposedNotAccepted': True,
            'credentialReestablishmentRequired': True, 'historicalAccountingReconciliationRequired': True,
            'governedInstallerAndCurrentHumanSignaturesRequired': True,
            'runtimeAuthorityIssued': False, 'productionApplyReady': False, 'budgetReset': False, 'notReleaseAcceptance': True}
        body = binding.encoded(proposal); name = 'policy-token-install-inputs-' + binding.sha(body) + '.private.json'
        report.update(phase='PRIVATE_INSTALL_PROPOSAL_PUBLICATION', privateEvidencePath=str(binding.PARENT / name))
        try: fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            binding.require(binding.read_member(directory, name) == body, 'PROPOSAL_RECONCILIATION_REQUIRED')
            report['newProposalPublished'] = False
        else:
            report.update(privateEvidenceWrites=1, newProposalPublished=True)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(os.dup(fd), 'wb') as stream:
                    stream.write(body); stream.flush(); os.fsync(stream.fileno())
                os.fsync(directory)
                binding.require(binding.identity(os.fstat(fd)) == binding.identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'PROPOSAL_MEMBER_CHANGED')
            finally: os.close(fd)
        binding.require(binding.read_member(directory, name) == body, 'PROPOSAL_RECONCILIATION_REQUIRED')
        report.update(status='INSTALL_INPUTS_OBSERVED_NOT_ACCEPTED', phase='OBSERVED_NOT_ACCEPTED',
            privateEvidenceHash=binding.sha(body), bindingCandidateHash=expected_hash,
            httpsPeerCount=len(peers), allObservedPeersCaAndHostnameVerified=True,
            issuerDiscoveryMatched=True, peerAddressesProposedNotAccepted=True, tlsTrustSetHash=proposal['tlsTrustSetHash'], **image)

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--candidate', required=True)
    parser.add_argument('--candidate-sha256', required=True); args = parser.parse_args()
    report = {'schema': 'ouf.policy-token-install-input-observation.v1', 'phase': 'RETAINED_CANDIDATE_READ',
        'observationProfile': 'ouf.policy-token-install-input-observation.single-attempt.v1', 'status': 'BLOCKED',
        'discoveryGetAttempts': 0, 'privateEvidenceWrites': 0, 'credentialFilesRead': 0, 'mountedTokenFilesRead': 0,
        'tokenGrantRequests': 0, 'iamMutations': 0, 'serviceMutations': 0, 'runtimeAuthorityIssued': False,
        'productionApplyReady': False, 'baselineRefreshed': False, 'budgetReset': False, 'r12Touched': False,
        'notReleaseAcceptance': True}
    try:
        def timeout(*_): raise binding.CandidateDenied('INSTALL_INPUT_OBSERVATION_DEADLINE')
        signal.signal(signal.SIGALRM, timeout); signal.alarm(90)
        observe(args.candidate, args.candidate_sha256, report); code = 0
    except Exception as error:
        report['reason'] = str(error) if type(error) is binding.CandidateDenied else (
            'TLS_CA_OR_HOSTNAME_UNPROVEN' if isinstance(error, ssl.SSLError) else type(error).__name__)
        if isinstance(error, OSError): report['errno'] = error.errno
        report['evidencePublicationMayBePartial'] = report['phase'] == 'PRIVATE_INSTALL_PROPOSAL_PUBLICATION'
        code = 1
    finally: signal.alarm(0)
    print(json.dumps(report, sort_keys=True, separators=(',', ':'))); return code

if __name__ == '__main__': raise SystemExit(main())
