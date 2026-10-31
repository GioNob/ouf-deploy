"""Discovery transport reads one signed Engine OCI, never a private journal.

The historical NativeBackend and its credential/journal readers stay unchanged.
Only bindings' OCI read differs; namespace, reciprocal NIC/peer and generation
checks retain the exact original source structure (qualified by parity test).
"""
import os,re,stat
from pathlib import Path
from .custody_capture import decode,require
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_preexec import PreexecDenied,digest
from tools.semantic_provider_lease_coordination import _ancestors
from tools.semantic_provider_deployment_authentication import attributes
import json


class EngineTransportBackend(NativeBackend):
    def __init__(self,profile,commands,budget,*,bundle_parent):
        parent=Path(bundle_parent)
        require(type(bundle_parent) is str and parent.is_absolute() and str(parent)==bundle_parent
            and '..' not in parent.parts and parent!=Path('/'), 'EXACT_DISCOVERY_ENGINE_BUNDLE_PARENT_REQUIRED')
        self.bundle_parent=bundle_parent;self.parent_seal=bundle_parent
        super().__init__(profile,commands,budget)

    def engine_bundle(self,profile):
        require(digest(profile)==self.seal and self.bundle_parent==self.parent_seal,
            'DISCOVERY_ENGINE_BUNDLE_PROFILE_OR_PARENT_DRIFT')
        cid=profile['containerId'];path=Path(profile['bundlePath'])/'config.json'
        require(type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid)
            and path==Path(self.bundle_parent)/cid/'config.json', 'EXACT_DISCOVERY_ENGINE_CID_BUNDLE_REQUIRED')
        _ancestors(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode) in (0o600,0o644) and before.st_nlink==1
                and 0<before.st_size<=131072, 'CUSTODIED_DISCOVERY_ENGINE_OCI_REQUIRED')
            raw=os.read(fd,131073)
            require(len(raw)==before.st_size and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat()),
                'DISCOVERY_ENGINE_OCI_CHANGED_DURING_READ')
        finally:os.close(fd)
        bundle=decode(raw)
        require(digest(bundle)==profile['bundleHash'],'SIGNED_DISCOVERY_ENGINE_FULL_OCI_REQUIRED')
        return bundle

    def bindings(self, profile, state):
        if digest(profile) != self.seal: raise PreexecDenied('PROFILE_BACKEND_BINDING_DRIFT')
        bundle = self.engine_bundle(profile)
        if digest(bundle) != profile['bundleHash']: raise PreexecDenied('OCI_BUNDLE_DRIFT')
        networks = [v for v in bundle['linux']['namespaces'] if v.get('type') == 'network']
        expected_networks = [{'type': 'network'}] if profile.get('namespaceOrigin') == 'OCI_CREATED' \
            else [{'type': 'network', 'path': profile['namespacePath']}]
        if networks != expected_networks \
                or set(bundle.get('hooks', {})) - {'prestart', 'createRuntime'}:
            raise PreexecDenied('PREPARED_NAMESPACE_AND_HOOK_ORDER_REQUIRED')
        namespace = Path(profile['namespacePath']); _ancestors(namespace)
        value = namespace.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 \
                or value.st_ino != profile['namespaceInode']:
            raise PreexecDenied('PREPARED_NAMESPACE_DRIFT')
        # Query only approved indexes, so thousands of unrelated host ports do
        # not consume this candidate's bounded native output/time budget.
        indexes = {v['ifindex'] for v in profile['policy']['attachments']}
        indexes.update(v['peerIngress']['ifindex'] for v in profile['policy']['flows']
                       if v['peerIngress']['kind'] != 'HOST')
        indexed = {i:self.link(i) for i in indexes}
        for attachment, child in zip(profile['policy']['attachments'], profile['namespaceLinks']):
            link = indexed.get(attachment['ifindex'])
            if link is None or link['ifname'] != attachment['interface'] or link.get('master') != attachment['bridge'] \
                    or link.get('link_index') != child['ifindex']:
                raise PreexecDenied('HOST_PORT_BINDING_DRIFT')
            peers = json.loads(self.run('nsenter', ['--net='+str(namespace), self.commands['ip'],
                '-j', 'addr', 'show', 'dev', child['interface']]))
            if len(peers) != 1: raise PreexecDenied('NAMESPACE_PORT_REQUIRED')
            peer = peers[0]
            addresses = [v['local'] for v in peer['addr_info'] if v['family'] == 'inet']
            if peer['ifindex'] != child['ifindex'] or peer.get('link_index') != attachment['ifindex'] \
                    or peer['address'] != attachment['mac'] or addresses != [attachment['ipv4']]:
                raise PreexecDenied('NAMESPACE_PORT_BINDING_DRIFT')
        for flow in profile['policy']['flows']:
            ingress = flow['peerIngress']
            if ingress['kind'] == 'HOST': continue
            peer = indexed.get(ingress['ifindex'])
            if peer is None: raise PreexecDenied('LIVE_PEER_INTERFACE_REQUIRED')
            if ingress['kind'] == 'BRIDGE_PORT':
                protected = next(v for v in profile['policy']['attachments']
                    if v['ipv4'] in (flow['source'], flow['destination']))
                if peer.get('master') != protected['bridge']:
                    raise PreexecDenied('LIVE_PEER_BRIDGE_DRIFT')
        if state is None: return None
        generation = self.generation(state['pid'])
        if generation['namespaceInode'] != profile['namespaceInode']:
            raise PreexecDenied('OCI_PROCESS_NAMESPACE_DRIFT')
        return generation
