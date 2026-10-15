"""Local Engine creation/reconciliation primitive for a sealed installer.

No target CLI, authority verification, image import, start, networking change,
lease or database operation. Caller pins socket custody, authenticates source
and transition authority, and proves old endpoint release at each checkpoint.
"""
import http.client
import hashlib
import json
import os
import re
import socket
import stat


class CreationDenied(RuntimeError): pass


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def require(ok, reason):
    if not ok: raise CreationDenied(reason)


def requested_host_config_matches(expected, actual, *, started=False):
    """Keep the standalone Engine closure; compare only the proven OOM default.

    Moby declares HostConfig.Mounts with json omitempty. Only a requested empty
    list can round-trip as null/absent. Binds and nonempty mount specs retain
    exact comparison. Native dictionaries and generation hashes never change.
    """
    if type(expected) is not dict or type(actual) is not dict: return False
    for key, value in expected.items():
        if key == 'Mounts' and type(value) is list and not value:
            if actual.get(key) is None: continue
        if key == 'OomKillDisable' and started:
            if key not in actual: return False
            current = actual[key]
            if (value is None or value is False) and (current is None or current is False): continue
            if value is True and current is True: continue
            return False
        if actual.get(key) != value: return False
    return True


def started_host_config_matches(expected, actual):
    return requested_host_config_matches(expected,actual,started=True)


class Engine:
    def __init__(self, socket_path, socket_binding):
        self.path, self.binding = socket_path, socket_binding
        self.check_socket()

    def check_socket(self):
        s = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) in {0o600,0o660},
                'ENGINE_SOCKET_CUSTODY_REQUIRED')
        require((s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)) == self.binding,
                'ENGINE_SOCKET_BINDING_CHANGED')

    def request(self, method, path, body=None):
        self.check_socket()
        engine_path = self.path
        class Local(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout);self.sock.connect(engine_path)
        connection = Local('localhost',timeout=15)
        try:
            raw = None if body is None else json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            require(raw is None or len(raw) <= 262144, 'BOUNDED_CREATION_REQUEST_REQUIRED')
            connection.request(method,path,body=raw,headers={'Content-Type':'application/json'})
            response = connection.getresponse(); payload = response.read(2097153)
            require(len(payload) <= 2097152, 'ENGINE_RESPONSE_UNBOUNDED')
            self.check_socket()
            return response.status, json.loads(payload) if payload else None
        except (OSError, ValueError, http.client.HTTPException):
            # Neither timeout nor missing response proves no mutation occurred.
            raise CreationDenied('ENGINE_OUTCOME_REQUIRES_RECONCILIATION') from None
        finally:
            connection.close()

    @staticmethod
    def name(transition):
        return 'ouf-semantic-cutover-'+transition.context

    def inspect(self, transition):
        status, value = self.request('GET','/v1.44/containers/'+self.name(transition)+'/json')
        if status == 404: return None
        require(status == 200 and type(value) is dict, 'EXACT_CREATION_INSPECTION_REQUIRED')
        return value

    def matching_configuration(self, transition, request, actual):
        require(type(actual) is dict and all(type(actual.get(k)) is dict
                for k in ('Config','HostConfig','State')), 'CREATION_NATIVE_SHAPE_UNPROVEN')
        require(type(request) is dict and type(request.get('Image')) is str
                and re.fullmatch('sha256:[0-9a-f]{64}',request['Image']) is not None,
                'EXACT_CREATION_IMAGE_REQUIRED')
        require(actual['Name'] == '/'+self.name(transition) and actual['Image'] == request['Image']
                and re.fullmatch('[0-9a-f]{64}',actual['Id']) is not None,
                'CREATION_NATIVE_IDENTITY_DRIFT')
        for key, expected in request.items():
            if key in {'HostConfig','NetworkingConfig'}: continue
            require(actual['Config'].get(key) == expected, 'CREATION_CONFIG_DRIFT')
        if actual['State'].get('Running') is True:
            # Moby may restore the default OomKillDisable=false to null at
            # start when the kernel lacks that control. Keep native hashes
            # unchanged; only that documented pair compares equivalently.
            require(started_host_config_matches(request.get('HostConfig',{}),actual['HostConfig']),
                    'CREATION_HOST_CONFIG_DRIFT')
        else:
            require(requested_host_config_matches(request.get('HostConfig',{}),actual['HostConfig']),
                    'CREATION_HOST_CONFIG_DRIFT')
        # Actual NICs, mount projections, all expanded OCI fields and live peer
        # generation require the NEXT authenticated attestation phase. This
        # creation consistency check never grants start or transport authority.
        return actual

    def matching_created(self, transition, request, actual):
        actual = self.matching_configuration(transition,request,actual)
        require(actual['State']['Status'] == 'created' and actual['State']['Running'] is False
                and actual['State']['Pid'] == 0, 'CREATION_ALREADY_STARTED_OR_STATE_UNKNOWN')
        return actual

    def create_once(self, transition, request, authority_evidence_hash, checkpoint):
        row = transition.read()
        intent = digest(request)
        require(row['creationRequestHash'] == intent, 'SEALED_CREATION_REQUEST_DRIFT')
        require(row['state'] == 'READY' and row['nextPhase'] == 4, 'EXACT_CREATION_PHASE_REQUIRED')
        checkpoint('BEFORE_CREATION_CLAIM')
        require(self.inspect(transition) is None, 'EXISTING_CONTAINER_REQUIRES_RECONCILIATION')
        transition.begin('CREATE_REPLACEMENT', intent, authority_evidence_hash, row['version'])
        checkpoint('BEFORE_CREATION_EFFECT')
        status, result = self.request('POST','/v1.44/containers/create?name='+self.name(transition),request)
        require(status == 201 and type(result) is dict and re.fullmatch('[0-9a-f]{64}',result.get('Id','')) is not None,
                'CREATION_OUTCOME_REQUIRES_RECONCILIATION')
        actual = self.matching_created(transition,request,self.inspect(transition))
        require(actual['Id'] == result['Id'], 'CREATION_RESPONSE_IDENTITY_DRIFT')
        checkpoint('AFTER_CREATION_EFFECT')
        # Caller may die here; the next invocation observes this exact object.
        return actual

    def reconcile(self, transition, request, checkpoint):
        row = transition.read();intent = digest(request)
        require(row['creationRequestHash'] == intent and row['state'] == 'IN_FLIGHT'
                and row['effects'][-1]['phase'] == 'CREATE_REPLACEMENT'
                and row['effects'][-1]['intentHash'] == intent, 'EXACT_IN_FLIGHT_CREATION_REQUIRED')
        checkpoint('BEFORE_CREATION_RECONCILIATION')
        actual = self.inspect(transition)
        if actual is None:
            # Absence now cannot establish that a container was never created
            # or subsequently removed. Keep the consumed intent ambiguous.
            transition.reconcile('CREATE_REPLACEMENT',intent,'UNKNOWN',digest({'nativeNameAbsent':True}),row['version'])
            raise CreationDenied('CREATION_ABSENT_HISTORY_UNPROVEN')
        actual = self.matching_created(transition,request,actual)
        following = self.inspect(transition)
        require(following == actual, 'CREATION_CHANGED_DURING_RECONCILIATION')
        checkpoint('AFTER_CREATION_RECONCILIATION')
        return transition.reconcile('CREATE_REPLACEMENT',intent,'APPLIED',digest(actual),row['version'])

    def stage_paused_once(self, transition, request, authority_evidence_hash, checkpoint):
        """Create a live namespace behind owner-proven DB and lease fences.

        Checkpoints MUST prove fresh database admission closed, producers stopped,
        old leases revoked, source/authority and native command custody. A no-op
        checkpoint is valid only in isolated fixtures. No start after a crash.
        The early JVM may exit before pause; this blocks instead of reopening DB
        or retrying start. Native pause is not full OCI/peer attestation.
        """
        row = transition.read()
        require(row['creationRequestHash'] == digest(request) and row['state'] == 'READY'
                and row['effects'][-1]['phase'] == 'CREATE_REPLACEMENT', 'CREATION_APPLIED_BEFORE_STAGE_REQUIRED')
        actual = self.matching_created(transition,request,self.inspect(transition))
        intent = {'containerId':actual['Id'],'creationRequestHash':digest(request),
                  'createdEvidenceHash':row['effects'][-1]['nativeEvidenceHash']}
        checkpoint('BEFORE_PAUSED_STAGE_CLAIM')
        transition.begin('STAGE_PAUSED_REPLACEMENT',digest(intent),authority_evidence_hash,row['version'])
        checkpoint('BEFORE_PAUSED_STAGE_EFFECT')
        cid = actual['Id']
        status,_ = self.request('POST','/v1.44/containers/'+cid+'/start')
        require(status == 204, 'PAUSED_STAGE_START_OUTCOME_UNPROVEN')
        status,_ = self.request('POST','/v1.44/containers/'+cid+'/pause')
        require(status == 204, 'PAUSED_STAGE_PAUSE_OUTCOME_UNPROVEN')
        actual = self.matching_paused(transition,request,intent,self.inspect(transition))
        checkpoint('AFTER_PAUSED_STAGE_EFFECT')
        return intent, actual

    def matching_paused(self, transition, request, intent, actual):
        require(type(intent) is dict and set(intent) == {'containerId','creationRequestHash','createdEvidenceHash'}
                and intent['creationRequestHash'] == digest(request), 'EXACT_PAUSED_STAGE_INTENT_REQUIRED')
        actual = self.matching_configuration(transition,request,actual)
        require(actual['Id'] == intent['containerId'] and actual['State']['Running'] is True
                and actual['State']['Paused'] is True and actual['State']['Status'] == 'paused'
                and type(actual['State']['Pid']) is int and actual['State']['Pid'] > 1,
                'EXACT_LIVE_PAUSED_GENERATION_REQUIRED')
        return actual

    def reconcile_paused(self, transition, request, intent, checkpoint):
        row = transition.read()
        require(row['state'] == 'IN_FLIGHT' and row['effects'][-1]['phase'] == 'STAGE_PAUSED_REPLACEMENT'
                and row['effects'][-1]['intentHash'] == digest(intent), 'EXACT_IN_FLIGHT_PAUSED_STAGE_REQUIRED')
        checkpoint('BEFORE_PAUSED_STAGE_RECONCILIATION')
        actual = self.matching_paused(transition,request,intent,self.inspect(transition))
        require(actual == self.inspect(transition), 'PAUSED_STAGE_CHANGED_DURING_RECONCILIATION')
        checkpoint('AFTER_PAUSED_STAGE_RECONCILIATION')
        return transition.reconcile('STAGE_PAUSED_REPLACEMENT',digest(intent),'APPLIED',digest(actual),row['version'])

    @staticmethod
    def runtime_binding(actual):
        return {'containerId':actual['Id'],'imageId':actual['Image'],
                'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
                'configHash':digest(actual['Config']),'hostConfigHash':digest(actual['HostConfig']),
                'mountsHash':digest(actual['Mounts']),'networkSettingsHash':digest(actual['NetworkSettings'])}

    def unpause_once(self, transition, request, authority_evidence_hash, checkpoint):
        """Release the exact attested paused generation; never start a new one.

        Authenticated checkpoints own full OCI/transport/current lease and scoped
        database admission. A claim/hash or this helper alone supplies none.
        Runtime application health is verified separately after release.
        """
        row = transition.read()
        require(row['creationRequestHash'] == digest(request) and row['state'] == 'READY'
                and row['effects'][-1]['phase'] == 'ADMIT_MIGRATION', 'SCOPED_ADMISSION_BEFORE_UNPAUSE_REQUIRED')
        actual = self.matching_configuration(transition,request,self.inspect(transition))
        require(actual['State']['Running'] and actual['State']['Paused'] and actual['State']['Pid'] > 1,
                'ATTESTED_PAUSED_GENERATION_REQUIRED')
        intent = self.runtime_binding(actual)
        checkpoint('BEFORE_UNPAUSE_CLAIM')
        transition.begin('START_REPLACEMENT',digest(intent),authority_evidence_hash,row['version'])
        checkpoint('BEFORE_UNPAUSE_EFFECT')
        require(self.runtime_binding(self.inspect(transition)) == intent, 'PAUSED_GENERATION_DRIFT_BEFORE_RELEASE')
        status,_ = self.request('POST','/v1.44/containers/'+intent['containerId']+'/unpause')
        require(status == 204, 'UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION')
        actual = self.matching_released(transition,request,intent,self.inspect(transition))
        checkpoint('AFTER_UNPAUSE_EFFECT')
        return intent, actual

    def matching_released(self, transition, request, intent, actual):
        actual = self.matching_configuration(transition,request,actual)
        require(self.runtime_binding(actual) == intent and actual['State']['Running'] is True
                and actual['State']['Paused'] is False and actual['State']['Status'] == 'running',
                'EXACT_RELEASED_GENERATION_UNPROVEN')
        return actual

    def reconcile_released(self, transition, request, intent, checkpoint):
        row = transition.read()
        require(row['state'] == 'IN_FLIGHT' and row['effects'][-1]['phase'] == 'START_REPLACEMENT'
                and row['effects'][-1]['intentHash'] == digest(intent), 'EXACT_IN_FLIGHT_RELEASE_REQUIRED')
        checkpoint('BEFORE_UNPAUSE_RECONCILIATION')
        actual = self.matching_released(transition,request,intent,self.inspect(transition))
        following = self.matching_released(transition,request,intent,self.inspect(transition))
        require(self.runtime_binding(following) == self.runtime_binding(actual), 'RELEASED_GENERATION_DRIFT')
        checkpoint('AFTER_UNPAUSE_RECONCILIATION')
        return transition.reconcile('START_REPLACEMENT',digest(intent),'APPLIED',digest(self.runtime_binding(actual)),row['version'])
