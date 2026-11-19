#!/usr/bin/env python3
"""Installation-specific fresh descriptor diagnostic after successful control deployment.
Reuses Teatri descriptor transport/pagination and qualified SERVICE reader login/custody.
No old entrypoint, scope, token, policy change, grant, job budget or resume.
"""
import base64
from datetime import datetime,timezone
import re,stat,hashlib,json,os,signal,sys,time
from pathlib import Path
import urllib.error,urllib.parse,urllib.request
ISSUER="https://auth.ouf-lab.it/realms/ouf"
ORIGIN="https://api.ouf-lab.it"
ADMIN=ORIGIN+"/api/trusted-human/v1/authorization"
SUBJECT="b93d8cf6-cd14-4ee6-91d7-84cd76c4f500"
CAPS=("ouf.managed-source.preview","ouf.managed-source.file.profile","ouf.onboarding.quarantine.release")
CASE={'policyRef': 'ouf-lab-authorization:56', 'policyHash': 'c52e856c8d95032f6942e1618fb0102f0b704acc5f41f044648e9466aaf9d323', 'requiredRoleCapabilities': ['authorization.permissions.propose', 'authorization.permissions.read', 'authorization.policy.admin', 'authorization.proposal.read', 'ingestion.contract.read', 'ingestion.lineage.read', 'ingestion.run.read', 'installation.configuration.activate', 'installation.configuration.export', 'installation.configuration.read', 'installation.configuration.write', 'lineage.object.read', 'lineage.property.read', 'operations.status.read', 'ouf.gateway.operations.summary', 'ouf.ingestion.operations.summary', 'ouf.managed-source.file.profile', 'ouf.managed-source.file.upload', 'ouf.managed-source.onboarding.create', 'ouf.managed-source.onboarding.read', 'ouf.managed-source.onboarding.review.prepare', 'ouf.managed-source.preview', 'ouf.onboarding.configuration.write', 'ouf.onboarding.quarantine.release', 'ouf.onboarding.revision.prepare', 'ouf.onboarding.revision.read', 'ouf.operations.summary', 'ouf.semantic.approval.request', 'ouf.semantic.approve', 'ouf.semantic.proposal.read', 'ouf.semantic.propose', 'ouf.semantic.publish', 'ouf.semantic.review', 'ouf.semantic.review.prepare', 'ouf.semantic.search', 'ouf.system.status', 'resolution.issue.read', 'resolution.match.approve', 'urban.identity.preflight', 'urban.object.read', 'urban.object.search']}
class Stop(Exception):
    pass

def require(value, code):
    if not value:
        raise Stop(code)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop("REDIRECT_DENIED")

class Transport:
    def __init__(self, *, clock=time.monotonic, reserve=None):
        self.clock = clock
        self.deadline = clock() + 600
        self.counts = {"iamGets": 0, "iamPosts": 0, "ownerGets": 0, "bytes": 0}
        self.opener = urllib.request.build_opener(NoRedirect())
        self.reserve = reserve or (lambda counts: None)

    def request(self, url, *, form=None, token=None):
        require(self.clock() < self.deadline, "FINITE_READ_EXPIRED")
        metadata = url == ISSUER + "/.well-known/openid-configuration"
        iam_post = url in (ISSUER + "/protocol/openid-connect/auth/device",
                           ISSUER + "/protocol/openid-connect/token")
        owner = url == ADMIN + "/policies/active" or url in {
            ADMIN + "/capabilities?limit=200&offset=" + str(n)
            for n in range(0, 10000, 200)}
        require((metadata and form is None and token is None)
                or (iam_post and form is not None and token is None)
                or (owner and form is None and isinstance(token, str) and bool(token)),
                "EXACT_READ_ENDPOINT_REQUIRED")
        kind = "ownerGets" if owner else "iamPosts" if iam_post else "iamGets"
        maximum = {"ownerGets": 52, "iamPosts": 121, "iamGets": 1}[kind]
        require(self.counts[kind] < maximum, "FINITE_REQUEST_LIMIT")
        self.counts[kind] += 1  # reserve before dispatch, including failed calls
        self.reserve(dict(self.counts))
        body = None if form is None else urllib.parse.urlencode(form).encode("ascii")
        headers = {"Accept": "application/json"}
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="GET" if body is None else "POST")
        try:
            response = self.opener.open(req, timeout=min(20, max(.1, self.deadline-self.clock())))
        except urllib.error.HTTPError as exc:
            # Only OAuth protocol errors are interpreted; owner errors are never echoed.
            if not iam_post or exc.code not in (400, 429):
                raise Stop("OWNER_HTTP_" + str(exc.code) if owner else "IAM_HTTP_FAILURE") from None
            response = exc
        except (OSError, urllib.error.URLError, TimeoutError):
            raise Stop("READ_TRANSPORT_STOP_NO_RETRY") from None
        with response:
            require(response.geturl() == url, "REDIRECT_DENIED")
            raw = response.read(2_000_001)
            self.counts["bytes"] += len(raw)
            self.reserve(dict(self.counts))
            require(len(raw) <= 2_000_000 and self.counts["bytes"] <= 16_000_000,
                    "BOUNDED_RESPONSE_REQUIRED")
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise Stop("INVALID_OWNER_JSON") from None
            return response.code, data

def login(transport, *, sleep=time.sleep, emit=None, wall=time.time):
    emit = emit or (lambda message: print(message, flush=True))
    status, metadata = transport.request(ISSUER + "/.well-known/openid-configuration")
    require(status == 200 and isinstance(metadata, dict) and metadata.get("issuer") == ISSUER,
            "EXACT_ISSUER_REQUIRED")
    device = ISSUER + "/protocol/openid-connect/auth/device"
    endpoint = ISSUER + "/protocol/openid-connect/token"
    require(metadata.get("device_authorization_endpoint") == device
            and metadata.get("token_endpoint") == endpoint, "EXACT_IAM_ENDPOINTS_REQUIRED")
    status, start = transport.request(device, form={"client_id": "ouf-human-admin",
                                                   "scope": "openid authorization.policy.admin"})
    require(status == 200 and isinstance(start, dict), "DEVICE_START_FAILED")
    uri = start.get("verification_uri")
    require(uri == ISSUER + "/device" and isinstance(start.get("user_code"), str)
            and 0 < len(start["user_code"]) <= 32
            and all(c.isalnum() or c == "-" for c in start["user_code"])
            and isinstance(start.get("device_code"), str)
            and 0 < len(start["device_code"]) <= 4096,
            "EXACT_DEVICE_RESPONSE_REQUIRED")
    expires = start.get("expires_in")
    interval = start.get("interval", 5)
    require(type(expires) is int and expires > 0 and type(interval) is int and interval > 0,
            "FINITE_DEVICE_WINDOW_REQUIRED")
    deadline = min(transport.deadline, transport.clock() + min(expires, 600))
    interval = max(5, min(interval, 30))
    emit("Apri nel browser: " + uri)
    emit("Codice da inserire solo nel browser: " + start["user_code"])
    emit("Accedi con ouf-admin. Non incollare codice o token in chat. Sola lettura di policy e cataloghi capability; nessuna pubblicazione, grant, budget o resume.")
    for _ in range(120):
        require(transport.clock() + interval < deadline, "DEVICE_WINDOW_EXPIRED")
        sleep(interval)
        status, reply = transport.request(endpoint, form={
            "client_id": "ouf-human-admin",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"]})
        require(isinstance(reply, dict), "INVALID_TOKEN_RESPONSE")
        if status == 200:
            token = reply.get("access_token")
            require(isinstance(token, str) and 0 < len(token) <= 16384
                    and not any(c.isspace() for c in token), "BOUNDED_TOKEN_REQUIRED")
            try:
                parts = token.split(".")
                require(len(parts) == 3, "TOKEN_CONTEXT_REQUIRED")
                claims = json.loads(base64.urlsafe_b64decode(parts[1]+"="*(-len(parts[1]) % 4)))
            except (ValueError, UnicodeError, TypeError):
                raise Stop("TOKEN_CONTEXT_REQUIRED") from None
            # This local check selects the account; the owner verifies JWT authenticity.
            require(isinstance(claims, dict) and claims.get("iss") == ISSUER
                    and claims.get("sub") == SUBJECT and claims.get("tenant_id") == "ouf-lab"
                    and claims.get("ouf_actor_type") == "HUMAN"
                    and type(claims.get("exp")) in (int, float) and claims["exp"] > wall()
                    and "authorization.policy.admin" in str(claims.get("scope", "")).split(),
                    "EXACT_OUF_ADMIN_CONTEXT_REQUIRED")
            return token
        error = reply.get("error")
        if error == "slow_down":
            interval = min(30, interval + 5)
        elif error != "authorization_pending":
            raise Stop("DEVICE_LOGIN_STOP_NO_RETRY")
    raise Stop("DEVICE_POLL_LIMIT")

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()

def observe(transport, token, *, case=CASE, retain=lambda name,value: None):
    status, before = transport.request(ADMIN + "/policies/active", token=token)
    require(status == 200 and isinstance(before, dict) and isinstance(before.get("policy"), dict)
            and isinstance(before.get("policyRef"), str) and isinstance(before.get("contentHash"), str),
            "ACTIVE_POLICY_REQUIRED")
    retain("active-before.json",before)
    require(before["policyRef"]==case["policyRef"] and before["contentHash"].removeprefix("sha256:")==case["policyHash"]
            and before["policy"].get("bundleId")=="ouf-lab-authorization" and before["policy"].get("version")==56,
            "EXACT_CURRENT_POLICY56_REQUIRED_NO_DRIFT_ADOPTION")
    descriptors = before["policy"].get("capabilities")
    require(isinstance(descriptors, list) and len(descriptors) <= 10000, "BOUNDED_ACTIVE_CATALOGUE_REQUIRED")
    active = {}
    for row in descriptors:
        require(isinstance(row, dict) and isinstance(row.get("capabilityId"), str)
                and row["capabilityId"] not in active, "DUPLICATE_ACTIVE_DESCRIPTOR")
        active[row["capabilityId"]] = row
    registered = {}
    for offset in range(0, 10000, 200):
        status, rows = transport.request(ADMIN + "/capabilities?limit=200&offset=" + str(offset), token=token)
        retain("registrations-%05d.json"%offset,rows)
        require(status == 200 and isinstance(rows, list) and len(rows) <= 200, "BOUNDED_REGISTRATION_PAGE_REQUIRED")
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("capability_id"), str)
                    and row["capability_id"] not in registered, "DUPLICATE_REGISTERED_DESCRIPTOR")
            descriptor = row.get("descriptor")
            if isinstance(descriptor, dict) and descriptor.get("type") == "jsonb":
                descriptor = descriptor.get("value")
            if isinstance(descriptor, str):
                try:
                    descriptor = json.loads(descriptor)
                except (ValueError, UnicodeError):
                    raise Stop("INVALID_REGISTRATION_DESCRIPTOR") from None
            require(isinstance(descriptor, dict), "INVALID_REGISTRATION_DESCRIPTOR")
            registered[row["capability_id"]] = {"ownerRef": row.get("owner_ref"), "descriptor": descriptor}
        if len(rows) < 200:
            break
    else:
        raise Stop("REGISTRATION_PAGE_LIMIT")
    status, after = transport.request(ADMIN + "/policies/active", token=token)
    retain("active-after.json",after)
    require(status == 200 and before == after, "ACTIVE_CHANGED_RECONCILE")
    projected = []
    for cap in CAPS:
        owner = "onboarding"
        expected = {"capabilityId": cap, "operation": "READ", "requiredScope": cap, "allowedActors": ["HUMAN"]}
        descriptor = active.get(cap)
        reg = registered.get(cap)
        # Print exact target descriptor fields, never grants or unrelated catalogue content.
        def minimized(d):
            return None if d is None else {k: d.get(k) for k in expected}
        projected.append({"capabilityId": cap, "sourceOwnerRef": owner,
                          "activeDescriptor": minimized(descriptor),
                          "activeHumanCompatible": isinstance(descriptor, dict)
                          and isinstance(descriptor.get("allowedActors"), list)
                          and "HUMAN" in descriptor["allowedActors"],
                          "registeredOwnerRef": reg["ownerRef"] if reg else None,
                          "registeredDescriptor": minimized(reg["descriptor"]) if reg else None})
    return {"schema": "ouf.managed-profile-control-capability-read.v1", "status": "MANAGED_PROFILE_CAPABILITY_STATE_OBSERVED_NO_AUTHORITY",
            "complete": True, "policyRef": before["policyRef"], "policyHash": before["contentHash"],
            "activeResponseHash": fingerprint(before), "catalogueHash": fingerprint(registered), "descriptors": projected,
            "invalidRoleCapabilities": [cap for cap in case["requiredRoleCapabilities"]
                if cap not in active or "HUMAN" not in (active[cap].get("allowedActors")or[])],
            "requiredRoleCapabilityCount":len(case["requiredRoleCapabilities"]),
            "humanBudgetsGranted":0,"resumes":0,"fileContentReads":0,"sqlSessions":0,"policyWrites":0,"credentialFileReads":0,"signingKeyReads":0,"newJobs":0,"uploads":0,
            "counts": dict(transport.counts), "administrativeWrites": 0, "engineRequests": 0,
            "newCredentialFileReads": 0, "sourceActivations": 0, "acquisitionsExecuted": 0,
            "runtimeAuthorityIssued": False, "budgetReset": False, "automaticReplayAllowed": False,
            "applicationE2EProven": False, "releaseAcceptance": False}

class Logger:
    def __init__(self, path):
        self.original = sys.stdout
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.file = os.fdopen(fd, "w", buffering=1)

    def write(self, value):
        self.file.write(value); self.file.flush(); os.fsync(self.file.fileno())
        return self.original.write(value)

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno()); self.original.flush()

    def isatty(self):
        return self.original.isatty()

    def fileno(self):
        return self.original.fileno()

def ancestry(path):
    for parent in (path, *path.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0
                and not st.st_mode & 0o022, "ROOT_READ_SCOPE_ANCESTRY_REQUIRED")

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            "ONE_ISOLATED_ROOT_DESCRIPTOR_READER_REQUIRED")
    require(sys.stdin.isatty() and sys.stdout.isatty(), "INTERACTIVE_OPERATOR_TERMINAL_REQUIRED")
    code = Path(__file__).resolve()
    ancestry(code.parent)
    st = code.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o400, "PROTECTED_READER_ROOT400_REQUIRED")
    sys.stdout = Logger(code.parent / "operator.log")
    directory = Path("/etc/ouf/deploy-snapshots/managed-profile-capability-read-policy56-20261028-v1")
    ancestry(directory.parent)
    require(not os.path.lexists(directory), "DESCRIPTOR_READ_SCOPE_CONSUMED_NO_REPLAY")
    directory.mkdir(mode=0o700); directory.chmod(0o700); sync(directory.parent)

    def save(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        require(len(raw) <= 65536, "BOUNDED_READ_RESULT_REQUIRED")
        temporary = directory / "state.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, directory / "state.json"); sync(directory)

    save({"state": "CLAIMED", "automaticReplayAllowed": False, "budgetReset": False})
    transport = Transport(reserve=lambda counts: save({"state": "READING", "counts": counts,
                          "automaticReplayAllowed": False, "budgetReset": False}))
    print("PrivateContext=" + str(directory), flush=True)
    print("Nuovo diagnostico: policy56 e registrazioni capability, massimo52GET/16MB/600s; zero mutazioni, Engine, SQL, file credenziali/chiavi, budget, resume o file CSV. Solo login HUMAN ouf-admin; nessun APPROVO.",flush=True)
    def expired(*_):raise Stop("FINITE_DESCRIPTOR_READ_WINDOW_EXPIRED")
    signal.signal(signal.SIGALRM,expired);signal.alarm(600)
    def retain(name,value):
        require(re.fullmatch(r"(?:active-before|active-after|registrations-[0-9]{5})\.json",name) is not None,"CLOSED_DESCRIPTOR_EVIDENCE_NAME_REQUIRED")
        raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        require(0<len(raw)<=2_000_000,"BOUNDED_PRIVATE_DESCRIPTOR_EVIDENCE_REQUIRED")
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb")as out:
            os.fchmod(out.fileno(),0o600);out.write(raw);out.flush();os.fsync(out.fileno())
        sync(directory)
    try:
        token = login(transport)
        result = observe(transport, token,retain=retain)
        del token
    except BaseException:
        save({"state": "STOP_RECONCILE", "counts": dict(transport.counts),
              "automaticReplayAllowed": False, "budgetReset": False})
        raise
    signal.alarm(0)
    save(result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)

if __name__ == "__main__":
    try:
        main()
    except Stop as exc:
        print(json.dumps({"status": "STOP_RECONCILE", "reasonCode": str(exc),
                          "automaticReplayAllowed": False, "runtimeAuthorityIssued": False,
                          "applicationE2EProven": False, "releaseAcceptance": False}), flush=True)
        sys.exit(2)
    except Exception:
        print('{"status":"STOP_RECONCILE","reasonCode":"PRIVATE_DETAILS_REDACTED","automaticReplayAllowed":false}', flush=True)
        sys.exit(2)
