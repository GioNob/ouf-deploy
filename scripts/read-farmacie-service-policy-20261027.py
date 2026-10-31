#!/usr/bin/env python3
"""One new finite HUMAN read of SERVICE grant metadata; no administrative writes.

Uses the existing ouf-human-admin device client. Token remains in memory.
IAM polling is finite; owner GET failures stop, never retry a permanent denial.
No Engine, filesystem credentials, signing keys, grants, scope edits or SQL.
"""
import base64
from datetime import datetime, timezone
import re
import stat
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = "https://auth.ouf-lab.it/realms/ouf"
ORIGIN = "https://api.ouf-lab.it"
ADMIN = ORIGIN + "/api/trusted-human/v1/authorization"
SUBJECT = "b93d8cf6-cd14-4ee6-91d7-84cd76c4f500"
CAPABILITY = "ouf.object-storage.content.read"
SERVICE = "ouf-onboarding"
NAMED_GRANT = "grant-managed-file-read-onboarding"


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
        owner = url == ADMIN + "/policies/active"
        require((metadata and form is None and token is None)
                or (iam_post and form is not None and token is None)
                or (owner and form is None and isinstance(token, str) and bool(token)),
                "EXACT_READ_ENDPOINT_REQUIRED")
        kind = "ownerGets" if owner else "iamPosts" if iam_post else "iamGets"
        maximum = {"ownerGets": 1, "iamPosts": 121, "iamGets": 1}[kind]
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
            require(len(raw) <= 2_000_000 and self.counts["bytes"] <= 4_000_000,
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
    emit("Accedi con ouf-admin. Non incollare codice o token in chat. Unica GET della policy attiva; sola diagnostica dei grant SERVICE, nessuna pubblicazione.")
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


def instant(value):
    require(isinstance(value, str) and 0 < len(value) <= 64, "BOUNDED_GRANT_DATE_REQUIRED")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(parsed.tzinfo is not None, "GRANT_TIMEZONE_REQUIRED")
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise Stop("TYPED_GRANT_DATE_REQUIRED") from None


def observe(transport, token, *, wall=time.time):
    status, response = transport.request(ADMIN + "/policies/active", token=token)
    require(status == 200 and isinstance(response, dict) and isinstance(response.get("policy"), dict),
            "ACTIVE_POLICY_REQUIRED")
    policy = response["policy"]
    require(policy.get("bundleId") == "ouf-lab-authorization" and type(policy.get("version")) is int
            and policy["version"] > 0 and response.get("policyRef") == "ouf-lab-authorization:" + str(policy["version"])
            and isinstance(response.get("contentHash"), str)
            and re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", response["contentHash"]), "EXACT_ACTIVE_POLICY_IDENTITY_REQUIRED")
    descriptors, grants = policy.get("capabilities"), policy.get("grants")
    require(type(descriptors) is list and len(descriptors) <= 10000
            and type(grants) is list and len(grants) <= 10000, "BOUNDED_POLICY_REQUIRED")
    seen = set()
    selected = None
    for row in descriptors:
        require(type(row) is dict and isinstance(row.get("capabilityId"), str)
                and row["capabilityId"] not in seen, "UNIQUE_ACTIVE_CAPABILITIES_REQUIRED")
        seen.add(row["capabilityId"])
        if row["capabilityId"] == CAPABILITY:
            require(type(row.get("allowedActors")) is list and len(row["allowedActors"]) <= 8
                    and all(isinstance(v, str) and re.fullmatch(r"[A-Z_]{1,32}", v) for v in row["allowedActors"]),
                    "BOUNDED_CAPABILITY_ACTORS_REQUIRED")
            selected = {"capabilityId": CAPABILITY, "operationIsRead": row.get("operation") == "READ",
                        "serviceActorAllowed": "SERVICE" in row["allowedActors"],
                        "requiredScopeMatchesSource": row.get("requiredScope") == "ouf.internal.object-storage.read"}
    now = wall()
    seen = set()
    matching = []
    named_present = False
    named_matches = False
    for grant in grants:
        require(type(grant) is dict and isinstance(grant.get("grantId"), str)
                and grant["grantId"] not in seen, "UNIQUE_ACTIVE_GRANTS_REQUIRED")
        seen.add(grant["grantId"])
        matches = (grant.get("tenantId") == "ouf-lab" and grant.get("capabilityId") == CAPABILITY
                   and grant.get("servicePrincipalId") == SERVICE)
        if grant["grantId"] == NAMED_GRANT:
            named_present, named_matches = True, matches
        if not matches:
            continue
        require(re.fullmatch(r"[A-Za-z0-9_:.-]{1,128}", grant["grantId"]) and len(matching) < 64,
                "BOUNDED_TARGET_GRANTS_REQUIRED")
        start, end = instant(grant.get("validFrom")), instant(grant.get("validUntil"))
        require(start < end, "FINITE_GRANT_WINDOW_REQUIRED")
        constraints = grant.get("constraints")
        require(constraints is None or type(constraints) is dict, "TYPED_GRANT_CONSTRAINTS_REQUIRED")
        effect = "ALLOW" if constraints is None else constraints.get("effect", "ALLOW")
        require(effect in ("ALLOW", "DENY"), "TYPED_GRANT_EFFECT_REQUIRED")
        matching.append({"grantId": grant["grantId"], "capabilityId": CAPABILITY, "servicePrincipalId": SERVICE,
                         "validFrom": grant["validFrom"], "validUntil": grant["validUntil"],
                         "expired": now >= end, "withinTimeWindow": start <= now < end,
                         "effect": effect, "subjectRestrictionPresent": grant.get("subjectId") is not None,
                         "organizationRestrictionPresent": grant.get("organizationId") is not None,
                         "unconstrained": constraints is None,
                         "constraintsHash": None if constraints is None else fingerprint(constraints)})
    matching.sort(key=lambda row: row["grantId"])
    return {"schema": "ouf.farmacie-service-policy-read.v1", "status": "SERVICE_POLICY_OBSERVED_NO_AUTHORITY",
            "complete": True, "policyRef": response["policyRef"], "policyHash": response["contentHash"],
            "activeResponseHash": fingerprint(response), "observedAt": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "timeBasis": "OPERATOR_HOST_UTC", "capability": selected, "namedSourceGrantPresent": named_present,
            "namedSourceGrantMatchesTarget": named_matches, "matchingServiceGrants": matching,
            "allMatchingWindowsExpired": bool(matching) and all(row["expired"] for row in matching),
            "anyCurrentAllowGrantConfigured": any(row["withinTimeWindow"] and row["effect"] == "ALLOW" for row in matching),
            "effectivePermissionProven": False, "workloadTokenClaimsObserved": False, "currentGatewayRequestIssued": False,
            "counts": dict(transport.counts), "maximums": {"iamGets": 1, "iamPosts": 121, "ownerGets": 1, "bytes": 4000000},
            "policyWrites": 0, "engineRequests": 0, "credentialFileReads": 0, "signingKeyReads": 0,
            "applicationPreviewCalls": 0, "fileContentReads": 0, "profilingRequests": 0, "newJobs": 0,
            "sourceActivations": 0, "acquisitionsExecuted": 0, "sqlSessions": 0, "runtimeAuthorityIssued": False,
            "continuationAuthorized": False, "automaticReplayAllowed": False, "budgetReset": False,
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
            "ONE_ISOLATED_ROOT_POLICY_READER_REQUIRED")
    require(sys.stdin.isatty() and sys.stdout.isatty(), "INTERACTIVE_OPERATOR_TERMINAL_REQUIRED")
    code = Path(__file__).resolve()
    ancestry(code.parent)
    st = code.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o400, "PROTECTED_READER_ROOT400_REQUIRED")
    sys.stdout = Logger(code.parent / "operator.log")
    directory = Path("/etc/ouf/deploy-snapshots/farmacie-service-policy-read-20261027-v1")
    ancestry(directory.parent)
    require(not os.path.lexists(directory), "POLICY_READ_SCOPE_CONSUMED_NO_REPLAY")
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
    print("Una GET policy attiva: grant SERVICE Onboarding minimizzati. Nessuna modifica/grant/Engine/SQL/file applicativo. Nessun APPROVO; solo login HUMAN ouf-admin.", flush=True)
    try:
        token = login(transport)
        result = observe(transport, token)
        del token
    except BaseException:
        save({"state": "STOP_RECONCILE", "counts": dict(transport.counts),
              "automaticReplayAllowed": False, "budgetReset": False})
        raise
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
