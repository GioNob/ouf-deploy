#!/usr/bin/env python3
"""One finite HUMAN read of ACTIVE descriptors; no administrative writes.

Uses the existing ouf-human-admin device client. Token remains in memory.
IAM polling is finite; owner GET failures stop, never retry a permanent denial.
No Engine, filesystem credentials, signing keys, grants, scope edits or SQL.
"""
import base64
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
CAPS = ("ingestion.run.read", "ingestion.contract.read", "ingestion.lineage.read",
        "urban.object.read", "lineage.object.read", "lineage.property.read")


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
    emit("Accedi con ouf-admin. Non incollare codice o token in chat. Sola lettura dei descrittori.")
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


def observe(transport, token):
    status, before = transport.request(ADMIN + "/policies/active", token=token)
    require(status == 200 and isinstance(before, dict) and isinstance(before.get("policy"), dict)
            and isinstance(before.get("policyRef"), str) and isinstance(before.get("contentHash"), str),
            "ACTIVE_POLICY_REQUIRED")
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
    require(status == 200 and before == after, "ACTIVE_CHANGED_RECONCILE")
    projected = []
    for cap in CAPS:
        owner = "ingestion" if cap.startswith("ingestion.") else "udp"
        expected = {"capabilityId": cap, "operation": "READ", "requiredScope": cap, "allowedActors": ["HUMAN"]}
        descriptor = active.get(cap)
        reg = registered.get(cap)
        # Print exact target descriptor fields, never grants or unrelated catalogue content.
        def minimized(d):
            return None if d is None else {k: d.get(k) for k in expected}
        projected.append({"capabilityId": cap, "expectedOwnerRef": owner,
                          "activeDescriptor": minimized(descriptor),
                          "activeHumanCompatible": isinstance(descriptor, dict)
                          and isinstance(descriptor.get("allowedActors"), list)
                          and "HUMAN" in descriptor["allowedActors"],
                          "registeredOwnerRef": reg["ownerRef"] if reg else None,
                          "registeredDescriptor": minimized(reg["descriptor"]) if reg else None})
    return {"schema": "ouf.acquisition-permission-descriptor-read.v1", "status": "DESCRIPTORS_OBSERVED_NO_AUTHORITY",
            "complete": True, "policyRef": before["policyRef"], "policyHash": before["contentHash"],
            "activeResponseHash": fingerprint(before), "descriptors": projected,
            "counts": dict(transport.counts), "administrativeWrites": 0, "engineRequests": 0,
            "newCredentialFileReads": 0, "sourceActivations": 0, "acquisitionsExecuted": 0,
            "runtimeAuthorityIssued": False, "budgetReset": False, "automaticReplayAllowed": False,
            "applicationE2EProven": False, "releaseAcceptance": False}


def main():
    require(len(sys.argv) == 1 and sys.stdin.isatty(), "INTERACTIVE_OPERATOR_TERMINAL_REQUIRED")
    require(os.geteuid() != 0, "RUN_AS_OPERATOR_NOT_ROOT")
    # New diagnostic only: never read or reopen an old installation/login scope.
    # The fixed claim is consumed even on denial/crash; do not remove to rerun.
    directory = Path("/home/oufadmin/ouf-acquisition-permission-descriptor-read-20261025")
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        raise Stop("DIAGNOSTIC_SCOPE_EXISTS_RECONCILE_NO_REPLAY") from None
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    print("Directory=" + str(directory), flush=True)

    def save(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        temporary = directory / "state.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, directory / "state.json")
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except BaseException:
            # No cleanup/replay after an ambiguous persistence error.
            raise

    save({"state": "CLAIMED", "automaticReplayAllowed": False, "budgetReset": False})
    transport = Transport(reserve=lambda counts: save({"state": "READING", "counts": counts,
                          "automaticReplayAllowed": False, "budgetReset": False}))
    try:
        token = login(transport)
        result = observe(transport, token)
    except BaseException:
        save({"state": "STOP_RECONCILE", "counts": dict(transport.counts),
              "automaticReplayAllowed": False, "budgetReset": False})
        raise
    save(result)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Stop as exc:
        print(json.dumps({"status": "STOP_RECONCILE", "reasonCode": str(exc),
                          "automaticReplayAllowed": False, "runtimeAuthorityIssued": False,
                          "applicationE2EProven": False, "releaseAcceptance": False}))
        sys.exit(2)
    except Exception:
        print('{"status":"STOP_RECONCILE","reasonCode":"PRIVATE_DETAILS_REDACTED","automaticReplayAllowed":false}')
        sys.exit(2)
