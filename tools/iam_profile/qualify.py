"""Read-only qualification after human apply. Only introspection and mandate status on wire."""
import http.client
import json
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from .profile import Invalid, canonical, digest, exact, require, validate


def qualify(profile, bindings, probe, *, begin_revocation, clock=time.monotonic, sleep=time.sleep):
    """Use the same checks for a disposable fixture and for the two provisioned assignments."""
    validate(profile, bindings)
    ttl = profile["grant"]["revocationTtlSeconds"]["value"]
    identities = {}
    for role in ("A", "B"):
        claims = probe.introspect(role)
        aud = claims.get("aud")
        if isinstance(aud, str):
            aud = [aud]
        require(claims.get("active") is True and claims.get("iss") == profile["trust"]["issuer"]
                and type(aud) is list and profile["trust"]["gatewayAudience"] in aud
                and claims.get("client_id") == profile["clients"]["mcp"]["clientId"]
                and claims.get("ouf_actor_type") == "SERVICE" and claims.get("sub")
                and claims.get("tenant_id") and type(claims.get("exp")) is int
                and claims["exp"] > probe.epoch() + ttl
                and bindings["scopeByAction"]["status"] in claims.get("scope", "").split(),
                "PET_WORKLOAD_INVALID")
        identities[role] = claims
    targets = probe.targets
    require(targets["A"]["human"] != targets["B"]["human"]
            and targets["A"]["grantRef"] != targets["B"]["grantRef"]
            and targets["A"]["mandateId"] != targets["B"]["mandateId"]
            and identities["A"]["tenant_id"] == identities["B"]["tenant_id"],
            "PET_ASSIGNMENTS_INVALID")
    for role in ("A", "B"):
        status, body = probe.status(role, role)
        require(status == 200 and body.get("mandateId") == targets[role]["mandateId"]
                and body.get("generation") == targets[role]["generation"]
                and body.get("state") == "ACTIVE" and body.get("decisionRef"), "PET_STATUS_FAILED")
    status, body = probe.status("A", "B")
    require(status == 404 and probe.error_code(body) == "ANALYSIS_MANDATE_UNKNOWN",
            "PET_ISOLATION_FAILED")
    # A real dispatch could have effects. Consume the observed 55h admission and owner count.
    probe.verify_denied_forward(profile, identities["A"])
    start = begin_revocation()
    require(identities["A"]["exp"] > probe.epoch() + ttl, "PET_REVOCATION_INCONCLUSIVE")
    deadline = start + ttl
    # Respect the installation's IAM rate; only an actual inactive observation counts.
    spacing = 60 / profile["iam"]["introspectionsPerMinute"]["value"]
    while clock() < deadline:
        inactive = probe.introspect("A").get("active") is False
        if inactive and clock() <= deadline:
            break
        sleep(min(spacing, max(0, deadline - clock())))
    else:
        raise Invalid("PET_REVOCATION_TIMEOUT")
    require(identities["A"]["exp"] > probe.epoch()
            and probe.introspect("B").get("active") is True, "PET_REVOCATION_INCONCLUSIVE")
    return {"IAM-55M-01": "PASS", "IAM-55M-02": "PASS"}


class LiveProbe:
    """TLS is destination-specific. No redirect, token acquisition, admin or dispatch method."""
    epoch = staticmethod(time.time)

    def __init__(self, profile, config):
        self.profile = profile
        exact(config, ("tls", "targets", "deniedForward", "timeoutSeconds"), "PET_CONFIG_INVALID")
        exact(config["tls"], ("introspection", "status"), "PET_CONFIG_INVALID")
        exact(config["targets"], ("A", "B"), "PET_CONFIG_INVALID")
        self.targets = config["targets"]
        for entry in self.targets.values():
            exact(entry, ("human", "grantRef", "mandateId", "generation", "tokenFile"),
                  "PET_CONFIG_INVALID")
            require(all(type(val) is str and val for val in entry.values())
                    and str(UUID(entry["mandateId"])) == entry["mandateId"]
                    and entry["generation"].isascii() and entry["generation"].isdigit(),
                    "PET_CONFIG_INVALID")
        self.config = config
        require(type(config["timeoutSeconds"]) is int and 1 <= config["timeoutSeconds"] <= 30,
                "PET_CONFIG_INVALID")
        self.contexts = {}
        for dest, settings in config["tls"].items():
            exact(settings, ("caFile", "certFile", "keyFile"), "PET_CONFIG_INVALID")
            ctx = ssl.create_default_context(cafile=settings["caFile"])
            ctx.load_cert_chain(settings["certFile"], settings["keyFile"])
            self.contexts[dest] = ctx
        # Freeze each pre-provisioned credential across all reads, including revocation.
        self.tokens = {k: Path(t["tokenFile"]).read_text(encoding="ascii").strip()
                       for k, t in self.targets.items()}
        require(all(self.tokens.values()) and self.tokens["A"] != self.tokens["B"],
                "PET_ASSIGNMENTS_INVALID")

    def post(self, dest, url, headers, payload):
        endpoint = urlsplit(url)
        conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port,
                                           context=self.contexts[dest],
                                           timeout=self.config["timeoutSeconds"])
        try:
            conn.request("POST", endpoint.path or "/", payload, headers)
            response = conn.getresponse()
            body = json.loads(response.read())
            require(type(body) is dict, "PET_RESPONSE_INVALID")
            return response.status, body
        finally:
            conn.close()

    def introspect(self, role):
        status, claims = self.post("introspection", self.profile["trust"]["introspection"],
                                   {"Content-Type": "application/x-www-form-urlencoded"},
                                   urlencode({"token": self.tokens[role]}))
        require(status == 200, "PET_INTROSPECTION_FAILED")
        return claims

    def status(self, role, target):
        path = self.profile["trust"]["gatewayOrigin"].rstrip("/") + "/internal/analysis/v1/mandates/status"
        payload = {key: self.targets[target][key] for key in ("mandateId", "generation")}
        return self.post("status", path, {"Authorization": "Bearer " + self.tokens[role],
                                         "Content-Type": "application/json"}, canonical(payload))

    @staticmethod
    def error_code(body):
        return body.get("code")

    def verify_denied_forward(self, profile, identity):
        from .plan import sha
        proof = self.config["deniedForward"]
        expected = {"pet": "55h", "profileSha256": digest(profile), "action": "dispatch",
                    "issuer": identity["iss"], "workload": identity["client_id"],
                    "workloadSubject": identity["sub"], "tenant": identity["tenant_id"],
                    "credentialGrantRef": self.targets["A"]["grantRef"],
                    "credentialHuman": self.targets["A"]["human"],
                    "originMandateId": self.targets["A"]["mandateId"],
                    "targetGrantRef": self.targets["B"]["grantRef"],
                    "holder": self.targets["B"]["human"], "mandateId": self.targets["B"]["mandateId"],
                    "generation": self.targets["B"]["generation"], "decision": "DENIED",
                    "ownerForwards": 0}
        exact(proof, (*expected, "sourceTraceSha256", "traceSha256"), "PET_FORWARD_UNPROVEN")
        require(sha(proof["sourceTraceSha256"]) and type(proof["ownerForwards"]) is int
                and proof["traceSha256"] == digest({k: v for k, v in proof.items() if k != "traceSha256"})
                and all(proof[key] == value for key, value in expected.items()),
                "PET_FORWARD_UNPROVEN")


def operator_signal():
    print("Pronti. Premere Invio immediatamente prima della revoca umana dell'incarico A.",
          file=sys.stderr, flush=True)
    input()
    return time.monotonic()

