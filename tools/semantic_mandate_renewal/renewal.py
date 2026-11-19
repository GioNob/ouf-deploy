"""Automatic authority mandate renewal job (sprint-01 task-28; D-018, D-028, D-030).

Subcommands:
  run             daily job: D-018 preconditions, T-30/90 renewal of the B1/B2 and
                  base ledgers, versioned base, closed status, local incident.
  install         governed installation (plan, then apply with the plan hash).
  incident-close  governed closure of the open incident (plan, then apply).

The mandates module is compiled from its verified bytes, never imported by path.
No private-key reads, no signing, no network. Every rejection is a public code.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types


CONFIG_SCHEMA = "ouf.semantic-mandate-renewal.v1"
STATUS_SCHEMA = "ouf.semantic-mandate-renewal-status.v1"
INSTALL_PLAN_SCHEMA = "ouf.semantic-mandate-renewal-install-plan.v1"
CLOSE_PLAN_SCHEMA = "ouf.semantic-mandate-renewal-incident-close-plan.v1"
PROFILE_SCHEMA = "ouf.semantic-existing-installation-authority-bindings.v1"
WINDOW_SECONDS = 7776000      # 90 days (D-028)
RENEW_BEFORE_SECONDS = 2592000  # T-30 days (D-028)
ISSUER_REF = "ouf-authority-mandate-renewal-job"
CONFIG_FIELDS = {"schema", "renewalSource", "mandatesModule", "installationRef", "entityRef", "issuerRef",
                 "authorityProfile", "b1b2", "base", "stateRoot", "windowSeconds", "renewBeforeSeconds"}
PROFILE_FIELDS = {"schema", "sourceCommit", "sourceRoot", "sourceHashes", "authorities", "keyRefs",
                  "keyBindings", "policyBinding", "custodyReceiptBinding"}
TEMPORARY = re.compile(r"[.]tmp-[1-9][0-9]{0,8}-[0-9a-f]{32}")
GENERATION = re.compile(r"([1-9][0-9]{0,8})[.]json")
PUBLIC_CODE = re.compile(r"[A-Z0-9_]{1,80}")
LAYOUT = {
    "codeRoot": "/etc/ouf/authority-mandate-renewal",
    "ledgerParent": "/var/lib/ouf-authority-mandates",
    "stateRoot": "/var/lib/ouf-authority-mandate-renewal",
    "unitDirectory": "/etc/systemd/system",
    "python": "/usr/bin/python3.13",
}
SERVICE = "ouf-authority-mandate-renewal.service"
TIMER = "ouf-authority-mandate-renewal.timer"


class Blocked(Exception):
    """Public reason code only."""


def require(condition, code):
    if not condition:
        raise Blocked(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw, code):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, code)
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked(code) from None
    require(type(value) is dict, code)
    return value


def hashed(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def identity(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None


def absolute(value, code="EXPLICIT_RENEWAL_PATH_REQUIRED"):
    require(type(value) is str, code)
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and str(path) == value, code)
    return path


def binding(value, code="EXACT_RENEWAL_BINDING_REQUIRED"):
    require(type(value) is dict and set(value) == {"path", "sha256"} and hashed(value["sha256"]), code)
    absolute(value["path"], code)
    return value


def trusted_ancestors(path, code):
    for parent in Path(path).parents:
        try:
            info = parent.lstat()
        except OSError:
            raise Blocked(code) from None
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, code)


def read_file(path, code, limit=2097152, private=True):
    """Root-owned regular file, single link, O_NOFOLLOW; 0600 when private, else not g/o-writable."""
    path = absolute(str(path), code)
    trusted_ancestors(path, code)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Blocked(code) from None
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and (mode == 0o600 if private else not mode & 0o022) and 0 < info.st_size <= limit, code)
        raw = os.read(fd, limit + 1)
        require(len(raw) == info.st_size, code)
        return raw
    except OSError:
        raise Blocked(code) from None
    finally:
        os.close(fd)


def private_directory(path, code):
    path = absolute(str(path), code)
    trusted_ancestors(path, code)
    try:
        info = path.lstat()
    except OSError:
        raise Blocked(code) from None
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, code)
    return path


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, raw, mode=0o600):
    """O_EXCL create, fsync, directory fsync; never replaces an existing entry."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        raise Blocked("RENEWAL_TARGET_EXISTS") from None
    except OSError:
        raise Blocked("RENEWAL_WRITE_FAILED") from None
    try:
        os.fchmod(fd, mode)
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_directory(Path(path).parent)


def publish_linked(root, name, number, raw):
    """Temporary O_EXCL + exclusive os.link + readback, as the mandate ledger does."""
    final = Path(root) / name
    temporary = Path(root) / (".tmp-" + str(number) + "-" + secrets.token_hex(16))
    write_exclusive(temporary, raw)
    try:
        try:
            os.link(temporary, final, follow_symlinks=False)
        except FileExistsError:
            raise Blocked("VERSIONED_BASE_DRIFT") from None
        except OSError:
            raise Blocked("RENEWAL_WRITE_FAILED") from None
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    fsync_directory(root)
    require(read_file(final, "VERSIONED_BASE_DRIFT", 65536) == raw, "VERSIONED_BASE_DRIFT")


def load_mandates(module_binding, code="MANDATES_MODULE_DRIFT"):
    """Compile the checked bytes; never reopen the path through an import loader."""
    binding(module_binding, code)
    path = Path(module_binding["path"])
    source = read_file(path, code, 1048576)
    require(sha(source) == module_binding["sha256"], code)
    module = types.ModuleType("ouf_bound_authority_mandates_renewal")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


# --- configuration ------------------------------------------------------------

def configuration(raw):
    value = decode(raw, "EXACT_RENEWAL_CONFIGURATION_REQUIRED")
    code = "EXACT_RENEWAL_CONFIGURATION_REQUIRED"
    require(set(value) == CONFIG_FIELDS and value["schema"] == CONFIG_SCHEMA
            and identity(value["installationRef"]) and identity(value["entityRef"])
            and identity(value["issuerRef"])
            and type(value["windowSeconds"]) is int and value["windowSeconds"] == WINDOW_SECONDS
            and type(value["renewBeforeSeconds"]) is int and value["renewBeforeSeconds"] == RENEW_BEFORE_SECONDS, code)
    for key in ("renewalSource", "mandatesModule", "authorityProfile"):
        binding(value[key], code)
    absolute(value["stateRoot"], code)
    b1b2, base = value["b1b2"], value["base"]
    require(type(b1b2) is dict and set(b1b2) == {"anchor", "ledgerRoot", "keyRefs"}
            and type(base) is dict and set(base) == {"anchor", "ledgerRoot", "versionedRoot", "keyRefs"}, code)
    for section, maximum in ((b1b2, 8), (base, 32)):
        binding(section["anchor"], code)
        absolute(section["ledgerRoot"], code)
        refs = section["keyRefs"]
        require(type(refs) is list and 1 <= len(refs) <= maximum and all(identity(ref) for ref in refs)
                and len(set(refs)) == len(refs), code)
    absolute(base["versionedRoot"], code)
    roots = [b1b2["ledgerRoot"], base["ledgerRoot"], base["versionedRoot"], value["stateRoot"]]
    require(len(set(roots)) == len(roots), code)
    return value


def read_anchor(mandates, anchor_binding, installation, entity, code):
    raw = read_file(anchor_binding["path"], code, 65536)
    require(sha(raw) == anchor_binding["sha256"], code)
    try:
        return mandates.anchor(raw, installation, entity)
    except mandates.MandateDenied:
        raise Blocked(code) from None


def coherence(mandates, cfg_like):
    """A.3: anchors, profile and keyRefs agree. Returns (b1b2 anchor, base anchor, profile, profile raw)."""
    installation, entity = cfg_like["installationRef"], cfg_like["entityRef"]
    code = "AUTHORITY_COHERENCE_UNPROVEN"
    b1b2 = read_anchor(mandates, cfg_like["b1b2"]["anchor"], installation, entity, code)
    base = read_anchor(mandates, cfg_like["base"]["anchor"], installation, entity, code)
    require(b1b2["schema"] == mandates.B1B2_ANCHOR_SCHEMA and base["schema"] == mandates.BASE_ANCHOR_SCHEMA, code)
    require(b1b2["authorityProfile"] == cfg_like["authorityProfile"]
            and b1b2["basePolicy"] == cfg_like["base"]["anchor"], code)
    profile_raw = read_file(cfg_like["authorityProfile"]["path"], "PRECONDITION_CUSTODY_INTACT_UNMET", private=False)
    require(sha(profile_raw) == cfg_like["authorityProfile"]["sha256"], "PRECONDITION_CUSTODY_INTACT_UNMET")
    profile = decode(profile_raw, "PRECONDITION_CUSTODY_INTACT_UNMET")
    require(set(profile) == PROFILE_FIELDS and profile["schema"] == PROFILE_SCHEMA, "PRECONDITION_CUSTODY_INTACT_UNMET")
    binding(profile["custodyReceiptBinding"], "PRECONDITION_CUSTODY_INTACT_UNMET")
    keys = profile["keyBindings"]
    # Syntax only: never open, stat or resolve a private-key path.
    require(type(keys) is dict and set(keys) == {"installer", "attestor"}
            and all(type(item) is dict and set(item) == {"path", "sha256"} and hashed(item["sha256"])
                    and type(item["path"]) is str for item in keys.values()), "PRECONDITION_CUSTODY_INTACT_UNMET")
    require(profile["policyBinding"] == cfg_like["base"]["anchor"], code)
    refs = profile["keyRefs"]
    require(type(refs) is dict and set(refs) == {"installer", "attestor"}
            and sorted(cfg_like["base"]["keyRefs"]) == sorted([refs["installer"], refs["attestor"]]), code)
    base_keys = {key["keyRef"]: key for key in base["keys"]}
    b1b2_keys = {key["keyRef"]: key for key in b1b2["keys"]}
    require(refs["installer"] in base_keys and refs["attestor"] in base_keys, code)
    installer_public = base_keys[refs["installer"]]["publicKey"]
    require(all(ref in b1b2_keys and b1b2_keys[ref]["publicKey"] == installer_public
                for ref in cfg_like["b1b2"]["keyRefs"]), code)
    return b1b2, base, profile, profile_raw


def custody(profile):
    """D-018 custodyIntact: the profile's custody receipt matches its pin."""
    receipt = profile["custodyReceiptBinding"]
    raw = read_file(receipt["path"], "PRECONDITION_CUSTODY_INTACT_UNMET", private=False)
    require(sha(raw) == receipt["sha256"], "PRECONDITION_CUSTODY_INTACT_UNMET")
    return sha(raw)


# --- run ----------------------------------------------------------------------

def versioned_base(mandates, ledger, anchored, key_refs, number):
    """Anchor base with configured keys' window/state at generation `number`; canonical."""
    records = ledger.view()["records"][:number]
    value = json.loads(canonical(anchored))
    for key in value["keys"]:
        if key["keyRef"] in key_refs:
            effective = ledger.effective(key["keyRef"], records)
            key.update(notBefore=effective["notBefore"], expiresAt=effective["expiresAt"], state=effective["state"])
    raw = canonical(value)
    mandates.base_anchor(raw, value["installationRef"], value["entityRef"])
    return raw


def versioned_inventory(root, generations):
    private_directory(root, "PRIVATE_VERSIONED_BASE_ROOT_REQUIRED")
    present = {}
    try:
        names = os.listdir(root)
    except OSError:
        raise Blocked("PRIVATE_VERSIONED_BASE_ROOT_REQUIRED") from None
    for name in names:
        match = GENERATION.fullmatch(name)
        if match is None:
            require(TEMPORARY.fullmatch(name) is None, "VERSIONED_BASE_TEMPORARY_ENTRY_PRESENT")
            raise Blocked("UNKNOWN_VERSIONED_BASE_ENTRY")
        number = int(match[1])
        require(number <= generations, "VERSIONED_BASE_DRIFT")
        present[number] = read_file(Path(root) / name, "VERSIONED_BASE_DRIFT", 65536)
    return present


def zero_ledger():
    return {"generation": 0, "headSha256": None, "earliestExpiresAt": 0}


class Job:
    def __init__(self, configuration_path, configuration_sha256, clock=time.time, source_path=None):
        self.path = absolute(str(configuration_path), "EXACT_RENEWAL_CONFIGURATION_REQUIRED")
        require(hashed(configuration_sha256), "EXACT_RENEWAL_CONFIGURATION_REQUIRED")
        self.raw = read_file(self.path, "EXACT_RENEWAL_CONFIGURATION_REQUIRED", 65536)
        require(sha(self.raw) == configuration_sha256, "RENEWAL_CONFIGURATION_DRIFT")
        self.cfg = configuration(self.raw)
        source = read_file(Path(source_path or __file__).absolute(), "RENEWAL_SOURCE_DRIFT", 1048576)
        require(sha(source) == self.cfg["renewalSource"]["sha256"], "RENEWAL_SOURCE_DRIFT")
        self.mandates = load_mandates(self.cfg["mandatesModule"])
        self.clock = clock
        self.state_root = private_directory(self.cfg["stateRoot"], "PRIVATE_RENEWAL_STATE_ROOT_REQUIRED")

    def ledger(self, section):
        return self.mandates.MandateLedger(section["anchor"], section["ledgerRoot"], self.cfg["installationRef"],
                                           self.cfg["entityRef"], self.clock)

    def incident(self):
        directory = self.state_root / "incidents"
        path = directory / "open.json"
        if not os.path.lexists(path):
            return None
        value = decode(read_file(path, "RENEWAL_INCIDENT_UNREADABLE", 4096), "RENEWAL_INCIDENT_UNREADABLE")
        require(set(value) == {"reasonCode", "firstSeenAt", "evidenceSha256"}
                and type(value["reasonCode"]) is str and PUBLIC_CODE.fullmatch(value["reasonCode"])
                and type(value["firstSeenAt"]) is int
                and (value["evidenceSha256"] is None or hashed(value["evidenceSha256"])), "RENEWAL_INCIDENT_UNREADABLE")
        return value

    def open_incident(self, code, now, evidence):
        directory = self.state_root / "incidents"
        if not os.path.lexists(directory):
            os.mkdir(directory, 0o700)
        private_directory(directory, "PRIVATE_RENEWAL_STATE_ROOT_REQUIRED")
        try:
            write_exclusive(directory / "open.json",
                            canonical({"reasonCode": code, "firstSeenAt": int(now), "evidenceSha256": evidence}))
        except Blocked:
            pass  # an incident already open keeps its first code

    def publish_status(self, value):
        raw = canonical(value)
        temporary = self.state_root / (".status-" + secrets.token_hex(16))
        write_exclusive(temporary, raw)
        try:
            os.replace(temporary, self.state_root / "status.json")
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
        fsync_directory(self.state_root)

    def save_evidence(self, evidence):
        directory = self.state_root / "evidence"
        if not os.path.lexists(directory):
            os.mkdir(directory, 0o700)
        private_directory(directory, "PRIVATE_RENEWAL_STATE_ROOT_REQUIRED")
        raw = canonical(evidence)
        path = directory / (sha(raw) + ".json")
        if os.path.lexists(path):
            require(read_file(path, "RENEWAL_EVIDENCE_DRIFT", 65536) == raw, "RENEWAL_EVIDENCE_DRIFT")
        else:
            write_exclusive(path, raw)
        return sha(raw)

    def evaluate(self, now, info):
        """Read-only: coherence, D-018 preconditions, per-ledger decisions. Fills `info`."""
        cfg, M = self.cfg, self.mandates
        _, base_anchor, profile, profile_raw = coherence(M, cfg)
        receipt = custody(profile)
        ledgers, plans = {}, {}
        for name in ("b1b2", "base"):
            section = cfg[name]
            ledger = self.ledger(section)
            try:
                ledger.refresh(now)
            except M.MandateDenied as error:
                raise Blocked(str(error)) from None
            ledgers[name] = ledger
            snapshot = ledger.snapshot()
            effective = [ledger.effective(ref, ledger.view()["records"]) for ref in section["keyRefs"]]
            info[name] = {"generation": snapshot["generations"], "headSha256": snapshot["headSha256"],
                          "earliestExpiresAt": min(item["expiresAt"] for item in effective)}
            require(not any(ledger.ever_revoked(ref) for ref in section["keyRefs"]),
                    "PRECONDITION_KEY_NOT_REVOKED_UNMET")
            require(all(now < item["expiresAt"] for item in effective), "MANDATE_EXPIRED_WITHOUT_RENEWAL")
            if all(item["expiresAt"] - now > RENEW_BEFORE_SECONDS for item in effective):
                plans[name] = None
            else:
                plans[name] = []
                for item in effective:
                    start = max(int(now), item["notBefore"])
                    plans[name].append({"keyRef": item["keyRef"], "notBefore": start,
                                        "expiresAt": start + WINDOW_SECONDS, "state": "ACTIVE"})
        present = versioned_inventory(cfg["base"]["versionedRoot"], info["base"]["generation"])
        for number, raw in present.items():
            require(raw == versioned_base(M, ledgers["base"], base_anchor, cfg["base"]["keyRefs"], number),
                    "VERSIONED_BASE_DRIFT")
        evidence = {"schema": "ouf.semantic-mandate-renewal-evidence.v1", "now": int(now),
                    "anchors": {"b1b2": cfg["b1b2"]["anchor"]["sha256"], "base": cfg["base"]["anchor"]["sha256"]},
                    "authorityProfileSha256": sha(profile_raw), "custodyReceiptSha256": receipt,
                    "ledgers": {name: ledgers[name].snapshot() for name in ledgers}}
        return {"ledgers": ledgers, "plans": plans, "present": present, "baseAnchor": base_anchor,
                "evidence": evidence}

    def apply(self, context, now):
        cfg, M = self.cfg, self.mandates
        wrote = False
        if any(plan is not None for plan in context["plans"].values()):
            evidence = self.save_evidence(context["evidence"])
            flags = {"keyNotRevoked": True, "custodyIntact": True, "noOpenSecurityIncident": True}
            for name in ("b1b2", "base"):
                plan = context["plans"][name]
                if plan is None:
                    continue
                section = cfg[name]
                try:
                    M.write_generation(section["ledgerRoot"], section["anchor"], cfg["installationRef"],
                                       cfg["entityRef"], plan, flags, cfg["issuerRef"], evidence, lambda: now)
                except M.MandateDenied as error:
                    raise Blocked(str(error)) from None
                wrote = True
        base = context["ledgers"]["base"]
        try:
            base.refresh(now)
        except M.MandateDenied as error:
            raise Blocked(str(error)) from None
        for number in range(1, base.snapshot()["generations"] + 1):
            raw = versioned_base(M, base, context["baseAnchor"], cfg["base"]["keyRefs"], number)
            if number in context["present"]:
                continue
            publish_linked(cfg["base"]["versionedRoot"], str(number) + ".json", number, raw)
        return wrote

    def summary(self, context, info):
        for name, ledger in context["ledgers"].items():
            ledger.refresh(int(self.clock()))
            snapshot = ledger.snapshot()
            refs = self.cfg[name]["keyRefs"]
            info[name] = {"generation": snapshot["generations"], "headSha256": snapshot["headSha256"],
                          "earliestExpiresAt": min(ledger.effective(ref, ledger.view()["records"])["expiresAt"]
                                                   for ref in refs)}
        generations = info["base"]["generation"]
        if generations == 0:
            return None
        raw = read_file(Path(self.cfg["base"]["versionedRoot"]) / (str(generations) + ".json"),
                        "VERSIONED_BASE_DRIFT", 65536)
        return {"generation": generations, "sha256": sha(raw)}

    def run(self, dry_run=False):
        lock = os.open(self.state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked("RENEWAL_ALREADY_RUNNING") from None
            now = int(self.clock())
            info = {"b1b2": zero_ledger(), "base": zero_ledger()}
            outcome, reason, versioned, would = "NOOP", None, None, False
            incident = None
            try:
                incident = self.incident()
                context = self.evaluate(now, info)
                require(incident is None, "OPEN_INCIDENT_PRESENT")
                would = any(plan is not None for plan in context["plans"].values())
                if not dry_run and self.apply(context, now):
                    outcome = "RENEWED"
                versioned = self.summary(context, info)
            except Blocked as error:
                outcome, reason = "BLOCKED", str(error)
            except self.mandates.MandateDenied as error:
                outcome, reason = "BLOCKED", str(error)
            if outcome == "BLOCKED":
                if incident is not None:
                    reason = incident["reasonCode"]  # the first cause stays visible (D-030)
                elif not dry_run:
                    self.open_incident(reason, now, None)
            open_now = os.path.lexists(self.state_root / "incidents" / "open.json")
            self.publish_status({"schema": STATUS_SCHEMA, "checkedAt": now, "outcome": outcome, "reasonCode": reason,
                                 "ledgers": info, "versionedBase": versioned, "openIncident": open_now})
            return outcome, reason, would
        finally:
            os.close(lock)


# --- governed installation ----------------------------------------------------

def unit_files(layout, configuration_sha256):
    code = layout["codeRoot"]
    writable = " ".join([layout["ledgerParent"], layout["stateRoot"]])
    service = (
        "[Unit]\n"
        "Description=OUF authority mandate renewal (D-018, D-028, D-030)\n"
        "After=local-fs.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "User=root\n"
        "Group=root\n"
        "UMask=0077\n"
        "ExecStart=" + layout["python"] + " -I -B " + code + "/renewal.py run --configuration " + code
        + "/configuration.json --configuration-sha256 " + configuration_sha256 + "\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
        "PrivateNetwork=true\n"
        "ProtectHome=true\n"
        "ProtectSystem=strict\n"
        "ReadOnlyPaths=" + code + "\n"
        "ReadWritePaths=" + writable + "\n"
    ).encode()
    timer = (
        "[Unit]\n"
        "Description=Daily OUF authority mandate renewal\n\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "RandomizedDelaySec=1h\n"
        "Persistent=true\n"
        "Unit=" + SERVICE + "\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    ).encode()
    return {SERVICE: service, TIMER: timer}


def install_plan(args, layout, own_source):
    source_dir = absolute(args.source_dir, "EXPLICIT_RENEWAL_SOURCE_REQUIRED")
    renewal_raw = read_file(source_dir / "tools/semantic_mandate_renewal/renewal.py", "RENEWAL_SOURCE_DRIFT", 1048576)
    require(renewal_raw == own_source, "RENEWAL_SOURCE_DRIFT")
    mandates_path = source_dir / "tools/semantic_authority_mandates/mandates.py"
    mandates_raw = read_file(mandates_path, "MANDATES_MODULE_DRIFT", 1048576)
    mandates = load_mandates({"path": str(mandates_path), "sha256": sha(mandates_raw)})
    for value in (args.installation_ref, args.entity_ref):
        require(identity(value), "EXACT_RENEWAL_CONFIGURATION_REQUIRED")
    b1b2_binding = binding({"path": args.b1b2_anchor, "sha256": args.b1b2_anchor_sha256})
    base_binding = binding({"path": args.base_anchor, "sha256": args.base_anchor_sha256})
    profile_binding = binding({"path": args.authority_profile, "sha256": args.authority_profile_sha256})
    b1b2 = read_anchor(mandates, b1b2_binding, args.installation_ref, args.entity_ref, "AUTHORITY_COHERENCE_UNPROVEN")
    profile = decode(read_file(profile_binding["path"], "PRECONDITION_CUSTODY_INTACT_UNMET", private=False),
                     "PRECONDITION_CUSTODY_INTACT_UNMET")
    refs = profile.get("keyRefs")
    require(type(refs) is dict and set(refs) == {"installer", "attestor"}, "AUTHORITY_COHERENCE_UNPROVEN")
    base = read_anchor(mandates, base_binding, args.installation_ref, args.entity_ref, "AUTHORITY_COHERENCE_UNPROVEN")
    installer = [key for key in base["keys"] if key["keyRef"] == refs["installer"]]
    require(len(installer) == 1, "AUTHORITY_COHERENCE_UNPROVEN")
    b1b2_refs = sorted(key["keyRef"] for key in b1b2["keys"] if key["publicKey"] == installer[0]["publicKey"])
    code, parent = layout["codeRoot"], layout["ledgerParent"]
    cfg = {"schema": CONFIG_SCHEMA,
           "renewalSource": {"path": code + "/renewal.py", "sha256": sha(renewal_raw)},
           "mandatesModule": {"path": code + "/mandates.py", "sha256": sha(mandates_raw)},
           "installationRef": args.installation_ref, "entityRef": args.entity_ref, "issuerRef": ISSUER_REF,
           "authorityProfile": profile_binding,
           "b1b2": {"anchor": b1b2_binding, "ledgerRoot": parent + "/b1b2", "keyRefs": b1b2_refs},
           "base": {"anchor": base_binding, "ledgerRoot": parent + "/base", "versionedRoot": parent + "/base-versioned",
                    "keyRefs": sorted([refs["installer"], refs["attestor"]])},
           "stateRoot": layout["stateRoot"], "windowSeconds": WINDOW_SECONDS,
           "renewBeforeSeconds": RENEW_BEFORE_SECONDS}
    cfg_raw = canonical(cfg)
    configuration(cfg_raw)
    _, _, checked_profile, _ = coherence(mandates, cfg)
    custody(checked_profile)
    for section in (cfg["b1b2"], cfg["base"]):
        anchored = read_anchor(mandates, section["anchor"], args.installation_ref, args.entity_ref,
                               "AUTHORITY_COHERENCE_UNPROVEN")
        keys = {key["keyRef"]: key for key in anchored["keys"]}
        require(all(keys[ref]["state"] == "ACTIVE" for ref in section["keyRefs"]), "PRECONDITION_KEY_NOT_REVOKED_UNMET")
    units = unit_files(layout, sha(cfg_raw))
    files = {code + "/renewal.py": renewal_raw, code + "/mandates.py": mandates_raw,
             code + "/configuration.json": cfg_raw}
    files.update({layout["unitDirectory"] + "/" + name: raw for name, raw in units.items()})
    directories = [code, parent, cfg["b1b2"]["ledgerRoot"], cfg["base"]["ledgerRoot"], cfg["base"]["versionedRoot"],
                   layout["stateRoot"]]
    for path in [*directories, *[p for p in files if not p.startswith(layout["unitDirectory"] + "/")],
                 *[layout["unitDirectory"] + "/" + name for name in units]]:
        require(not os.path.lexists(path), "INSTALL_TARGET_EXISTS")
    for target in (code, parent, layout["stateRoot"], layout["unitDirectory"] + "/" + SERVICE):
        trusted_ancestors(Path(target), "TRUSTED_INSTALL_PARENT_REQUIRED")
    plan = {"schema": INSTALL_PLAN_SCHEMA, "configurationSha256": sha(cfg_raw), "directories": directories,
            "files": {path: sha(raw) for path, raw in sorted(files.items())},
            "keyRefs": {"b1b2": cfg["b1b2"]["keyRefs"], "base": cfg["base"]["keyRefs"]}}
    return plan, files, directories, cfg


def install(args, layout=None, runner=subprocess.run, own_source=None):
    layout = layout or LAYOUT
    own_source = own_source if own_source is not None else read_file(Path(__file__).absolute(), "RENEWAL_SOURCE_DRIFT",
                                                                       1048576)
    plan, files, directories, cfg = install_plan(args, layout, own_source)
    plan_sha = sha(canonical(plan))
    if not args.apply:
        print(json.dumps(plan, indent=1, sort_keys=True))
        print("MANDATE_RENEWAL_INSTALL=PLAN_READY PLAN_SHA256=" + plan_sha)
        return 0
    require(args.plan_sha256 == plan_sha, "INSTALL_PLAN_CHANGED")
    for path in directories:
        if not os.path.lexists(path):
            os.mkdir(path, 0o700)
            os.chown(path, 0, 0)
            os.chmod(path, 0o700)
        private_directory(path, "PRIVATE_INSTALL_DIRECTORY_REQUIRED")
    for path, raw in files.items():
        write_exclusive(path, raw, 0o644 if path.startswith(layout["unitDirectory"] + "/") else 0o600)
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    code = layout["codeRoot"]

    def call(argv):
        result = runner(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=120, env=env)
        return result.returncode, result.stdout, result.stderr

    returncode, _, _ = call(["systemctl", "daemon-reload"])
    require(returncode == 0, "INSTALL_DAEMON_RELOAD_FAILED")
    returncode, _, error = call([layout["python"], "-I", "-B", code + "/renewal.py", "run", "--configuration",
                                 code + "/configuration.json", "--configuration-sha256", plan["configurationSha256"],
                                 "--dry-run"])
    print("MANDATE_RENEWAL_DRY_RUN=" + error.decode("ascii", "replace").strip()[:200])
    require(returncode == 0, "INSTALL_DRY_RUN_BLOCKED")
    returncode, _, _ = call(["systemctl", "enable", "--now", TIMER])
    require(returncode == 0, "INSTALL_TIMER_ENABLE_FAILED")
    print("MANDATE_RENEWAL_INSTALL=APPLIED PLAN_SHA256=" + plan_sha)
    return 0


# --- governed incident closure ------------------------------------------------

def temporaries(roots):
    found = []
    for root in roots:
        private_directory(root, "PRIVATE_MANDATE_LEDGER_REQUIRED")
        for name in sorted(os.listdir(root)):
            if TEMPORARY.fullmatch(name):
                path = Path(root) / name
                info = path.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and info.st_size <= 65536, "UNSAFE_TEMPORARY_ENTRY")
                raw = path.read_bytes()
                found.append({"path": str(path), "size": len(raw), "sha256": sha(raw)})
    return found


def incident_close(args, runner=subprocess.run, source_path=None):
    job = Job(args.configuration, args.configuration_sha256, source_path=source_path)
    cfg = job.cfg
    incident_path = job.state_root / "incidents" / "open.json"
    incident = job.incident()
    found = temporaries([cfg["b1b2"]["ledgerRoot"], cfg["base"]["ledgerRoot"], cfg["base"]["versionedRoot"]])
    require(incident is not None or found, "NOTHING_TO_CLOSE")
    incident_sha = sha(read_file(incident_path, "RENEWAL_INCIDENT_UNREADABLE", 4096)) if incident else None
    plan = {"schema": CLOSE_PLAN_SCHEMA, "incident": incident, "incidentSha256": incident_sha, "temporaries": found}
    plan_sha = sha(canonical(plan))
    if not args.apply:
        print(json.dumps(plan, indent=1, sort_keys=True))
        print("MANDATE_RENEWAL_INCIDENT_CLOSE=PLAN_READY PLAN_SHA256=" + plan_sha)
        return 0
    require(args.plan_sha256 == plan_sha, "INCIDENT_CLOSE_PLAN_CHANGED")
    for item in found:
        path = Path(item["path"])
        require(TEMPORARY.fullmatch(path.name) and sha(path.read_bytes()) == item["sha256"], "INCIDENT_CLOSE_PLAN_CHANGED")
        os.unlink(path)
        fsync_directory(path.parent)
    if incident is not None:
        closed = job.state_root / "incidents" / "closed"
        if not os.path.lexists(closed):
            os.mkdir(closed, 0o700)
        private_directory(closed, "PRIVATE_RENEWAL_STATE_ROOT_REQUIRED")
        target = closed / (str(incident["firstSeenAt"]) + "-" + incident_sha[:16] + ".json")
        try:
            os.link(incident_path, target, follow_symlinks=False)
        except FileExistsError:
            raise Blocked("RENEWAL_TARGET_EXISTS") from None
        os.unlink(incident_path)
        fsync_directory(closed)
        fsync_directory(incident_path.parent)
    result = runner(["systemctl", "start", SERVICE], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=300, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    print("MANDATE_RENEWAL_INCIDENT_CLOSE=APPLIED PLAN_SHA256=" + plan_sha
          + " SERVICE_RETURNCODE=" + str(result.returncode))
    return 0


# --- CLI ----------------------------------------------------------------------

def parser():
    root = argparse.ArgumentParser(prog="renewal.py")
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--configuration", required=True)
    run.add_argument("--configuration-sha256", required=True)
    run.add_argument("--dry-run", action="store_true")
    for name in ("install", "incident-close"):
        item = sub.add_parser(name)
        mode = item.add_mutually_exclusive_group(required=True)
        mode.add_argument("--plan", action="store_true")
        mode.add_argument("--apply", action="store_true")
        item.add_argument("--plan-sha256")
    install_parser = sub.choices["install"]
    for option in ("--source-dir", "--b1b2-anchor", "--b1b2-anchor-sha256", "--base-anchor", "--base-anchor-sha256",
                   "--authority-profile", "--authority-profile-sha256", "--installation-ref", "--entity-ref"):
        install_parser.add_argument(option, required=True)
    close_parser = sub.choices["incident-close"]
    close_parser.add_argument("--configuration", required=True)
    close_parser.add_argument("--configuration-sha256", required=True)
    return root


def main(argv=None):
    os.umask(0o077)
    try:
        args = parser().parse_args(argv)
    except SystemExit:
        return 2
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                "ISOLATED_ROOT_REQUIRED")
        if args.command != "run":
            require(not args.apply or hashed(args.plan_sha256), "EXACT_PLAN_SHA256_REQUIRED")
        if args.command == "install":
            return install(args)
        if args.command == "incident-close":
            return incident_close(args)
        outcome, reason, would = Job(args.configuration, args.configuration_sha256).run(args.dry_run)
    except Blocked as error:
        print("MANDATE_RENEWAL=BLOCKED REASON=" + str(error), file=sys.stderr)
        return 2
    except Exception:
        print("MANDATE_RENEWAL=BLOCKED REASON=MANDATE_RENEWAL_UNPROVEN", file=sys.stderr)
        return 2
    suffix = " WOULD_RENEW" if args.dry_run and would else ""
    print("MANDATE_RENEWAL=" + outcome + " REASON=" + (reason or "NONE") + suffix, file=sys.stderr)
    return 2 if outcome == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
