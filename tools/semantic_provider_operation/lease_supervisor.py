"""R3 lease service. No signing, Docker access or direct nft writes.

Linux custody and durable storage are production boundaries; Service accepts
small injected clocks/stores/factories so the lifecycle is testable on Windows.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import threading
import time
import types

import authorization
import epochs

SCHEMA = "ouf.semantic-provider-lease-supervisor.v1"
STATUS_SCHEMA = "ouf.semantic-provider-lease-supervisor-status.v1"
RATE_SCHEMA = "ouf.semantic-provider-lease-activations.v1"
ROLES = ("adapter", "southbound")
CODE = re.compile(r"[A-Z0-9_]{1,80}")
FIELDS = {"schema", "sourceRoot", "sourceHashes", "installationRef", "entityRef", "issuerRef", "authorizationRoot", "anchorBinding",
          "mandateRoot", "opensslBinding", "mandatesModule", "registryRoot", "coordinator",
          "recoveryJournalRoot", "statusPath", "limits"}
COORDINATOR_FIELDS = {"ownerConfiguration", "journalPath", "commonLockPath", "dnsProfile", "nftBinding"}
# Reviewed R12 bytes (LF delivery). Never import recovery programs from paths.
PINS = {
    "activation_core": "06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a",
    "bounded_recovery": "ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd",
    "recovery_journal": "43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d",
    "lease_recovery_budget": "c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf",
    "resilient_lease_adapter": "beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683",
    "adaptive_supervisor": "08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c",
    "nft_seconds_backend": "04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1",
    "deadline_backend": "9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2",
    "continuous_supervisor": "8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e",
    "dns": "f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f",
    "readback_margin_compiler": "814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d",
}
SELF = "scripts/semantic-provider-lease-supervisor-v2.py"
OPERATION_SOURCES = {"tools/semantic_provider_operation/" + name + ".py"
                     for name in ("authorization", "epochs", "lease_supervisor")}
RECOVERY_SOURCES = {"tools/semantic_lease_recovery/" + name + ".py": digest for name, digest in PINS.items()}
SOURCES = {SELF} | OPERATION_SOURCES | set(RECOVERY_SOURCES)


class Denied(RuntimeError):
    """Only explicit public codes cross the CLI boundary."""


def require(ok, code):
    if not ok:
        raise Denied(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


canonical = authorization.canonical


def public(error):
    if isinstance(error, (Denied, authorization.OperationDenied)) and CODE.fullmatch(str(error)):
        return str(error)
    return "LOCAL_STATE_UNPROVEN"


def absolute(value):
    return (type(value) is str and value.startswith("/") and ".." not in value.split("/")
            and "//" not in value and "\x00" not in value and str(Path(value).as_posix()) == value)


def binding(value, extra=()):
    return (type(value) is dict and set(value) == {"path", "sha256", *extra}
            and absolute(value["path"]) and type(value["sha256"]) is str
            and authorization.HEX64.fullmatch(value["sha256"]) is not None)


def source_bindings(value):
    require(absolute(value["sourceRoot"]), "ABSOLUTE_SOURCE_ROOT_REQUIRED")
    hashes = value["sourceHashes"]
    require(type(hashes) is dict and set(hashes) == SOURCES
            and all(type(h) is str and authorization.HEX64.fullmatch(h) for h in hashes.values()),
            "EXACT_SUPERVISOR_SOURCE_SET_REQUIRED")
    require(all(hashes[path] == digest for path, digest in RECOVERY_SOURCES.items()),
            "SUPERVISOR_RECOVERY_PIN_MISMATCH")


def validate(raw):
    value = authorization.decode(raw)
    require(set(value) == FIELDS and value["schema"] == SCHEMA, "EXACT_SUPERVISOR_CONFIGURATION_REQUIRED")
    source_bindings(value)
    require(all(authorization.identity(value[k]) for k in ("installationRef", "entityRef", "issuerRef")),
            "SUPERVISOR_IDENTITY_REQUIRED")
    require(all(absolute(value[k]) for k in ("authorizationRoot", "mandateRoot", "registryRoot",
                                            "recoveryJournalRoot", "statusPath")), "ABSOLUTE_PATH_REQUIRED")
    require(binding(value["anchorBinding"]) and binding(value["mandatesModule"])
            and binding(value["opensslBinding"], ("version",))
            and type(value["opensslBinding"]["version"]) is str
            and re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,63}", value["opensslBinding"]["version"]),
            "EXACT_SUPERVISOR_BINDING_REQUIRED")
    c = value["coordinator"]
    require(type(c) is dict and set(c) == COORDINATOR_FIELDS
            and all(binding(c[k]) for k in ("ownerConfiguration", "dnsProfile", "nftBinding"))
            and all(absolute(c[k]) for k in ("journalPath", "commonLockPath")), "EXACT_COORDINATOR_BINDINGS_REQUIRED")
    limits = value["limits"]
    require(type(limits) is dict and set(limits) == {"maxActivationsPerHour", "heartbeatSeconds", "pollSeconds"}
            and type(limits["maxActivationsPerHour"]) is int and limits["maxActivationsPerHour"] == 6
            and type(limits["heartbeatSeconds"]) is int and 1 <= limits["heartbeatSeconds"] <= 30
            and type(limits["pollSeconds"]) is int and 1 <= limits["pollSeconds"] <= 300,
            "BOUNDED_SUPERVISOR_LIMITS_REQUIRED")
    return value


def ancestors(path):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "SUPERVISOR_ANCESTOR_CUSTODY_REQUIRED")


def read_file(path, expected=None, *, executable=False):
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and (bool(info.st_mode & 0o111) and not info.st_mode & 0o022 if executable
                     else stat.S_IMODE(info.st_mode) == 0o600)
                and info.st_size <= (16 * 1024 * 1024 if executable else 131072), "SUPERVISOR_FILE_CUSTODY_REQUIRED")
        raw = os.read(fd, info.st_size + 1)
        end = os.fstat(fd)
        require(len(raw) == info.st_size and (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (end.st_size, end.st_mtime_ns, end.st_ctime_ns), "SUPERVISOR_FILE_CHANGED")
        require(expected is None or sha(raw) == expected, "SUPERVISOR_BINDING_HASH_MISMATCH")
        return raw
    finally:
        os.close(fd)


def private_directory(path):
    ancestors(path)
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "SUPERVISOR_PRIVATE_DIRECTORY_REQUIRED")


def verify_sources(cfg, reader=read_file, directory=private_directory):
    """Return only verified bytes; recheck the closed set and the fixed R12 pins."""
    source_bindings(cfg)
    root = Path(cfg["sourceRoot"])
    directory(root)
    verified = {}
    for relative in sorted(SOURCES):
        raw = reader(root / relative, cfg["sourceHashes"][relative])
        require(sha(raw) == cfg["sourceHashes"][relative], "SUPERVISOR_BINDING_HASH_MISMATCH")
        verified[relative] = raw
    return verified


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    path = Path(path)
    private_directory(path.parent)
    temp = path.parent / (".lease-" + secrets.token_hex(16))
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        if temp.exists():
            temp.unlink()


def compiled(raw, path, name, expected):
    require(sha(raw) == expected, "SUPERVISOR_BINDING_HASH_MISMATCH")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module  # dataclasses and sealed inter-module imports
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class Configuration:
    def __init__(self, path, expected, reader=read_file, directory=private_directory):
        require(type(expected) is str and authorization.HEX64.fullmatch(expected), "CONFIGURATION_SHA256_REQUIRED")
        self.path, self.expected, self.reader = path, expected, reader
        self.directory = directory
        self.value = validate(reader(path, expected))

    def custody(self):
        try:
            self.reader(self.path, self.expected)
            c = self.value["coordinator"]
            for name in ("ownerConfiguration", "dnsProfile", "nftBinding"):
                item = c[name]
                self.reader(item["path"], item["sha256"], executable=name == "nftBinding")
            item = self.value["mandatesModule"]
            self.reader(item["path"], item["sha256"])
            return verify_sources(self.value, self.reader, self.directory)
        except OSError:
            raise Denied("CONFIGURATION_CUSTODY_CHANGED") from None


class Guards:
    def __init__(self, configuration, mandates, structure_hash, permanent, *, head=authorization.head,
                 current=epochs.current, live=epochs.live, boot=epochs.boot_id, clock=time.time, retained=lambda: None):
        self.configuration, self.cfg, self.mandates = configuration, configuration.value, mandates
        self.structure, self.Permanent = structure_hash, permanent
        self.head, self.current, self.live, self.boot, self.clock = head, current, live, boot, clock
        self.retained = retained
        self.fixed = None
        self.reason = None
        self.sequence = None
        self.epochs = dict.fromkeys(ROLES)

    def deny(self, category, detail):
        self.reason = detail
        raise self.Permanent(category)

    def custody_guard(self):
        try:
            self.configuration.custody()
            self.retained()
        except Denied as error:
            self.deny("CONFIGURATION_DRIFT", public(error))
        except Exception:
            self.deny("INTEGRITY_UNPROVEN", "LOCAL_STATE_UNPROVEN")

    def scope_guard(self):
        try:
            return self._scope()
        except self.Permanent:
            raise
        except authorization.OperationDenied as error:
            self.deny("INTEGRITY_UNPROVEN", public(error))
        except Exception:
            self.deny("INTEGRITY_UNPROVEN", "LOCAL_STATE_UNPROVEN")

    def _scope(self):
        c = self.cfg
        try:
            h = self.head(self.mandates, c["anchorBinding"], c["mandateRoot"], c["opensslBinding"],
                          c["authorizationRoot"], c["installationRef"], c["entityRef"], c["issuerRef"], self.clock)
        except authorization.OperationDenied as error:
            self.deny("AUTHORITY_REVOKED", public(error))
        except OSError:
            self.deny("AUTHORITY_REVOKED", "OPERATION_AUTHORIZATION_UNPROVEN")
        self.sequence = h["sequence"]
        if h["decision"] != "OPERATE":
            self.deny("AUTHORITY_REVOKED", "OPERATION_STOP")
        expected = {"ownerConfigurationSha256": c["coordinator"]["ownerConfiguration"]["sha256"],
                    "leaseStructureHash": self.structure, "dnsProfileSha256": c["coordinator"]["dnsProfile"]["sha256"]}
        if h["authorization"]["lease"] != expected:
            self.deny("CONFIGURATION_DRIFT", "LEASE_BINDINGS_CHANGED")
        snapshot = {}
        boot = self.boot()
        for role in ROLES:
            cid = h["authorization"]["roles"][role]["containerId"]
            journal = self.current(c["registryRoot"], cid)
            if journal is None or not self.live(journal, boot):
                self.deny("GENERATION_CHANGED", "EPOCH_NOT_LIVE")
            if journal["authorizationSha256"] != h["sha256"]:
                self.deny("AUTHORITY_REVOKED", "EPOCH_AUTHORIZATION_CHANGED")
            snapshot[role] = {"containerId": cid, "epoch": journal["epoch"], "generation": dict(journal["generation"])}
        if self.fixed is not None and snapshot != self.fixed:
            self.deny("GENERATION_CHANGED", "EPOCH_SCOPE_CHANGED")
        self.epochs = {r: snapshot[r]["epoch"] for r in ROLES}
        return snapshot


class ActivationStore:
    """Single process writer, protected by the service lifetime lock."""
    def __init__(self, status_path, *, reader=read_file, writer=atomic):
        self.path = Path(str(status_path) + ".activations.json")
        self.reader, self.writer = reader, writer
        if self.path.exists():
            self.row = authorization.decode(reader(self.path))
            require(set(self.row) == {"schema", "lastWall", "openings"} and self.row["schema"] == RATE_SCHEMA
                    and type(self.row["openings"]) is list and len(self.row["openings"]) <= 6
                    and all(self.number(v) for v in [self.row["lastWall"], *self.row["openings"]])
                    and self.row["openings"] == sorted(self.row["openings"])
                    and all(v <= self.row["lastWall"] for v in self.row["openings"]), "ACTIVATION_HISTORY_UNPROVEN")
        else:
            require(not Path(status_path).exists(), "ACTIVATION_HISTORY_MISSING")
            self.row = {"schema": RATE_SCHEMA, "lastWall": 0, "openings": []}
            writer(self.path, self.row)

    @staticmethod
    def number(value):
        return type(value) in (int, float) and math.isfinite(value) and value >= 0

    def recent(self, now):
        require(self.number(now) and now >= self.row["lastWall"], "ACTIVATION_CLOCK_REGRESSION")
        return [v for v in self.row["openings"] if v > now - 3600]

    def count(self, now):
        return len(self.recent(now))

    def reserve(self, now):
        rows = self.recent(now)
        require(len(rows) < 6, "ACTIVATION_RATE_LIMITED")
        row = {"schema": RATE_SCHEMA, "lastWall": now, "openings": [*rows, now]}
        self.writer(self.path, row)  # fsync BEFORE opening a scope; failures consume no live lease
        self.row = row


class ScopeStop:
    def __init__(self, stop):
        self.stop, self.ended = stop, False

    def is_set(self):
        return self.ended or self.stop.is_set()

    def wait(self, seconds):
        return self.is_set() or self.stop.wait(seconds)


class Service:
    def __init__(self, cfg, coordinator, guards, factory, activations=None, *, stop=None, clock=time.time,
                 writer=atomic):
        self.cfg, self.c, self.guards, self.factory, self.activations = cfg, coordinator, guards, factory, activations
        self.stop = stop if stop is not None else threading.Event()
        self.clock, self.writer = clock, writer
        self.renewals = 0

    def terminate(self, *_):
        self.stop.set()  # signal handler never performs I/O or takes a lock

    def quiesce(self):
        self.c.quiesce()
        self.verify_quiesced()

    def verify_quiesced(self):
        with self.c.hold_lock():
            row = self.c.journal()
            require(row["state"] == "QUIESCED" and row["leaseAuthorized"] is False
                    and row["startAuthorized"] is False and not any(self.c.sets()), "QUIESCENCE_UNPROVEN")

    def status(self, state, reason=None):
        require(state in {"WAITING", "ACTIVE", "PARKED_RATE_LIMITED", "STOPPED", "FAILED"}
                and (reason is None or type(reason) is str and CODE.fullmatch(reason)), "STATUS_SCHEMA_UNPROVEN")
        value = {"schema": STATUS_SCHEMA, "state": state, "reason": reason,
                 "activationsLastHour": self.activations.count(self.clock()), "renewals": self.renewals,
                 "authorizationSequence": self.guards.sequence, "epochs": dict(self.guards.epochs),
                 "updatedAt": int(self.clock())}
        require(type(value["renewals"]) is int and value["renewals"] >= 0
                and (value["authorizationSequence"] is None or type(value["authorizationSequence"]) is int)
                and set(value["epochs"]) == set(ROLES)
                and all(v is None or type(v) is int for v in value["epochs"].values()), "STATUS_SCHEMA_UNPROVEN")
        self.writer(self.cfg["statusPath"], value)

    def run_scope(self):
        token = ScopeStop(self.stop)
        supervisor = None
        base = self.renewals

        def observe(row):
            self.renewals = base + supervisor.renewals
            if row["state"] in {"BLOCKED", "RECONCILE_REQUIRED", "PAUSED_EXHAUSTED", "CANCELLED"}:
                token.ended = True
                self.guards.reason = self.guards.reason or safe_recovery_reason(row["reason"])
            elif row["state"] == "ACTIVE":
                self.status("ACTIVE")
            else:
                self.status("WAITING", safe_recovery_reason(row["reason"]))
        try:
            supervisor = self.factory(self.guards)
            supervisor.serve(token, observe)
        except self.guards.Permanent:
            pass  # includes invalidation between reservation and factory guards
        finally:
            if supervisor is not None:
                self.renewals = base + supervisor.renewals
            self.quiesce()

    def run(self):
        try:
            self.quiesce()  # first lifecycle action, even when already stopped
            if self.activations is None:
                self.activations = ActivationStore(self.cfg["statusPath"])
            while not self.stop.is_set():
                self.guards.fixed = None
                self.guards.reason = None
                try:
                    self.guards.custody_guard()
                    snapshot = self.guards.scope_guard()
                except self.guards.Permanent:
                    self.status("WAITING", self.guards.reason)
                else:
                    if self.activations.count(self.clock()) >= 6:
                        self.verify_quiesced()
                        self.status("PARKED_RATE_LIMITED", "ACTIVATION_RATE_LIMITED")
                    elif not self.stop.is_set():
                        self.activations.reserve(self.clock())
                        self.guards.fixed = snapshot
                        self.run_scope()
                        if not self.stop.is_set():
                            self.status("WAITING", self.guards.reason)
                self.stop.wait(self.cfg["limits"]["heartbeatSeconds"])
            self.quiesce()
            self.status("STOPPED")
            return 0
        except Exception as error:
            reason = public(error)
            try:
                self.quiesce()
            except Exception:
                reason = "QUIESCENCE_UNPROVEN"
            # A broken history/clock must not prevent a FAILED status publication.
            try:
                self.status("FAILED", reason)
            except Exception:
                self.writer(self.cfg["statusPath"], {"schema": STATUS_SCHEMA, "state": "FAILED", "reason": reason,
                    "activationsLastHour": len(self.activations.row["openings"]) if self.activations else 0,
                    "renewals": self.renewals,
                    "authorizationSequence": None, "epochs": dict.fromkeys(ROLES), "updatedAt": int(self.clock())})
            return 1


def safe_recovery_reason(reason):
    # Only the fixed library vocabulary may enter status, never an arbitrary exception string.
    allowed = {"DNS_UNAVAILABLE", "DNS_WINDOW_TOO_SHORT", "DEPENDENCY_TIMEOUT", "DEPENDENCY_UNAVAILABLE",
               "RATE_LIMITED", "SERVICE_UNAVAILABLE", "RETRY_BUDGET_EXHAUSTED", "RECOVERY_SCOPE_TIME_EXHAUSTED",
               "NO_RETRY_WINDOW_WITHIN_BUDGET", "AUTHORITY_REVOKED", "GENERATION_CHANGED", "CONFIGURATION_DRIFT",
               "INTEGRITY_UNPROVEN", "SAFE_PAUSE_UNPROVEN", "PUBLICATION_OUTCOME_AMBIGUOUS"}
    return reason if reason in allowed else "LOCAL_STATE_UNPROVEN"


@contextmanager
def lifetime_lock(status_path):
    import fcntl
    path = Path(str(status_path) + ".lock")
    private_directory(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        read_file(path)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def runtime(configuration):
    """Compose the installed owner closure and the unchanged pinned R12 recovery."""
    cfg = configuration.value
    verified = configuration.custody()
    root = Path(cfg["sourceRoot"])

    def recovery(name, module_name=None):
        relative = "tools/semantic_lease_recovery/" + name + ".py"
        expected = cfg["sourceHashes"][relative]
        require(expected == PINS[name], "SUPERVISOR_RECOVERY_PIN_MISMATCH")
        return compiled(verified[relative], root / relative, module_name or name, expected)

    core = recovery("activation_core", "lease_activation_core_v2")
    binding_ = cfg["coordinator"]["ownerConfiguration"]
    owner = json.loads(read_file(binding_["path"], binding_["sha256"]))
    source = Path(binding_["path"]).parent / "source"
    installed, retained = core.load_installed(owner, source, read_file)
    loaded = {}
    for name in PINS:
        if name == "activation_core":
            continue
        loaded[name] = recovery(name)
    c = cfg["coordinator"]
    require(owner["journalFile"] == c["journalPath"] and owner["commonLockFile"] == c["commonLockPath"]
            and owner["nftPath"] == c["nftBinding"]["path"] and owner["nftSha256"] == c["nftBinding"]["sha256"]
            and owner["binding"]["leaseStructureHash"] == owner["expectedStructureHash"]
            and canonical(owner["dns"]) == read_file(c["dnsProfile"]["path"], c["dnsProfile"]["sha256"]),
            "COORDINATOR_CONFIGURATION_DRIFT")
    class BoundBackend(loaded["deadline_backend"].DeadlineNftBackend):
        def run(self, *args, **kwargs):
            item = c["nftBinding"]
            read_file(item["path"], item["sha256"], executable=True)
            result = super().run(*args, **kwargs)
            read_file(item["path"], item["sha256"], executable=True)
            return result

    backend = BoundBackend([c["nftBinding"]["path"]], owner["kernel"],
                                                         owner["expectedStructureHash"], owner["readBudgetSeconds"])
    owner_object = installed["semantic_provider_lease_owner"].LeaseOwner(owner["kernel"], owner["dns"], backend)
    coordination = installed["semantic_provider_lease_coordination"]
    journal = coordination.PrivateJournal(Path(c["journalPath"]))
    coordinator = coordination.Coordinator(owner_object, owner["binding"],
        lambda: coordination.hold_common_lock(Path(c["commonLockPath"])), journal.read, journal.write)
    item = cfg["mandatesModule"]
    mandates = compiled(read_file(item["path"], item["sha256"]), item["path"], "lease_mandates_v2", item["sha256"])

    def custody():
        for name, raw in retained.items():
            read_file(source / name, sha(raw))

    guards = Guards(configuration, mandates, owner["expectedStructureHash"], loaded["bounded_recovery"].Permanent,
                    retained=custody)

    def factory(guards):
        guards.custody_guard()
        guards.scope_guard()
        parent = Path(cfg["recoveryJournalRoot"])
        private_directory(parent)
        directory = parent / secrets.token_hex(24)
        directory.mkdir(mode=0o700)  # never reopen or delete a previous recovery
        sync_directory(parent)
        journal = loaded["recovery_journal"].Journal(directory)
        adapter = loaded["continuous_supervisor"].RenewingLeaseAdapter(coordinator, loaded["dns"],
            loaded["readback_margin_compiler"], guards.scope_guard, guards.custody_guard, time.monotonic)
        recovery = loaded["lease_recovery_budget"].LeaseRecovery(journal, adapter, loaded["bounded_recovery"].Policy(),
            sha(canonical({"configuration": configuration.expected, "invocation": directory.name})),
            sha(canonical(guards.fixed)), lambda: (time.time(), time.monotonic()), secrets.SystemRandom().random)
        journal.initialize(recovery.initial())
        return loaded["continuous_supervisor"].Supervisor(recovery, coordinator, cfg["limits"]["pollSeconds"],
                                                        heartbeat=cfg["limits"]["heartbeatSeconds"])
    return coordinator, guards, factory


def quiesce_only(configuration):
    """One revocation, verified under the coordinator lock; no service lifetime."""
    coordinator, _, _ = runtime(configuration)
    coordinator.quiesce()
    Service.verify_quiesced(types.SimpleNamespace(c=coordinator))
    configuration.custody()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Semantic provider lease supervisor v2")
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--quiesce-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        configuration = Configuration(args.configuration, args.configuration_sha256)
        if args.quiesce_only:
            return quiesce_only(configuration)
        cfg = configuration.value
        # Install the handler before loading native bindings or acquiring the worker lock.
        stop = threading.Event()
        previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
        try:
            with lifetime_lock(cfg["statusPath"]):
                try:
                    coordinator, guards, factory = runtime(configuration)
                except Exception as error:
                    # Configuration is verified and this process owns the status lock.
                    # A construction failure cannot establish a usable scope.
                    atomic(cfg["statusPath"], {"schema": STATUS_SCHEMA, "state": "FAILED", "reason": public(error),
                        "activationsLastHour": 0, "renewals": 0, "authorizationSequence": None,
                        "epochs": dict.fromkeys(ROLES), "updatedAt": int(time.time())})
                    raise
                service = Service(cfg, coordinator, guards, factory, stop=stop)
                return service.run()
        finally:
            signal.signal(signal.SIGTERM, previous)
    except Exception as error:
        print(public(error), file=sys.stderr)
        return 1
