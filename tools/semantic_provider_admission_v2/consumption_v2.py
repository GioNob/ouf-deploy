"""One-way epoch consumption; caller supplies the existing common lock and CAS IO."""
import copy

from tools.semantic_provider_operation import authorization


def require(ok, code):
    if not ok:
        raise authorization.OperationDenied(code)


def hashed(value):
    return type(value) is str and authorization.HEX64.fullmatch(value) is not None


def generation(value):
    require(type(value) is dict and set(value) == {"pid", "startTicks", "namespaceInode"}
            and all(type(v) is int and v > 0 for v in value.values()) and value["pid"] > 1,
            "CONSUMPTION_GENERATION_REQUIRED")
    return copy.deepcopy(value)


def operating_role(head, binding):
    require(type(head) is dict and head.get("decision") == "OPERATE"
            and head.get("sha256") == binding["authorizationSha256"], "OPERATION_HEAD_DRIFT")
    value = head["authorization"]
    require(all(value[k] == binding[k] for k in ("installationRef", "entityRef")),
            "CONSUMPTION_OPERATION_SCOPE_DRIFT")
    roles = [role for role in value["roles"].values() if role["containerId"] == binding["containerId"]]
    require(len(roles) == 1, "CONSUMPTION_OPERATION_ROLE_REQUIRED")
    require(roles[0]["admissionConfigurationSha256"] == binding["configurationHash"],
            "CONSUMPTION_CONFIGURATION_DRIFT")
    return copy.deepcopy(roles[0])


class EpochConsumption:
    STATES = {"STAGED", "CREATING", "CREATED", "READY", "STARTING", "STARTED"}
    SCHEMA = "ouf.semantic-deployment-consumption.v2"

    def __init__(self, binding, journal, hold_lock):
        require(type(binding) is dict and set(binding) == {"installationRef", "entityRef", "containerId",
                "epoch", "authorizationSha256", "configurationHash"}
                and all(authorization.identity(binding[k]) for k in ("installationRef", "entityRef"))
                and all(hashed(binding[k]) for k in ("containerId", "authorizationSha256", "configurationHash"))
                and type(binding["epoch"]) is int and 1 <= binding["epoch"] <= 10 ** 9,
                "EXACT_CONSUMPTION_BINDING_REQUIRED")
        self.binding = copy.deepcopy(binding)
        self.journal, self.hold_lock = journal, hold_lock

    def initial(self):
        return {"schema": self.SCHEMA, **self.binding, "state": "STAGED", "bundleHash": None,
                "generation": None, "evidenceHash": None, "driverHash": None}

    def record(self):
        value = self.journal.read()
        require(type(value) is dict and set(value) == {"schema", *self.binding, "state", "bundleHash",
                "generation", "evidenceHash", "driverHash"} and value["schema"] == self.SCHEMA
                and all(value[k] == v for k, v in self.binding.items()) and value["state"] in self.STATES,
                "FOREIGN_CONSUMPTION_JOURNAL")
        fields = ("bundleHash", "generation", "evidenceHash", "driverHash")
        if value["state"] in ("STAGED", "CREATING"):
            require(all(value[k] is None for k in fields), "INCOMPLETE_CONSUMPTION_PHASE")
        else:
            require(hashed(value["bundleHash"]), "CREATED_BUNDLE_HASH_REQUIRED")
            generation(value["generation"])
            if value["state"] == "CREATED":
                require(value["evidenceHash"] is value["driverHash"] is None, "INCOMPLETE_CONSUMPTION_PHASE")
            else:
                require(hashed(value["evidenceHash"]) and (value["driverHash"] is None or hashed(value["driverHash"])),
                        "FINAL_CONSUMPTION_EVIDENCE_REQUIRED")
                if value["state"] in ("STARTING", "STARTED"):
                    require(hashed(value["driverHash"]), "SEALED_CONSUMPTION_DRIVER_REQUIRED")
        return copy.deepcopy(value)

    def publish(self, old, **changes):
        require(self.record() == old, "CONSUMPTION_CHANGED_UNDER_LOCK")
        value = {**old, **copy.deepcopy(changes)}
        self.journal.write(old, value)
        require(self.record() == value, "CONSUMPTION_PUBLICATION_UNPROVEN")
        return copy.deepcopy(value)

    def authorize_create(self, head):
        with self.hold_lock():
            old = self.record()
            require(old["state"] == "STAGED", "DO_NOT_REPLAY_DEPLOYMENT_CREATE")
            operating_role(head, self.binding)
            return self.publish(old, state="CREATING")

    def created(self, bundle_hash, live_generation):
        with self.hold_lock():
            old = self.record()
            require(old["state"] == "CREATING" and hashed(bundle_hash), "OWNED_CREATION_REQUIRED")
            return self.publish(old, state="CREATED", bundleHash=bundle_hash, generation=generation(live_generation))

    def ready_locked(self, evidence):
        from .evidence_v2 import validate
        old = self.record()
        require(old["state"] == "CREATED", "DO_NOT_REPLAY_FINAL_EVIDENCE")
        validate(evidence)
        require(all(evidence[k] == self.binding[k] for k in ("containerId", "epoch", "authorizationSha256"))
                and evidence["bundleHash"] == old["bundleHash"] and evidence["generation"] == old["generation"],
                "CREATED_EVIDENCE_GENERATION_DRIFT")
        self.publish(old, state="READY", evidenceHash=authorization.sha(authorization.canonical(evidence)))
        return copy.deepcopy(evidence)

    def seal_driver_locked(self, driver_hash):
        old = self.record()
        require(old["state"] == "READY" and old["driverHash"] is None and hashed(driver_hash),
                "DO_NOT_REBIND_CONSUMPTION_DRIVER")
        return self.publish(old, driverHash=driver_hash)

    def consume_locked(self, evidence_hash, driver_hash, live_generation, reauthorize, starter):
        old = self.record()
        require(old["state"] == "READY", "DO_NOT_REPLAY_DEPLOYMENT_START")
        require(old["evidenceHash"] == evidence_hash and old["driverHash"] == driver_hash and hashed(driver_hash)
                and generation(live_generation) == old["generation"], "SEALED_START_EVIDENCE_DRIFT")
        require(callable(reauthorize) and callable(starter), "EXPLICIT_GUARDED_START_REQUIRED")
        reauthorize()
        pending = self.publish(old, state="STARTING")
        reauthorize()
        require(self.record() == pending, "CONSUMPTION_CHANGED_BEFORE_START")
        starter()
        self.publish(pending, state="STARTED")
