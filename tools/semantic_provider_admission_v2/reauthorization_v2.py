"""Durable reauthorization immediately around STARTING; no freshness window."""
import copy
from pathlib import Path

from tools.semantic_provider_operation import authorization
from .consumption_v2 import operating_role, require
from .evidence_v2 import validate


def sealed_authorizer_v2(*, head_reader, binding, evidence_binding, creation_frame_observer_binding,
                         bundle, budget):
    """head_reader must execute authorization.head against the sealed operation inputs."""
    from tools.semantic_provider_deployment_authentication import CreatedFrameObserver, private_bytes
    from tools.semantic_provider_preexec_native import NativeBackend

    binding = copy.deepcopy(binding)
    evidence_binding = copy.deepcopy(evidence_binding)
    require(set(evidence_binding) == {"path", "sha256"}, "EXACT_SEALED_EVIDENCE_BINDING_REQUIRED")
    frame = CreatedFrameObserver(copy.deepcopy(creation_frame_observer_binding), budget)

    def authorize():
        budget.check()
        head = head_reader()
        role = operating_role(head, binding)
        path = Path(evidence_binding["path"])
        raw = private_bytes(path)
        require(authorization.sha(raw) == evidence_binding["sha256"], "SEALED_EPOCH_EVIDENCE_DRIFT")
        value = validate(authorization.decode(raw))
        require(all(value[k] == binding[k] for k in ("containerId", "epoch", "authorizationSha256")),
                "SEALED_EPOCH_SCOPE_DRIFT")
        require(NativeBackend.generation(None, value["generation"]["pid"]) == value["generation"],
                "LATE_EPOCH_GENERATION_DRIFT")
        frame_hash, inputs = frame.observe(value["generation"], Path(bundle) / "config.json",
                                          value["applicationHash"], role["framePolicySha256"])
        require(frame_hash == value["creationFrameHash"], "LATE_CREATED_FRAME_DRIFT")
        require(NativeBackend.generation(None, value["generation"]["pid"]) == value["generation"]
                and private_bytes(path) == raw, "LATE_EPOCH_EVIDENCE_CHANGED")
        for source, content in inputs.items():
            require(private_bytes(source) == content, "LATE_FRAME_INPUT_DRIFT")
        operating_role(head_reader(), binding)
        budget.check()
        return True

    return authorize
