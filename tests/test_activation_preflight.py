"""Exercise the public isolated CLI against independent release inputs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/activation_preflight"
CLI = ROOT / "scripts/activation-preflight.py"
CAP = "ouf.semantic.search.batch"
CHECKS = {"OWNER_CONFIG", "DESCRIPTOR_REGISTERED", "GRANT_APPLICABLE",
          "GATEWAY_INSTALLATION", "MCP_TOOL", "PROFILE_VALID"}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def inputs(tmp_path):
    tree = shutil.copytree(FIXTURE, tmp_path / "release")
    if os.name == "nt":
        # Executor validators use native Path.is_absolute(). Use native fixture
        # paths on Windows while preserving the original Linux fixture for CI.
        path = tree / "profile.json"
        profile = read(path)
        for section, keys in [(profile["gateway"], ["dockerSocket", "keyFile"]),
                              (profile["modules"]["sample"], ["inbox", "journal", "dockerSocket", "nsenter"])]:
            for key in keys:
                section[key] = str(tree / key)
        write(path, profile)
    return tree


def run(tree, roles=True, bundle=True, strict=False):
    cmd = [sys.executable, "-I", "-B", str(CLI), "--request", "request.json", "--profile", "profile.json"]
    if bundle:
        cmd += ["--gateway-bundle", "bundle.json"]
    if roles:
        cmd += ["--role-catalogue", "roles.json"]
    if strict:
        cmd.append("--require-runtime")
    for module in ("onboarding", "semantic", "mcp", "gateway"):
        cmd.extend(["--source", f"{module}={module}"])
    return subprocess.run(cmd, cwd=tree, capture_output=True, text=True, check=False)


def report(tree, **options):
    result = run(tree, **options)
    assert "FIXTURE_SECRET_SENTINEL" not in result.stdout + result.stderr
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert data["contract"] == "ouf.activation-preflight-report.v1"
    checks = data["checks"]
    assert all(set(row) == {"check", "capabilityId", "code", "status", "detail"} for row in checks)
    assert result.returncode == int(any(row["status"] == "FAIL" for row in checks))
    assert data["status"] == next(s for s in ("FAIL", "UNVERIFIABLE", "PASS")
                                  if any(row["status"] == s for row in checks))
    return checks


def single_issue(tree, check, code, status="FAIL", **options):
    rows = report(tree, **options)
    issues = [r for r in rows if r["status"] != "PASS"]
    assert [(r["check"], r["code"], r["status"]) for r in issues] == [(check, code, status)]
    return issues[0]


def test_pass(inputs):
    rows = report(inputs, strict=True)
    assert len(rows) == len(CHECKS) and {r["check"] for r in rows} == CHECKS
    assert all((r["capabilityId"], r["status"], r["code"]) == (CAP, "PASS", "OK") for r in rows)


@pytest.mark.parametrize("separate", [True, False])
def test_profile_only(inputs, separate):
    path = inputs / "semantic/src/main/resources/application.yml"
    if separate:
        path.rename(path.with_name("application-dev.yml"))
        path.write_text("spring.application.name: fixture\n", encoding="utf-8")
    else:
        path.write_text("spring:\n  config.activate.on-profile: fixture\n" + path.read_text(encoding="utf-8"),
                        encoding="utf-8")
    single_issue(inputs, "OWNER_CONFIG", "OWNER_FLAG_PROFILE_ONLY")


@pytest.mark.parametrize("default", ["${FIXTURE_INTENTS}", "${FIXTURE_INTENTS:}", "false", "0"])
def test_invalid_limit(inputs, default):
    path = inputs / "semantic/src/main/resources/application.yml"
    path.write_text(path.read_text(encoding="utf-8").replace("${FIXTURE_INTENTS:4}", default), encoding="utf-8")
    single_issue(inputs, "OWNER_CONFIG", "OWNER_DEFAULT_INVALID")


def test_only_registered_catalogues_count(inputs):
    path = inputs / "onboarding/catalogue/fixture.json"
    path.rename(path.with_name("ignored.json"))
    rows = read(path.with_name("ignored.json"))
    rows[0]["descriptor"]["capabilityId"] = "fixture.other"
    write(path, rows)
    java, = (inputs / "onboarding").rglob("*.java")
    with java.open("a", encoding="utf-8") as stream:
        stream.write('\n// CATALOGUES = List.of("catalogue/ignored.json");\n')
    single_issue(inputs, "DESCRIPTOR_REGISTERED", "DESCRIPTOR_NOT_REGISTERED")


def test_descriptor_actors(inputs):
    path = inputs / "onboarding/catalogue/fixture.json"
    rows = read(path)
    rows[0]["descriptor"]["allowedActors"].append("SERVICE")
    write(path, rows)
    single_issue(inputs, "DESCRIPTOR_REGISTERED", "DESCRIPTOR_MISMATCH")


def test_role_attribute_constraints(inputs):
    path = inputs / "roles.json"
    role = read(path)
    constraints = {"allowedDataLabels": [f"L{i}" for i in range(5)],
                   "allowedDetailLevels": [f"D{i}" for i in range(4)], "effect": "ALLOW"}
    role["roles"][0]["permissions"][0]["constraints"] = constraints
    write(path, {"structuredContent": role})
    single_issue(inputs, "GRANT_APPLICABLE", "GRANT_ATTRIBUTES_MISSING")
    req = read(inputs / "request.json")
    for attr in ("dataAccessLabel", "detailLevel"):
        req["capabilities"][0]["ownerResourceAttributes"].append(attr)
        write(inputs / "request.json", req)
        if attr == "dataAccessLabel":
            single_issue(inputs, "GRANT_APPLICABLE", "GRANT_ATTRIBUTES_MISSING")
    assert all(r["status"] == "PASS" for r in report(inputs))


def test_role_denied_or_empty(inputs):
    path = inputs / "roles.json"
    role = read(path)
    constraints = {"allowedDataLabels": [], "allowedDetailLevels": [], "effect": "DENY"}
    role["roles"][0]["permissions"][0]["constraints"] = constraints
    write(path, role)
    single_issue(inputs, "GRANT_APPLICABLE", "GRANT_DENIED")
    constraints["effect"] = "ALLOW"
    write(path, role)
    assert all(r["status"] == "PASS" for r in report(inputs))


@pytest.mark.parametrize("strict,status", [(True, "FAIL"), (False, "UNVERIFIABLE")])
def test_missing_role_catalogue(inputs, strict, status):
    single_issue(inputs, "GRANT_APPLICABLE", "ROLE_CATALOGUE_REQUIRED", status, roles=False, strict=strict)


def test_missing_bundle_usage(inputs):
    result = run(inputs, bundle=False)
    assert result.returncode == 2 and result.stdout == "" and "--gateway-bundle" in result.stderr


def test_second_role_without_permission(inputs):
    path = inputs / "request.json"
    req = read(path)
    req["capabilities"][0]["roles"].append("fixture-second")
    write(path, req)
    path = inputs / "roles.json"
    roles = read(path)
    roles["roles"].append({"roleId": "fixture-second", "permissions": []})
    write(path, roles)
    assert single_issue(inputs, "GRANT_APPLICABLE", "GRANT_MISSING")["detail"] == "fixture-second"


def test_supplied_unreadable_roles_is_failure(inputs):
    (inputs / "roles.json").unlink()
    single_issue(inputs, "GRANT_APPLICABLE", "INPUT_INVALID")


def test_later_unconditional_document_overrides_flag(inputs):
    path = inputs / "semantic/src/main/resources/application.yml"
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n---\nouf.semantic.published-batch.enabled: false\n")
    single_issue(inputs, "OWNER_CONFIG", "OWNER_DEFAULT_INVALID")


def test_seven_missing_gateway_values(inputs):
    path = inputs / "profile.json"
    profile = read(path)
    values = profile["gateway"]["values"]
    removed = set(values) - {"fixtureCredential"}
    for key in removed:
        del values[key]
    write(path, profile)
    row = single_issue(inputs, "GATEWAY_INSTALLATION", "GATEWAY_VALUES_MISSING")
    assert len(removed) == 7 and all(key in row["detail"] for key in removed)


@pytest.mark.parametrize("kind,code", [("wrong", "GATEWAY_VALUE_INVALID"), ("extra", "GATEWAY_VALUES_UNUSED")])
def test_gateway_type_and_coverage(inputs, kind, code):
    path = inputs / "profile.json"
    profile = read(path)
    key = "rateLimits.semanticSearch.count" if kind == "wrong" else "fixtureExtra"
    profile["gateway"]["values"][key] = "FIXTURE_SECRET_SENTINEL"
    write(path, profile)
    row = single_issue(inputs, "GATEWAY_INSTALLATION", code)
    if kind == "wrong":
        assert row["detail"] == key + " (integer)"


@pytest.mark.parametrize("changed,code", [("spec", "GATEWAY_CAPABILITY_MISMATCH"), ("kind", "GATEWAY_ROUTE_MISSING")])
def test_gateway_route_and_scope(inputs, changed, code):
    if changed == "spec":
        path, = (inputs / "gateway").rglob("*.yaml")
        path.write_text(path.read_text(encoding="utf-8").replace("scope: ", "scope: different."), encoding="utf-8")
    else:
        path = inputs / "bundle.json"
        bundle = read(path)
        bundle["resources"][0]["kind"] = "services"
        write(path, bundle)
    single_issue(inputs, "GATEWAY_INSTALLATION", code)


@pytest.mark.parametrize("key,code", [("publicationState", "MCP_TOOL_INACTIVE"),
                                      ("requiredAuthorizationCapability", "MCP_TOOL_BINDING")])
def test_mcp_manifest(inputs, key, code):
    path = inputs / "mcp/internal/manifest/capabilities.json"
    manifest = read(path)
    manifest["capabilities"][0][key] = "INACTIVE"
    write(path, manifest)
    single_issue(inputs, "MCP_TOOL", code)


@pytest.mark.parametrize("section,key", [("nextSuccessorImage", "ci"), ("semanticDatabase", "schema"),
                                         ("modules", "sample"), ("gateway", "port"), ("runbooks", "issue-12")])
def test_profile_checked(inputs, section, key):
    path = inputs / "profile.json"
    profile = read(path)
    if section == "modules":
        profile[section][key]["module"] = "other"
    else:
        del profile[section][key]
    write(path, profile)
    assert single_issue(inputs, "PROFILE_VALID", "PROFILE_INVALID")["detail"] == section


def test_closed_request_and_contained_paths(inputs):
    path = inputs / "request.json"
    req = read(path)
    config = req["capabilities"][0]["ownerConfig"]
    config["unknown"] = 1
    write(path, req)
    assert run(inputs).returncode == 2
    del config["unknown"]
    config["file"] = "../outside.yml"
    write(path, req)
    assert run(inputs).returncode == 2


def test_multiple_capabilities_keep_independent_rows(inputs):
    req = read(inputs / "request.json")
    cap = dict(req["capabilities"][0], capabilityId="fixture.other")
    req["capabilities"].append(cap)
    write(inputs / "request.json", req)
    rows = report(inputs)
    assert len(rows) == 12 and all(r["status"] == "PASS" for r in rows if r["capabilityId"] == CAP)
    assert {r["check"] for r in rows if r["capabilityId"] == "fixture.other" and r["status"] == "FAIL"} == {
        "DESCRIPTOR_REGISTERED", "MCP_TOOL", "GATEWAY_INSTALLATION", "GRANT_APPLICABLE"}
