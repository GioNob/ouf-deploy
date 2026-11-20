"""Semantic CI image admission and Flyway review for the existing A2 cutover."""
from pathlib import Path
import tempfile

from mandate import Held, digest, need
from module_release.contract import CI_COORDINATES, NAME, Held as ReleaseHeld, matches, package, validate_ci
from module_release.docker import Docker
from module_release.provenance import select_artifact, verify_tested_tree


def inventory(entries):
    need(isinstance(entries, list) and all(isinstance(row, (str, dict)) and row for row in entries),
         "MIGRATION_INVENTORY_REQUIRED")
    stamps = {digest(row) for row in entries}
    need(len(stamps) == len(entries), "DUPLICATE_MIGRATION")
    return stamps


def admit(cfg, journal, source_get):
    spec = cfg["successorImage"]
    ci = spec["ci"]
    repo = ci["repository"]
    try:
        need(set(ci) == set(CI_COORDINATES), "SEMANTIC_CI_PROFILE_REQUIRED")
        validate_ci(ci)
        need(repo.split("/")[-1] == "ouf-semantic-registry" and matches(NAME, ci["workflow"])
             and type(ci["pullRequest"]) is int and ci["pullRequest"] > 0
             and matches(NAME, ci["manifestSchema"]) and matches(NAME, spec["migrationsField"])
             and Path(spec["inbox"]).is_absolute(), "SEMANTIC_CI_PROFILE_REQUIRED")
        previous = inventory(spec["predecessorMigrations"])
        selected = select_artifact(ci, ci["runId"], ci["artifactId"], source_get,
                                   artifact_prefix="semantic-registry-governed-image")
        need(selected == ci, "SEMANTIC_CI_PINS_CHANGED")
        with tempfile.TemporaryFile(dir=journal.path) as archive:
            facts = package(spec, archive, migrations_field=spec["migrationsField"])
            verify_tested_tree(ci, facts, source_get)
            current = inventory(facts["migrations"])
            need(previous <= current, "PREDECESSOR_MIGRATIONS_CHANGED")
            added = [row for row in facts["migrations"] if digest(row) not in previous]
            approved = {"ci": ci, **facts, "newMigrations": added}
            archive.seek(0)
            runtime = Docker({"dockerSocket": cfg["socket"], "ci": ci})
            journal.effect("load-image", approved, lambda: runtime.load(archive, facts))
            return approved
    except ReleaseHeld as exc:
        raise Held(str(exc)) from None


def migration_review(plan, stage):
    image = plan.get("successorImage")
    if image and image["newMigrations"]:
        return digest({"mode": "spring-flyway", "stage": digest(stage), "plan": digest(plan),
                       "imageId": image["ci"]["imageId"], "newMigrations": image["newMigrations"]})
    return None
