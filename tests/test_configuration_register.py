import ast
from fnmatch import fnmatchcase
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from capture.contract import registry


# These owners compute destinations from private argv or delegated code. Require the
# relevant entries in addition to checking every literal root in the entry point.
DELEGATES = {
    "platform-restart-install.sh": ["restart"],
    "mandate-renewal-install.sh": ["units", "r3-evidence"],
    "r3-install.sh": ["r3-evidence", "boot-guard"],
    "b1-install.sh": ["r3-evidence", "boot-guard"],
    "runtime-v51-install.sh": ["r3-evidence", "readers"],
    "install-chatbot-file-cohort.py": ["r3-evidence"],
    "install-semantic-provider-r3.py": ["r3-evidence", "units", "readers"],
    "install-semantic-provider-b1.py": ["r3-evidence", "readers"],
    "install-semantic-runtime-v51.py": ["r3-evidence", "readers"],
}
# Read-only OS tools, pseudo filesystems and the ephemeral lock/socket.
OS_INPUT = re.compile(r"^/(?:usr/(?:s?bin|lib)(?:/|$)|bin/|dev/|proc/|sys/|run/(?:docker\.sock|"
                      r"containerd/|ouf-semantic-boot-guard/)|var/run/docker\.sock|tmp(?:/|$))")
LITERAL = re.compile(r"""(?:(?<=["'= (\t])|^)(/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+)""", re.M)
ASSIGNED = re.compile(r"""(?im)^\s*(?:DEST(?:INATION)?|TARGET|INSTALL_ROOT|ROOT|ENTRY|RULE|UNIT)"""
                      r"""\s*=\s*(?:Path\()?['"]?(/[a-zA-Z0-9_./-]+)""")


def destinations(source):
    # Scan literals irrespective of the verb (install, Path, mkdir, redirection or cp).
    candidates = {m[1] for m in LITERAL.finditer(source) if m[1].count("/") >= 2
                  and not OS_INPUT.match(m[1]) and not re.search(r"""\+\s*['"]$""", source[:m.start()])}
    return candidates | set(ASSIGNED.findall(source))


class RegisterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = registry()
        cls.new = [row for row in cls.entries.values() if "kind" in row]

    def test_a5_register_graph(self):
        done = set()
        def walk(key, parents):
            self.assertNotIn(key, parents)
            self.assertIn(key, self.entries)
            if key not in done:
                for parent in self.entries[key].get("dependsOn", []):
                    walk(parent, parents | {key})
                done.add(key)
        for key in self.entries:
            walk(key, set())
        for row in self.new:
            self.assertTrue(row["restoreOrder"] and row["selector"]["bindings"])
            self.assertIn(row["class"], ("mista", "configurazione", "esclusa"))
            if row["class"] == "mista":
                self.assertTrue(row["selector"]["dataSelection"])
            if row["secrets"]:
                self.assertTrue(all(row[k] for k in ("custodian", "rotation", "consumers")))

    def test_a5_registered_units_and_profiles(self):
        selectors = [e["selector"] for e in self.new]
        for path in (ROOT / "ops").rglob("*"):
            if path.is_file() and "systemd" in path.relative_to(ROOT).parts:
                self.assertTrue(any(fnmatchcase(path.name, p) for s in selectors
                                    for p in s.get("unitPatterns", [])), path)
        for path in (ROOT / "contracts").glob("*profile*.json"):
            self.assertTrue(any(path.name in s.get("profileSchemas", []) for s in selectors), path)
        guard = self.entries["capture.boot-guard"]
        self.assertEqual("configurazione", guard["class"])
        for key in ("restore", "test"):
            self.assertIn("docs/OUF_SEMANTIC_LEASE_KERNEL_MIGRATION.md", guard[key])

    def test_a5_installer_destinations(self):
        patterns = [p for e in self.new for p in e["selector"].get("installRoots", [])]
        files = [*(ROOT / "ops/vps").glob("*-install.sh"), *(ROOT / "scripts").glob("install-*.py")]
        for path in files:
            source = path.read_text(encoding="utf-8")
            if path.suffix == ".py":
                ast.parse(source)
            roots = destinations(source)
            self.assertTrue(roots or path.name in DELEGATES, path)
            for root in roots:
                # Parent directories checked for custody are not themselves installation roots.
                if root in {"/usr/local", "/usr/local/libexec", "/usr/local/sbin", "/etc/systemd", "/var/lib"}:
                    continue
                self.assertTrue(any(fnmatchcase(root, p) or fnmatchcase(root, p + "/*")
                                    for p in patterns), (path.name, root))
            for entry in DELEGATES.get(path.name, []):
                self.assertIn("capture." + entry, self.entries)
        self.assertIn("/srv/unclassified", destinations("DEST=/srv/unclassified"))
        self.assertIn("/usr/bin/new-tool", destinations('DEST = Path("/usr/bin/new-tool")'))
