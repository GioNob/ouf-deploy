"""Replay an offline transaction from a fresh fixture for every durable publication."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from unittest.mock import patch


class ProcessLost(BaseException):
    pass


class Trace:
    def __init__(self, cut=None, expected=()):
        self.cut = cut
        self.expected = expected
        self.points = []
        self.outcome = None
        self.failures = None

    def transaction(self, root, run, recover):
        def interrupt():
            self.failures = set(root.rglob("*.failure"))
            raise ProcessLost

        def instrument(publish):
            def wrapped(src, dst, *args, **kwargs):
                path = Path(dst)
                frame = sys._getframe(1)
                module = frame.f_globals["__name__"]
                if module not in ("store", "module_release.operation") or not path.is_relative_to(root):
                    return publish(src, dst, *args, **kwargs)
                while ((frame.f_globals["__name__"], frame.f_code.co_name) in {
                        ("store", "save_bytes"), ("store", "save"), ("module_release.operation", "record"),
                        ("module_release.operation", "confirm")}):
                    frame = frame.f_back
                writer = frame.f_globals["__name__"] + "." + frame.f_code.co_qualname
                # Fixture publishers simulate other owners (lease, supervisor, issuer).
                if path in (root / "lease", root / "status") and writer.startswith(("test_", "__main__.")):
                    return publish(src, dst, *args, **kwargs)
                parts = path.relative_to(root).parts
                name = "/".join("<plan>" if re.fullmatch("[a-f0-9]{64}", p) else p for p in parts)
                if re.fullmatch(r"book-[0-9a-f]{32}", path.name):
                    evidence = json.loads(Path(src).read_bytes())
                    name = name[:-32] + "<uuid>/" + evidence["operation"] + "-" + evidence["mode"]
                index = len(self.points)
                point = (name, writer)
                self.points.append(point)
                if self.cut and self.expected[index] != point:
                    raise AssertionError((index, self.expected[index], point))
                if self.cut == (index, "prima"):
                    interrupt()
                result = publish(src, dst, *args, **kwargs)
                if self.cut == (index, "dopo"):
                    interrupt()
                return result
            return wrapped

        try:
            with ExitStack() as patches:
                for method in ("link", "replace"):
                    patches.enter_context(patch.object(os, method, instrument(getattr(os, method))))
                outcome = run()
        except ProcessLost:
            if self.failures != set(root.rglob("*.failure")):
                raise AssertionError("process loss recorded an ordinary failure")
            outcome = recover()
        else:
            if self.cut:
                raise AssertionError(f"unreached interruption {self.cut}")
        if outcome not in ("RESUMED", "RETURNED") and not re.fullmatch(r"HELD [A-Z][A-Z0-9_/]*", outcome):
            raise AssertionError(f"unclassified outcome {outcome!r}")
        self.outcome = outcome


def sweep(scenario, expected=None):
    # The journal remains real. Only the simulated host's disk flush latency is elided.
    with ExitStack() as host:
        host.enter_context(patch.object(os, "fsync", lambda fd: None))
        ram = Path("/dev/shm")
        if sys.platform == "linux" and ram.is_dir() and os.access(ram, os.W_OK):
            host.enter_context(patch.object(tempfile, "tempdir", str(ram)))
        clean = Trace()
        scenario(clean)
        assert clean.points and clean.outcome in ("RESUMED", "RETURNED"), clean.outcome
        points = [[name, writer, side] for name, writer in clean.points for side in ("prima", "dopo")]
        if expected is not None:
            reviewed = [row[:3] for row in expected]
            if points != reviewed:
                mismatch = next((i for i, (a, b) in enumerate(zip(points, reviewed)) if a != b),
                                min(len(points), len(reviewed)))
                raise AssertionError(f"journal changed at row {mismatch + 1}: "
                                     f"observed {points[mismatch:mismatch+1]}, reviewed {reviewed[mismatch:mismatch+1]}")
        rows = []
        for index, (name, writer) in enumerate(clean.points):
            for side in ("prima", "dopo"):
                trace = Trace((index, side), clean.points)
                try:
                    scenario(trace)
                except Exception as exc:
                    raise AssertionError(f"{index + 1} {writer} {name} {side}") from exc
                rows.append([name, writer, side, *trace.outcome.split(" ", 1)])
        return rows
