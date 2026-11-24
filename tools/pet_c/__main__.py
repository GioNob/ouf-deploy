"""CLI offline del PET C. I trasporti verso gli owner sono esterni al pacchetto."""

import argparse
import asyncio
import sys
from pathlib import Path

from . import load, simulator
from .manifest import Refusal, canonical, digest, parse, validate
from .measures import measure
from .report import markdown, read_traces, report
from .scenarios import plan


def parser():
    root = argparse.ArgumentParser(prog="python -B -m tools.pet_c")
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan", "simulate", "load", "measure", "report"):
        p = sub.add_parser(name)
        p.add_argument("manifest", type=Path)
        if name in ("simulate", "load", "measure", "report"):
            p.add_argument("traces", type=Path)
        if name == "simulate":
            p.add_argument("--scenario", default="55n-06")
            p.add_argument("--address", required=True)
            p.add_argument("--port", type=int, required=True)
            p.add_argument("--search-path", default="/search")
            p.add_argument("--fetch-path", default="/fetch")
        if name == "load":
            p.add_argument("--waves", type=int, default=1)
        if name == "report":
            p.add_argument("--also", nargs=2, action="append", default=[], type=Path,
                           metavar=("MANIFEST", "JSONL"))
            p.add_argument("--format", choices=("json", "markdown"), default="json")
    return root


def read_manifest(path):
    return validate(parse(path.read_bytes()))


def run(args):
    manifest = read_manifest(args.manifest)
    command = args.command
    if command == "validate":
        return "VALID"
    if command == "plan":
        return plan(manifest)
    if command == "measure":
        return canonical(measure(manifest, read_traces(args.traces.read_bytes(), manifest))).decode()
    if command == "report":
        bundles = [(manifest, args.traces.read_bytes())]
        bundles.extend((read_manifest(m), t.read_bytes()) for m, t in args.also)
        document = report(bundles)
        return markdown(document) if args.format == "markdown" else canonical(document).decode()

    scenario = getattr(args, "scenario", "55n-06")
    if scenario not in manifest["scenarios"] or manifest["provider"]["mode"] != "simulator":
        raise Refusal("SIMULATOR_SCOPE_REQUIRED")
    labels = dict(runId=manifest["runId"], site=manifest["site"], scenario=scenario,
                  manifestSha256=digest(canonical(manifest)))
    if command == "load":
        labels["transport"] = "fake"
        calendar = load.schedule(manifest, args.waves)
    with args.traces.open("xb") as stream:
        def emit(event):
            stream.write(canonical(dict(event, **labels)) + b"\n")
            stream.flush()

        if command == "load":
            asyncio.run(load.execute(calendar, load.FakeTransport(), emit))
        else:
            provider = simulator.Provider(manifest["provider"], manifest["capacity"], emit)
            with simulator.server(args.address, args.port, provider,
                                  args.search_path, args.fetch_path) as service:
                try:
                    service.serve_forever()
                except KeyboardInterrupt:
                    pass
    return "OK"


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        message = run(args)
        is_json = args.command == "measure" or (args.command == "report" and args.format == "json")
        sys.stdout.buffer.write(message.rstrip("\n").encode("utf-8") + (b"" if is_json else b"\n"))
        return 0
    except Refusal as error:
        print(str(error), file=sys.stderr)
    except (OSError, KeyError, ValueError, TypeError, OverflowError, RecursionError):
        print("INVALID_INPUT_OR_IO", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
