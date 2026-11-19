#!/usr/bin/env python3
"""Read the bound adapter.json and emit its public projection as canonical JSON."""
import argparse
import os
from pathlib import Path
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.semantic_provider_config import contract as D
from tools.semantic_provider_routes import custody as C
from tools.semantic_provider_routes.routes import Held


ARGUMENTS = ('adapter-launch', 'adapter-launch-sha256', 'adapter-policy', 'adapter-policy-sha256')


def observe(args, *, read=C.read):
    inputs = [(getattr(args, name), getattr(args, name + '_sha256'))
              for name in ('adapter_launch', 'adapter_policy')]
    recipes = [read(path, pin) for path, pin in inputs]
    launch, policy = [D.source_entry(D.decode(raw)) for raw in recipes]
    D.require(launch == policy, 'ADAPTER_CONFIG_RECIPE_BINDING_MISMATCH')
    source, pin, limit = launch['source'], launch['sha256'], launch['maxBytes']
    raw = read(source, pin, metadata=D.METADATA, limit=limit)
    result = D.project(source, raw)
    D.require(result['sha256'] == pin, 'ADAPTER_CONFIG_RECIPE_BINDING_MISMATCH')
    D.require([read(path, digest) for path, digest in inputs] == recipes
              and read(source, pin, metadata=D.METADATA, limit=limit) == raw, 'ADAPTER_CONFIG_CHANGED')
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Held('ADAPTER_PROJECTION_ARGUMENT_INVALID')


def main(argv=None):
    parser = Parser(description=__doc__)
    for flag in ARGUMENTS:
        parser.add_argument('--' + flag, required=True)
    try:
        args = parser.parse_args(argv)
        D.require(all(D.SHA256.fullmatch(getattr(args, key)) for key in
                      ('adapter_launch_sha256', 'adapter_policy_sha256')), 'ADAPTER_PROJECTION_ARGUMENT_INVALID')
        D.require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
                  and sys.flags.isolated and sys.dont_write_bytecode, 'ADAPTER_PROJECTION_ISOLATED_ROOT_REQUIRED')
        sys.stdout.buffer.write(D.canonical(observe(args)) + b'\n')
    except (Held, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(str(error) if isinstance(error, Held) else 'ADAPTER_PROJECTION_READ_DENIED', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
