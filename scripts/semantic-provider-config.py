#!/usr/bin/env python3
"""Governed adapter configuration publication and B1 v4 preparation."""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_config import b1_v4, contract as D, observation as O, publication as Q
from tools.semantic_provider_routes import publication as P


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    operations = parser.add_subparsers(dest='operation', required=True)
    publication = operations.add_parser('publish', allow_abbrev=False)
    publication.add_argument('mode', choices=('plan', 'apply', 'restore'))
    publication.add_argument('filename', choices=Q.FILES)
    publication.add_argument('--old-sha256', required=True)
    recipes = operations.add_parser('b1', allow_abbrev=False)
    recipes.add_argument('mode', choices=('plan', 'apply'))
    recipes.add_argument('--publication-sha256', required=True)
    recipes.add_argument('--previous-recipes-sha256', required=True)
    for command in (publication, recipes):
        command.add_argument('--r3-version', type=int, required=True)
        for pin in (*O.RUNTIME_PINS, 'profile_sha256'):
            command.add_argument('--' + pin.replace('_', '-'), required=True)
        command.add_argument('--plan-sha256')
    args = parser.parse_args(argv)
    if ((args.mode != 'plan') != (args.plan_sha256 is not None)
            or any(not D.SHA256.fullmatch(value) for key, value in vars(args).items()
                   if key.endswith('_sha256') and value is not None)):
        parser.error('expected exact SHA-256 bindings and a plan pin for apply/restore')
    progress = {}
    schema = Q.SCHEMA if args.operation == 'publish' else b1_v4.SCHEMA
    try:
        D.require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
                  and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077)
        result = (Q.execute(args.mode, args.filename, args, progress=progress) if args.operation == 'publish'
                  else b1_v4.execute(args.mode, args, progress=progress))
        print(D.canonical({'schema': schema, **P.FLAGS, **result}).decode(), flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(D.canonical({'schema': schema, 'status': 'PARTIAL' if any(progress.values()) else 'HELD',
                           'reason': P.public_error(error), **progress, **P.FLAGS}).decode(), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
