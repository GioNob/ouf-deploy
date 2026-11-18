"""Preflight for the existing v5.1 acceptance issuer, with pinned g7 inputs."""
import argparse
from pathlib import Path
import os
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.semantic_provider_config import contract as D
from tools.semantic_provider_routes import custody as C, publication as P
from tools.semantic_provider_routes.routes import Held, canonical, decode, require


def validate(recipes, profile, profile_sha, rootfs_binding):
    require(recipes.get('schema') == 'ouf.semantic-provider-b1-recipes.v1'
            and recipes.get('status') == 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED'
            and type(recipes.get('recipeRevision')) is int and recipes['recipeRevision'] == 4,
            'ACCEPTANCE_G7_B1_V4_REQUIRED')
    require(recipes.get('rootfs') == rootfs_binding, 'ACCEPTANCE_G7_D042_REQUIRED')
    require(recipes.get('installationProfile') == P.binding(D.PROFILE_PATH, profile_sha),
            'ACCEPTANCE_G7_PROFILE_MISMATCH')
    D.declaration(profile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recipes')
    parser.add_argument('recipes_sha256')
    parser.add_argument('profile_sha256')
    parser.add_argument('rootfs')
    parser.add_argument('rootfs_sha256')
    args = parser.parse_args()
    try:
        require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0, 'ROOT_CUSTODY_REQUIRED')
        require(all(D.SHA256.fullmatch(value) for value in
                    (args.recipes_sha256, args.profile_sha256, args.rootfs_sha256)), 'EXACT_SHA256_REQUIRED')
        recipes = decode(C.read(args.recipes, args.recipes_sha256))
        raw = C.read(D.PROFILE_PATH, args.profile_sha256)
        profile = decode(raw)
        require(raw == canonical(profile) + b'\n', 'ACCEPTANCE_G7_PROFILE_MISMATCH')
        rootfs = decode(C.read(args.rootfs, args.rootfs_sha256))
        require(rootfs['rule'] == 'D-042', 'ACCEPTANCE_G7_D042_REQUIRED')
        validate(recipes, profile, args.profile_sha256, P.binding(args.rootfs, args.rootfs_sha256))
    except (Held, OSError, ValueError, TypeError, KeyError) as error:
        print(P.public_error(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
