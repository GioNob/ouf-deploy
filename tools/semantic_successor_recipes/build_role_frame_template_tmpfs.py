"""Retain the baseline tmpfs verbatim in the Engine's ordered user mounts.

The historical builder groups every non-bind mount with Engine defaults. A
role tmpfs belongs to the ordered user mounts instead. All other substitutions
and validation still use the historical builder and compile_policy unchanged.
This module neither authenticates its inputs nor authorizes a target start.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'semantic_frame_compiler'))

from build_role_frame_template import build_role_template as build_historical
from compile_creation_frame_policy import canonical, require


def build_role_template(template, baseline_launch, launch, approved_user, *, mount_ordering):
    """Support only an explicitly declared, unchanged baseline role tmpfs.

    manifest.tmpfs contains Docker request strings, not reconstructed OCI
    options. The corresponding OCI mount is copied only from the baseline.
    System tmpfs mounts such as /dev and /dev/shm remain Engine defaults.
    """
    require(mount_ordering == 'depth-path', 'TMPFS_DEPTH_PATH_ORDER_REQUIRED')
    baseline_tmpfs = baseline_launch.get('manifest', {}).get('tmpfs')
    require(type(baseline_tmpfs) is dict and len(baseline_tmpfs) == 1
            and all(type(k) is str and type(v) is str and v
                    for k, v in baseline_tmpfs.items()), 'TMPFS_BASELINE_DECLARATION_REQUIRED')
    require(type(launch) is dict and type(launch.get('manifest')) is dict
            and canonical(launch['manifest'].get('tmpfs')) == canonical(baseline_tmpfs),
            'TMPFS_LAUNCH_DRIFT')
    targets = set(baseline_tmpfs)
    mounts = template['expectedOci']['mounts']
    role_tmpfs = [m for m in mounts if m.get('destination') in targets]
    require(len(role_tmpfs) == len(targets)
            and {m['destination'] for m in role_tmpfs} == targets
            and all(m.get('type') == 'tmpfs' and m.get('source') == 'tmpfs'
                    and type(m.get('options')) is list for m in role_tmpfs),
            'TMPFS_BASELINE_MOUNT_REQUIRED')
    result = build_historical(template, baseline_launch, launch, approved_user,
                              mount_ordering=mount_ordering)
    retained = result['expectedOci']['mounts']
    defaults = [m for m in retained if m['type'] != 'bind' and m['destination'] not in targets]
    ordered = [m for m in retained if m['type'] == 'bind' or m['destination'] in targets]
    ordered.sort(key=lambda m: (m['destination'].count('/'), m['destination']))
    result['expectedOci']['mounts'] = defaults + ordered
    return result
