"""Sealed supplementary-ledger operator, preserving the original auth graph."""
from pathlib import Path
from tools.governed_human_successor import auth_delivery

ENTRY='tools.governed_human_successor.supplementary'
BOOTSTRAP=auth_delivery.BOOTSTRAP.replace(
    "('open-window','step','status','reconcile-read')", "('prepare','open-window','step','status')").replace(
    "(sys.argv[1]=='open-window')", "(sys.argv[1]in('prepare','open-window'))").replace(
    "sys.modules.get('tools.governed_human_successor.operator')", "sys.modules.get(DECLARATION['entryModule'])").replace(
    "'ouf.human-explicit-successor-operator-result.v1'", "'ouf.human-supplementary-ledger-result.v1'")


def generate(root,case):
    extra={'.'.join(p.with_suffix('').parts):str(p)for p in (
        Path('tools/ingestion_rollout_preparation')/n for n in (
            'iam_lifetime_policy.py','iam_explicit_api.py','iam_policy_read.py','human_timing.py'))}
    return auth_delivery.generate(root,case,{},entry=ENTRY,bootstrap=BOOTSTRAP,extra_paths=extra)
