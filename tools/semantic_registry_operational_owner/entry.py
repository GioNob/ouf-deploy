"""Worker-only entry; cannot install, issue authority, initialize or reset state."""
import argparse
import re
from .core import require, Denied, encoded
from .service import run


def main(argv=None):
    parser=argparse.ArgumentParser(description='Installed Registry credential owner')
    parser.add_argument('--configuration',required=True)
    parser.add_argument('--configuration-sha256',required=True)
    args=parser.parse_args(argv)
    require(len(args.configuration_sha256)==64
            and set(args.configuration_sha256)<=set('0123456789abcdef'),
            'PINNED_OPERATIONAL_CONFIGURATION_REQUIRED')
    run(args.configuration,args.configuration_sha256)


def execute(argv=None):
    try:
        main(argv)
        return 0
    except (Exception,KeyboardInterrupt) as error:
        # Never print an arbitrary transport error/traceback: those may contain
        # endpoint names or confidential request values. Detailed state remains
        # in the protected ledger; no success or no-effect claim is invented.
        reason=str(error) if isinstance(error,Denied) else 'OPERATIONAL_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:
            reason='OPERATIONAL_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        print(encoded({'schema':'ouf.registry-operational-token-exit.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'outcomeRequiresReconciliation':True,'automaticReplayAllowed':False,
            'releaseAcceptance':False}).decode(),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(execute())
