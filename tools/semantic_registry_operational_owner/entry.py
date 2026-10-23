"""Worker-only entry; cannot install, issue authority, initialize or reset state."""
import argparse
from .core import require
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


if __name__=='__main__':main()
