#!/usr/bin/python3
"""Root entry for the authenticated complete preparation source capsule."""
import argparse
from pathlib import Path
import sys

parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--source-directory',required=True)
args,_=parser.parse_known_args()
root=Path(args.source_directory)
if not root.is_absolute() or root.resolve()!=root or Path(__file__).resolve()!=root/'scripts/install-chatbot-file-cohort.py':
    raise SystemExit('EXACT_QUALIFIED_PREPARATION_ROOT_REQUIRED')
sys.path[:0]=[str(root),str(root/'tools/semantic_cohort_admission/cohort-draft'),
    *[str(root/'tools'/name) for name in ('semantic_policy_token_owner','semantic_application_cutover',
                                        'semantic_database_cutover','semantic_frame_compiler')]]
from tools.chatbot_file_cohort.entry import main
main()
