#!/usr/bin/env python3
"""Run a read-only SQL file against an OUF database on the VPS.

The remote command matches, byte for byte, the sudoers rule documented in
tools/ops_kit/README.md; any change to it makes sudo ask for a password.
Variables are passed as psql \\set lines prepended to the SQL, so the remote
command line never changes.
"""
import argparse
import os
import subprocess
import sys

DATABASES = ("ouf_onboarding", "ouf_udp")
PSQL = ("sudo -n /usr/bin/docker exec -i -e PGOPTIONS=-cdefault_transaction_read_only=on ouf-postgres "
        "psql -X -w -q -P pager=off -v ON_ERROR_STOP=1 -h /var/run/postgresql -U {db} -d {db}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True, choices=DATABASES)
    parser.add_argument("--sql", required=True, help="SQL file; must contain BEGIN READ ONLY ... ROLLBACK")
    parser.add_argument("--var", action="append", default=[], metavar="NAME=VALUE",
                        help="psql variable, referenced in the SQL as :'NAME'")
    parser.add_argument("--host", default=os.environ.get("OUF_VPS", "oufadmin@62.83.33.202"))
    parser.add_argument("--out", help="write output here (UTF-8) instead of stdout")
    args = parser.parse_args()

    sql = open(args.sql, "rb").read().replace(b"\r", b"").decode("utf-8")
    if "BEGIN READ ONLY" not in sql or "ROLLBACK" not in sql:
        sys.exit("refusing to run: SQL must be wrapped in BEGIN READ ONLY ... ROLLBACK")
    header = []
    for item in args.var:
        name, sep, value = item.partition("=")
        if not sep or not name.isidentifier():
            sys.exit(f"invalid --var {item!r}")
        header.append(f"\\set {name} '{value.replace(chr(39), chr(39) * 2)}'")
    payload = ("\n".join(header) + "\n" + sql).encode("utf-8")

    result = subprocess.run(["ssh", "-o", "BatchMode=yes", args.host, PSQL.format(db=args.db)],
                            input=payload, capture_output=True)
    text = result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
