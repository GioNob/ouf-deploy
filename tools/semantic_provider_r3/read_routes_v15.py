#!/usr/bin/env python3
"""Read the bound D-052 route source and public certificate as one R3 input."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.semantic_provider_r3 import compose as C, egress_v15 as E
from tools.semantic_provider_routes import custody, routes


ARGUMENTS = ('routes', 'routes-sha256', 'southbound-launch', 'southbound-launch-sha256',
             'southbound-policy', 'southbound-policy-sha256', 'adapter-launch', 'adapter-launch-sha256',
             'openssl', 'openssl-sha256')
CERT_LIMIT = 65536
PRIVATE_KEY = 'R3_ADAPTER_CERTIFICATE_PRIVATE_KEY'
CERT_INVALID = 'R3_ADAPTER_CERTIFICATE_SAN_UNPROVEN'
CERT_READ = 'R3_ADAPTER_CERTIFICATE_READ_DENIED'
OPENSSL = 'R3_ROUTES_OPENSSL_UNPROVEN'
DENIED = 'R3_ROUTES_READ_DENIED'
ARGUMENT_INVALID = 'R3_ROUTES_ARGUMENT_INVALID'
ROOT_REQUIRED = 'R3_ROUTES_LINUX_ROOT_REQUIRED'


def read_der(raw):
    """Iterate bounded DER TLVs at a known X.509 level."""
    offset = 0
    while offset < len(raw):
        C.require(len(raw) - offset >= 2, CERT_INVALID)
        tag, length = raw[offset:offset + 2]
        C.require(tag & 31 != 31, CERT_INVALID)
        start = offset + 2
        if length >= 128:
            count = length - 128
            C.require(1 <= count <= 3 and len(raw) >= start + count and raw[start] != 0, CERT_INVALID)
            length = int.from_bytes(raw[start:start + count], 'big')
            start += count
            C.require(length >= 128, CERT_INVALID)
        end = start + length
        C.require(end <= len(raw), CERT_INVALID)
        yield tag, raw[start:end]
        offset = end


def single_der(raw, tag):
    fields = list(read_der(raw))
    C.require(len(fields) == 1 and fields[0][0] == tag, CERT_INVALID)
    return fields[0][1]


def dns_sans(der):
    # Inspect the structured SAN extension. OpenSSL's rendered GeneralNames
    # are comma-separated and can contain commas inside non-DNS entries.
    certificate = list(read_der(single_der(der, 0x30)))
    C.require([tag for tag, _ in certificate] == [0x30, 0x30, 0x03], CERT_INVALID)
    wrappers = [value for tag, value in read_der(certificate[0][1]) if tag == 0xa3]
    C.require(len(wrappers) == 1, CERT_INVALID)
    extensions = single_der(wrappers[0], 0x30)
    san = []
    for tag, raw in read_der(extensions):
        C.require(tag == 0x30, CERT_INVALID)
        fields = list(read_der(raw))
        C.require([kind for kind, _ in fields] in ([0x06, 0x04], [0x06, 0x01, 0x04]), CERT_INVALID)
        if fields[0][1] == b'\x55\x1d\x11':  # id-ce-subjectAltName (2.5.29.17)
            san.append(fields[-1][1])
    C.require(len(san) == 1, CERT_INVALID)
    try:
        names = [value.decode('ascii') for tag, value in read_der(single_der(san[0], 0x30)) if tag == 0x82]
    except UnicodeError:
        raise C.A.OperationDenied(CERT_INVALID) from None
    C.require(names and all(E.dns_name(name) for name in names), CERT_INVALID)
    return sorted(set(names))


def bound_openssl(path, expected, certificate):
    """Decode exactly the verified byte stream using the pinned executable."""
    try:
        custody.executable(path, expected)
        try:
            process = subprocess.run([path, 'x509', '-inform', 'PEM', '-outform', 'DER'],
                input=certificate, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, env={'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'})
        finally:
            custody.executable(path, expected)
    except (routes.Held, OSError, subprocess.TimeoutExpired):
        raise C.A.OperationDenied(OPENSSL) from None
    C.require(process.returncode == 0 and 0 < len(process.stdout) <= CERT_LIMIT, CERT_INVALID)
    return dns_sans(process.stdout)


def observe(args, read=custody.read, extract=bound_openssl):
    bindings = []

    def verified(path, digest, code, **options):
        try:
            return read(path, digest, **options)
        except (routes.Held, OSError):
            raise C.A.OperationDenied(code) from None

    def bound(path, digest, code, **options):
        raw = verified(path, digest, code, **options)
        bindings.append((path, digest, code, options))
        return raw

    def recipe(name, code):
        raw = bound(getattr(args, name), getattr(args, name + '_sha256'), code)
        return C.document(raw, code)

    def source(row, limit, code):
        return bound(row['source'], row['sha256'], code,
                     metadata=(row['uid'], row['gid'], row['mode']), limit=min(limit, row['maxBytes']))

    launch = E.source_entry(recipe('southbound_launch', E.CONFIG))
    policy = E.source_entry(recipe('southbound_policy', E.CONFIG))
    C.require(launch == policy and (args.routes, args.routes_sha256) == (policy['source'], policy['sha256']), E.CONFIG)
    raw = source(policy, routes.MAX_BYTES, E.CONFIG)
    try:
        projection = routes.project(args.routes, raw)
    except routes.Held:
        raise C.A.OperationDenied(E.CONFIG) from None
    entry = E.source_entry(recipe('adapter_launch', CERT_READ), certificate=True)
    certificate = source(entry, CERT_LIMIT, CERT_READ)
    C.require(b'PRIVATE KEY' not in certificate, PRIVATE_KEY)
    C.require(re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+'
                           rb'-----END CERTIFICATE-----(?:\r?\n)?', certificate), CERT_INVALID)
    names = extract(args.openssl, args.openssl_sha256, certificate)
    projection['adapterTlsIdentity'] = {'certificateSha256': entry['sha256'], 'dnsNames': names}
    for path, digest, code, options in bindings:
        verified(path, digest, code, **options)
    return projection


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise C.A.OperationDenied(ARGUMENT_INVALID)


def main(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    for flag in ARGUMENTS:
        parser.add_argument('--' + flag, required=True)
    try:
        args = parser.parse_args(argv)
        C.require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0, ROOT_REQUIRED)
        C.require(all(E.SHA256.fullmatch(value) for name, value in vars(args).items() if name.endswith('_sha256')),
                  ARGUMENT_INVALID)
        sys.stdout.buffer.write(C.canonical(observe(args)) + b'\n')
        return 0
    except C.A.OperationDenied as error:
        public = {E.CONFIG, E.TLS, PRIVATE_KEY, CERT_INVALID, CERT_READ, OPENSSL, ARGUMENT_INVALID, ROOT_REQUIRED}
        print(error.args[0] if error.args and error.args[0] in public else DENIED, file=sys.stderr)
    except Exception:
        print(DENIED, file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
