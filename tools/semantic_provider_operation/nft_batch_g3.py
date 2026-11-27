"""Linux nf_tables UAPI for the sealed refresh compiler's two set operations.

NFNL_BATCH_GENID makes handle verification and a later name-based set update
one optimistic transaction. A generation conflict must never be retried here.
"""
from contextlib import contextmanager
import errno
import ipaddress
import re
import socket
import struct

from tools.semantic_lease_kernel_migration.boot_dispatcher import need


# linux/netfilter/{nfnetlink,nf_tables}.h and linux/netlink.h
NFTABLES = 10
NEWSETELEM, DELSETELEM, NEWGEN, GETGEN = (NFTABLES << 8 | op for op in (12, 14, 15, 16))
BATCH_BEGIN, BATCH_END = 16, 17
REQUEST, ACK, CREATE = 1, 4, 0x400
NESTED = 0x8000
FAMILIES = {'inet': 1, 'bridge': 7}
HEADER = struct.Struct('=IHHII')
ATTRIBUTE = struct.Struct('=HH')
FORMAT = 'G3_NFT_BATCH_FORMAT'
CONFLICT = 'G3_NFT_GENERATION_CHANGED'


def attr(kind, data):
    length = ATTRIBUTE.size + len(data)
    return ATTRIBUTE.pack(length, kind) + data + bytes(-length % 4)


def message(kind, flags, sequence, family=0, subsystem=0, attrs=b''):
    body = struct.pack('!BBH', family, 0, subsystem) + attrs
    return HEADER.pack(HEADER.size + len(body), kind, flags, sequence, 0) + body


def responses(sock):
    packet, _, flags, peer = sock.recvmsg(65536)
    need(packet and peer == (0, 0) and not flags & socket.MSG_TRUNC, FORMAT)
    offset = 0
    while offset < len(packet):
        length, kind, _, sequence, _ = HEADER.unpack_from(packet, offset)
        need(HEADER.size <= length <= len(packet) - offset, FORMAT)
        body = packet[offset + HEADER.size:offset + length]
        if kind == 2:  # NLMSG_ERROR also carries successful ACKs.
            error, = struct.unpack_from('=i', body)
            if error in (-errno.ERESTART, -errno.EAGAIN):
                raise ValueError(CONFLICT)
            if error:
                raise OSError(-error, 'G3_NFT_BATCH_FAILED')
        yield kind, sequence, body
        offset += (length + 3) & ~3


def generation(sock):
    sock.sendto(message(GETGEN, REQUEST, 1), (0, 0))
    for kind, sequence, body in responses(sock):
        need(kind == NEWGEN and sequence == 1, FORMAT)
        offset = 4  # nfgenmsg
        while offset < len(body):
            size, key = ATTRIBUTE.unpack_from(body, offset)
            need(4 <= size <= len(body) - offset, FORMAT)
            if key & 0x3fff == 1:  # NFTA_GEN_ID, network byte order
                need(size == 8, FORMAT)
                value, = struct.unpack_from('!I', body, offset + 4)
                need(value != 0, FORMAT)  # zero disables the kernel comparison
                return value
            offset += (size + 3) & ~3
    raise ValueError(FORMAT)


def set_operation(line, table, sequence):
    command = re.fullmatch(r'(flush set|add element) (inet|bridge) ([\w-]+) (provider_[0-9]+)(.*)', line,
                           re.ASCII)
    need(command and command[3] == table, FORMAT)
    verb, family, _, name, suffix = command.groups()
    # NFTA_SET_ELEM_LIST_TABLE, _SET, and (for adds) _ELEMENTS.
    attrs = attr(1, table.encode('ascii') + b'\0') + attr(2, name.encode('ascii') + b'\0')
    if verb == 'flush set':
        need(not suffix, FORMAT)
        return message(DELSETELEM, REQUEST | ACK, sequence, FAMILIES[family], attrs=attrs)
    need(suffix.startswith(' { ') and suffix.endswith(' }'), FORMAT)
    elements = []
    for item in suffix[3:-2].split(', '):
        match = re.fullmatch(r'([0-9a-fA-F:.]+) timeout ([1-9][0-9]*)s', item)
        need(match, FORMAT)
        address = ipaddress.ip_address(match[1]).packed
        timeout = struct.pack('!Q', int(match[2]) * 1000)
        key = attr(1 | NESTED, attr(1, address))  # NFTA_SET_ELEM_KEY / NFTA_DATA_VALUE
        elements.append(attr(1 | NESTED, key + attr(4, timeout)))
    attrs += attr(3 | NESTED, b''.join(elements))
    return message(NEWSETELEM, REQUEST | ACK | CREATE, sequence, FAMILIES[family], attrs=attrs)


def submit(sock, expected, table, transaction):
    begin = message(BATCH_BEGIN, REQUEST, 2, subsystem=NFTABLES,
                    attrs=attr(1, struct.pack('!I', expected)))  # NFNL_BATCH_GENID
    rows = [set_operation(line, table, i) for i, line in enumerate(transaction.splitlines(), 3)]
    need(rows and expected != 0, FORMAT)
    end = message(BATCH_END, REQUEST, 3 + len(rows), subsystem=NFTABLES)
    sock.sendto(b''.join((begin, *rows, end)), (0, 0))
    pending = set(range(3, 3 + len(rows)))
    while pending:
        for kind, sequence, _ in responses(sock):
            need(kind == 2 and sequence in pending, FORMAT)
            pending.remove(sequence)


@contextmanager
def guarded_batch():
    # One unicast socket in the same network namespace as the nft reader.
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:  # NETLINK_NETFILTER
        sock.settimeout(3)
        expected = generation(sock)
        yield lambda table, transaction: submit(sock, expected, table, transaction)
