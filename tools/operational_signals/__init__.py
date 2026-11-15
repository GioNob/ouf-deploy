"""Public operational snapshots; no lifecycle or authority mutations."""
import os
import re
import stat
import tempfile

from tools.semantic_authority_mandates import mandates as M

LIMIT = 16384
CODE = re.compile(r"[A-Z0-9_]{1,80}")


class SignalError(RuntimeError):
    """An explicitly public diagnostic, never input contents."""


def require(ok, code):
    if not ok:
        raise SignalError(code)


def public(error):
    if type(error).__name__ in {"SignalError", "MandateDenied", "OperationDenied", "Denied", "Held",
                                "AuthorityDenied", "AcceptanceDenied", "ConsumptionDenied"}:
        value = str(error)
        if CODE.fullmatch(value):
            return value
    if type(error).__name__ == "TransactionDenied":
        value = getattr(error, "diagnosis", {}).get("reason")
        if type(value) is str and CODE.fullmatch(value):
            return value
    return "OPERATIONAL_SIGNAL_READ_UNPROVEN"


def status_directory(path):
    path = M.absolute(str(path))
    M.ancestors(path)
    M.directory(path.parent)
    return path


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def seal_status(fd):
    os.fchmod(fd, 0o600)
    os.fchown(fd, 0, 0)
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            "OPERATIONAL_STATUS_CUSTODY_REQUIRED")


def atomic_status(path, value):
    """Only our temporary and destination file are ever written; no mkdir/chmod of inputs."""
    raw = M.canonical(value)
    require(len(raw) <= LIMIT, "OPERATIONAL_STATUS_TOO_LARGE")
    path = status_directory(path)
    # The trusted parent cannot be replaced by an unprivileged writer.
    parent = M.attributes(path.parent.lstat())
    fd, temporary = tempfile.mkstemp(prefix=".status-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            seal_status(stream.fileno())
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Creating the temporary changes directory timestamps, so compare stable fields only.
        require(M.attributes(path.parent.lstat())[:6] == parent[:6], "OPERATIONAL_STATUS_DIRECTORY_CHANGED")
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
