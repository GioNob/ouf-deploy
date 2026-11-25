"""DEP-60w. Run from the executor checkout as root on a controlling terminal.

python3 -I -B scripts/read_installation_active.py --profile /opt/ouf-a2/profile.json

--installation-id and --origin override the corresponding profile fields.
If gateway.values lacks the literal key "gateway.publicApiHost", pass --origin.
Enter the trusted HTTPS issuer (including realm path), HUMAN subject and tenant
when prompted on /dev/tty, complete the device login and acknowledge it there.
HumanSession supplies its existing ouf-human-admin client, ouf-api-gateway
audience, SCOPES and finite login window. The owner checks read/export grants.
HumanSession writes its 0600 recovery journal as well as human-access.jwt in
the command's temporary 0700 directory. Both are removed before reporting.
"""
import argparse
from contextlib import closing
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

# Isolated Python omits the checkout. HumanSession and the executor's profile
# reader also have sibling imports, resolved from this same checkout.
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools/semantic_policy_token_owner"),
                str(ROOT / "tools/semantic_application_cutover"),
                str(ROOT / "tools/semantic_cohort_admission/cohort-draft"),
                str(ROOT / "tools/privileged_executor")]


class ReadError(Exception):
    """Only fixed public outcome codes reach the command boundary."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ReadError("TRANSPORT_ERROR")


def target(args):
    installation, origin = args.installation_id, args.origin
    if installation is None or origin is None:
        from tools.privileged_executor.store import read
        gateway = read(args.profile)["gateway"]
        values = gateway.get("values", {})
        if installation is None:
            installation = values.get("installationId")
        if origin is None:
            if "gateway.publicApiHost" not in values:
                print('Nel profilo manca gateway.values["gateway.publicApiHost"]. '
                      'Specificare --origin.', file=sys.stderr)
                raise ReadError("TRANSPORT_ERROR")
            host = values["gateway.publicApiHost"]
            if not isinstance(host, str) or "/" in host:
                raise ReadError("TRANSPORT_ERROR")
            origin = "https://" + host
    if (not isinstance(installation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", installation)
            or installation in (".", "..")):
        raise ReadError("TRANSPORT_ERROR")
    if not re.fullmatch(r"https://(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])(?::[0-9]+)?/?", origin):
        raise ReadError("TRANSPORT_ERROR")
    address = urlsplit(origin)
    if address.port == 0:
        raise ReadError("TRANSPORT_ERROR")
    return installation, address


def login(directory):
    from tools.chatbot_file_cohort.human_session import HumanSession, PROFILE

    with open("/dev/tty", "r", encoding="utf-8") as answers, open(
            "/dev/tty", "w", encoding="utf-8", buffering=1) as terminal:
        def ask(prompt):
            print(prompt, file=terminal, flush=True)
            answer = answers.readline().strip()
            if not answer:
                raise ReadError("TRANSPORT_ERROR")
            return answer

        selection = {key: ask(prompt) for key, prompt in (
            ("issuer", "Issuer HTTPS del login HUMAN (incluso il percorso del realm)"),
            ("subject", "Subject atteso del HUMAN"), ("tenant", "Tenant atteso del HUMAN"))}
        path = directory / "human-access.jwt"
        session = HumanSession(selection, directory, path,
                               int(time.time()) + PROFILE["maximumElapsedSeconds"])
        session.login(emit=lambda line: print(line, file=terminal),
                      confirm_browser=lambda _: ask("Dopo il login nel browser digita OK.") == "OK")
        session.current()
        return path.read_text(encoding="ascii")


def get(connection, path, token, *, projection=False):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "X-Correlation-ID": str(uuid.uuid4())}
    with closing(connection()) as client:
        client.request("GET", path, headers=headers)
        with client.getresponse() as response:
            if response.status in (401, 403):
                raise ReadError(f"HTTP_{response.status}")
            if projection and response.status == 409:
                raise ReadError("PROJECTION_NOT_ACTIVE")
            if response.status != 200:
                raise ReadError("TRANSPORT_ERROR")
            if projection:
                digest = hashlib.sha256()
                while chunk := response.read(65536):
                    digest.update(chunk)
                if response.length:
                    raise ReadError("TRANSPORT_ERROR")
                return response.status, digest.hexdigest()
            raw = response.read(16385)
            if len(raw) > 16384 or response.length:
                raise ReadError("TRANSPORT_ERROR")
            try:
                active = json.loads(raw)
            except (ValueError, RecursionError):
                pass
            else:
                return active, response.getheader("ETag")
            # Raise outside the handler so the decoder and its document are released.
            del raw
            raise ReadError("TRANSPORT_ERROR") from None


def active_fields(active, installation):
    revision, checksum, generation = (active[k] for k in ("revision", "checksum", "generation"))
    if (active["installationId"] != installation
            or not all(type(n) is int and 1 <= n < 2**63 for n in (revision, generation))
            or not re.fullmatch("[0-9a-f]{64}", checksum)):
        raise ReadError("TRANSPORT_ERROR")
    return revision, checksum, generation


def read_active(installation, connection, token):
    base = f"/api/trusted-human/v1/installations/{installation}"
    active, etag = get(connection, base + "/active", token)
    revision, checksum, generation = active_fields(active, installation)
    if etag != f'"{revision}:{checksum}:{generation}"':
        raise ReadError("TRANSPORT_ERROR")
    status, digest = get(connection, f"{base}/projection?revision={revision}", token, projection=True)
    last, last_etag = get(connection, base + "/active", token)
    if last_etag != etag or active_fields(last, installation) != (revision, checksum, generation):
        raise ReadError("ACTIVE_CHANGED")
    return {"revision": revision, "checksum": checksum, "generation": generation,
            "etag": etag, "projection_http": status, "projection_sha256": digest}


def main(argv=None):
    parser = Parser(description="Legge la revisione ACTIVE da Onboarding con un login HUMAN.")
    parser.add_argument("--installation-id")
    parser.add_argument("--origin")
    parser.add_argument("--profile", type=Path, default=Path("/opt/ouf-a2/profile.json"))
    try:
        args = parser.parse_args(argv)
        if os.geteuid() != 0:
            raise ReadError("TRANSPORT_ERROR")
        installation, address = target(args)
        # /run has the root-owned, non-writable ancestry required by HumanSession.
        temporary = tempfile.TemporaryDirectory(dir="/run", prefix="ouf-active-")
        try:
            token = login(Path(temporary.name))
            result = read_active(installation, lambda: http.client.HTTPSConnection(
                address.hostname, address.port, timeout=5), token)
        finally:
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                temporary.cleanup()
            finally:
                signal.signal(signal.SIGINT, previous)
        print(*(f"{key}={value}" for key, value in result.items()), "ACTIVE_READ_OK", sep="\n")
        return 0
    except ReadError as error:
        print(error)
    except (Exception, KeyboardInterrupt):
        # Transport, parser and login exceptions may contain private data.
        print("TRANSPORT_ERROR")
    return 1


if __name__ == "__main__":
    sys.exit(main())
