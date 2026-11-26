"""DEP-60w. Run from the executor checkout as root on a controlling terminal.

python3 -I -B scripts/read_installation_active.py --profile /opt/ouf-a2/profile.json

--installation-id and --origin override the corresponding profile fields.
If gateway.values lacks the literal key "gateway.publicApiHost", pass --origin.
--issuer, --subject and --tenant pin the expected HUMAN identity. The issuer
defaults to gateway.values["gateway.issuerUrl"], and queue.subjectTenants maps
a selected subject to its tenant. Only missing identity fields require /dev/tty
input. Complete the login in the browser while HumanSession polls automatically.
HumanSession supplies its existing ouf-human-admin client, ouf-api-gateway
audience, SCOPES and finite login window. The owner checks read/export grants.
HumanSession writes its 0600 recovery journal as well as human-access.jwt in
the command's temporary 0700 directory. Both are removed before reporting.
"""
import argparse
import base64
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
        raise ReadError("INPUT_MISSING:arguments")


def load_profile(args):
    from tools.privileged_executor.store import read
    from mandate import Held

    if all(value is not None for value in (args.installation_id, args.origin, args.issuer, args.tenant)):
        return {}
    try:
        profile = read(args.profile)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError, Held):
        pass
    else:
        if isinstance(profile, dict):
            return profile
    raise ReadError("INPUT_MISSING:profile")


def target(args, values):
    installation = args.installation_id if args.installation_id is not None else values.get("installationId")
    if (not isinstance(installation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", installation)
            or installation in (".", "..")):
        raise ReadError("INPUT_MISSING:installation-id")
    origin = args.origin
    if origin is None:
        host = values.get("gateway.publicApiHost")
        if not isinstance(host, str) or not host or "/" in host:
            print('Specificare --origin oppure gateway.values["gateway.publicApiHost"].', file=sys.stderr)
            raise ReadError("INPUT_MISSING:origin")
        origin = "https://" + host
    if re.fullmatch(r"https://(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])(?::[0-9]+)?/?", origin):
        try:
            address = urlsplit(origin)
            if address.port != 0:
                return installation, address
        except ValueError:
            pass
    raise ReadError("INPUT_MISSING:origin")


def identity_field(field, value):
    if value is None or isinstance(value, str) and not value.strip():
        try:
            with open("/dev/tty", "w", encoding="utf-8") as terminal:
                print(f"Specificare {field} per il login HUMAN:", file=terminal, flush=True)
            with open("/dev/tty", "r", encoding="utf-8") as answers:
                value = answers.readline().strip()
        except (OSError, UnicodeError):
            pass
    if not isinstance(value, str) or not value.strip():
        raise ReadError(f"INPUT_MISSING:{field}")
    return value


def rejected_claim_phase(token, selection):
    # HumanSession has already parsed this JWT and rejected its context. This
    # read only disambiguates its combined guard and can never accept a bearer.
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    if claims.get("sub") != selection["subject"]:
        return "subject"
    if claims.get("tenant_id") != selection["tenant"]:
        return "tenant"
    expiry = claims.get("exp")
    return "expired" if type(expiry) in (int, float) and expiry <= time.time() + 5 else "token"


def new_session(selection, directory, path):
    from tools.chatbot_file_cohort.human_session import (
        PROFILE, HumanOAuthResponseUnknown, HumanSession, HumanSessionPaused,
    )
    from tools.chatbot_file_cohort.plan import PlanDenied

    class ReaderSession(HumanSession):
        phase = "device-start"

        def _login_locked(self, emit, stopper, confirmed):
            try:
                return super()._login_locked(emit, stopper, confirmed)
            except HumanSessionPaused as pause:
                # The owner checks expiry before issuing a poll. Also wake the
                # reader at expiry if the next poll or retry would fall later.
                if pause.retry_at is not None:
                    row = self._read()
                    if row.get("deviceCode"):
                        deadline = row["deviceDeadline"]
                        if time.time() >= deadline:
                            raise HumanSessionPaused("HUMAN_DEVICE_LOGIN_EXPIRED") from None
                        pause.retry_at = min(pause.retry_at, deadline)
                raise

        def _http(self, url, values=None, bearer=None):
            try:
                return super()._http(url, values, bearer)
            except HumanOAuthResponseUnknown as error:
                if self.phase == "poll" and error.status == 200:
                    self.phase = "token"
                raise

        def _request(self, row, operation, url, values=None, bearer=None):
            self.phase = {"DISCOVERY": "device-start", "DEVICE_START": "device-start",
                          "DEVICE_POLL": "poll", "USERINFO": "token", "REFRESH": "token"}[operation]
            reply = super()._request(row, operation, url, values, bearer)
            _, status, result, _ = reply
            if operation == "DEVICE_POLL":
                if status == 200:
                    self.phase = "token"
                elif status == 400 and result.get("error") == "expired_token":
                    self.phase = "expired"
            return reply

        def _claims(self, token):
            try:
                return super()._claims(token)
            except PlanDenied as error:
                if error.args == ("EXACT_CURRENT_HUMAN_CONTEXT_REQUIRED",):
                    self.phase = rejected_claim_phase(token, self.selection)
                raise

    return ReaderSession(selection, directory, path, int(time.time()) + PROFILE["maximumElapsedSeconds"])


def login(directory, selection):
    path = directory / "human-access.jwt"
    session = None
    uri = None
    displayed = None
    try:
        terminal = open("/dev/tty", "w", encoding="utf-8", buffering=1)
    except OSError:
        terminal = None
    if terminal is None:
        raise ReadError("INPUT_MISSING:terminal")
    with terminal as output:
        def show(line):
            nonlocal uri, displayed
            name, _, value = line.partition("=")
            if name == "OPEN_IN_BROWSER":
                uri = value
            elif name == "ENTER_DEVICE_CODE" and uri and displayed != (uri, value):
                print(f"{uri}  Codice: {value}  In attesa della conferma nel browser…",
                      file=output, flush=True)
                displayed = (uri, value)

        try:
            session = new_session(selection, directory, path)
            session.login(emit=show, confirm_browser=lambda _: True)
            session.phase = "token"
            session.current()
            return path.read_text(encoding="ascii")
        except Exception as error:
            phase = session.phase if session is not None else "device-start"
            if error.args == ("HUMAN_PROVIDER_PRINCIPAL_CHANGED",):
                phase = "subject"
            elif error.args in (("HUMAN_DEVICE_LOGIN_EXPIRED",), ("CURRENT_HUMAN_SESSION_REFRESH_PENDING",),
                                ("HUMAN_SESSION_WINDOW_EXPIRED_OR_CLOCK_DRIFT",)):
                phase = "expired"
    raise ReadError(f"LOGIN_FAILED:{phase}")


def get(connection, path, token, *, projection=False):
    stage = "PROJECTION" if projection else "ACTIVE"
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "X-Correlation-ID": str(uuid.uuid4())}
    try:
        with closing(connection()) as client:
            client.request("GET", path, headers=headers)
            with client.getresponse() as response:
                if response.status != 200:
                    raise ReadError(f"{stage}_HTTP_{response.status}")
                if projection:
                    digest = hashlib.sha256()
                    while chunk := response.read(65536):
                        digest.update(chunk)
                    if response.length:
                        raise ReadError("PROJECTION_PARSE_ERROR")
                    return response.status, digest.hexdigest()
                raw = response.read(16385)
                try:
                    if len(raw) > 16384 or response.length:
                        raise ReadError("ACTIVE_PARSE_ERROR")
                    return json.loads(raw), response.getheader("ETag")
                finally:
                    del raw
    except OSError as error:
        # Includes DNS, TLS, timeout and RemoteDisconnected.
        code = f"ORIGIN_UNREACHABLE:{type(error).__name__}"
    except (http.client.HTTPException, ValueError, RecursionError):
        code = f"{stage}_PARSE_ERROR"
    # Drop the decoder/HTTP exception and its potentially private document.
    raise ReadError(code)


def active_fields(active, installation):
    if not isinstance(active, dict):
        raise ReadError("ACTIVE_PARSE_ERROR")
    revision, checksum, generation = (active.get(k) for k in ("revision", "checksum", "generation"))
    if (active.get("installationId") != installation
            or not all(type(n) is int and 1 <= n < 2**63 for n in (revision, generation))
            or not isinstance(checksum, str) or not re.fullmatch("[0-9a-f]{64}", checksum)):
        raise ReadError("ACTIVE_PARSE_ERROR")
    return revision, checksum, generation


def read_active(installation, connection, token):
    base = f"/api/trusted-human/v1/installations/{installation}"
    active, etag = get(connection, base + "/active", token)
    revision, checksum, generation = active_fields(active, installation)
    if etag != f'"{revision}:{checksum}:{generation}"':
        raise ReadError("ACTIVE_PARSE_ERROR")
    status, digest = get(connection, f"{base}/projection?revision={revision}", token, projection=True)
    last, last_etag = get(connection, base + "/active", token)
    last_fields = active_fields(last, installation)
    if last_etag != etag or last_fields != (revision, checksum, generation):
        raise ReadError("ACTIVE_CHANGED")
    return {"revision": revision, "checksum": checksum, "generation": generation,
            "etag": etag, "projection_http": status, "projection_sha256": digest}


def main(argv=None):
    parser = Parser(description="Legge la revisione ACTIVE da Onboarding con un login HUMAN.",
                    allow_abbrev=False, exit_on_error=False)
    parser.add_argument("--installation-id")
    parser.add_argument("--origin")
    parser.add_argument("--profile", type=Path, default=Path("/opt/ouf-a2/profile.json"))
    for field in ("issuer", "subject", "tenant"):
        parser.add_argument("--" + field)
    try:
        args = parser.parse_args(argv)
        if os.geteuid() != 0:
            raise ReadError("INPUT_MISSING:root")
        profile = load_profile(args)
        gateway = profile.get("gateway", {})
        values = gateway.get("values", {}) if isinstance(gateway, dict) else None
        if not isinstance(values, dict):
            raise ReadError("INPUT_MISSING:profile")
        installation, address = target(args, values)
        issuer = identity_field("issuer", args.issuer if args.issuer is not None else values.get("gateway.issuerUrl"))
        subject = identity_field("subject", args.subject)
        tenant = args.tenant
        if tenant is None:
            queue = profile.get("queue", {})
            tenants = queue.get("subjectTenants", {}) if isinstance(queue, dict) else None
            if not isinstance(tenants, dict):
                raise ReadError("INPUT_MISSING:profile")
            tenant = tenants.get(subject)
        selection = dict(issuer=issuer, subject=subject, tenant=identity_field("tenant", tenant))
        # /run has the root-owned, non-writable ancestry required by HumanSession.
        temporary = tempfile.TemporaryDirectory(dir="/run", prefix="ouf-active-")
        try:
            token = login(Path(temporary.name), selection)
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
    except argparse.ArgumentError as error:
        field = (error.argument_name or "arguments").removeprefix("--")
        print(f"INPUT_MISSING:{field}")
    except KeyboardInterrupt:
        print("INTERRUPTED")
    except Exception as error:
        print(f"TRANSPORT_ERROR:{type(error).__name__}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
