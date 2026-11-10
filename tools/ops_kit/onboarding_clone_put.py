#!/usr/bin/env python3
"""Clone an onboarding version into a new DRAFT and replace its configuration.

Uses the native Onboarding API as a HUMAN (device login of ouf-admin, scope
ouf.onboarding.configuration.write). It never approves, publishes or activates:
review preparation, approval and activation stay on the THS/MCP path.

Typical flow:
  1. build the configuration with onboarding_swap_asset.py and review the diff;
  2. run this script; open the printed URL and enter the code;
  3. compare the saved server diff with the reviewed one.
"""
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = "https://auth.ouf-lab.it/realms/ouf"
API = "https://api.ouf-lab.it/api/onboarding/v1/sources/{source}/onboarding-versions"
CLIENT = "ouf-human-admin"


def post_form(url, values):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(values).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


def device_login(scope):
    with urllib.request.urlopen(ISSUER + "/.well-known/openid-configuration", timeout=20) as r:
        meta = json.load(r)
    status, start = post_form(meta["device_authorization_endpoint"], {"client_id": CLIENT, "scope": scope})
    if status != 200:
        raise SystemExit(f"DEVICE_AUTHORIZATION_FAILED {status} {start.get('error')}")
    print("OPEN_IN_BROWSER=" + start["verification_uri"], flush=True)
    print("ENTER_DEVICE_CODE=" + start["user_code"], flush=True)
    interval = max(5, int(start.get("interval", 5)))
    deadline = time.monotonic() + min(600, int(start["expires_in"]))
    while time.monotonic() < deadline:
        time.sleep(interval)
        status, res = post_form(meta["token_endpoint"], {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT, "device_code": start["device_code"]})
        if status == 200:
            print("LOGIN_OK scope=" + res.get("scope", ""), flush=True)
            return res["access_token"]
        if res.get("error") == "slow_down":
            interval += 5
        elif res.get("error") != "authorization_pending":
            raise SystemExit(f"LOGIN_FAILED {res.get('error')}")
    raise SystemExit("LOGIN_EXPIRED")


def call(method, url, token, correlation, body=None, headers=None):
    h = {"Authorization": "Bearer " + token, "Accept": "application/json", "X-Correlation-Id": correlation}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.headers.get("ETag"), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("ETag"), e.read(4000).decode("utf-8", "replace")


def summary(raw):
    try:
        body = json.loads(raw)
    except ValueError:
        return raw[:1500]
    keys = ("onboarding_version_id", "source_id", "version", "state", "parent_version_id",
            "lock_version", "configuration_hash")
    return json.dumps({k: body.get(k) for k in keys})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True)
    parser.add_argument("--parent", required=True, help="onboarding_version_id to clone")
    parser.add_argument("--config", required=True, help='JSON file {"configuration": {...}}')
    parser.add_argument("--correlation", required=True)
    parser.add_argument("--diff-out", default="onboarding_diff.json")
    args = parser.parse_args()

    config = json.load(open(args.config, encoding="utf-8"))
    if set(config) != {"configuration"}:
        raise SystemExit('config file must contain exactly {"configuration": {...}}')
    base = API.format(source=args.source)
    token = device_login("openid ouf.onboarding.configuration.write")

    status, etag, raw = call("POST", f"{base}/{args.parent}/clone", token, args.correlation,
                             headers={"Content-Length": "0"})
    print("CLONE_STATUS", status, "ETAG", etag, summary(raw), flush=True)
    if status not in (200, 201):
        raise SystemExit(1)
    version_id = json.loads(raw)["onboarding_version_id"]

    status, etag, raw = call("PUT", f"{base}/{version_id}", token, args.correlation, body=config,
                             headers={"If-Match": etag})
    print("PUT_STATUS", status, "ETAG", etag, summary(raw), flush=True)
    if status != 200:
        raise SystemExit(1)

    status, _, raw = call("GET", f"{base}/{version_id}/diff", token, args.correlation)
    with open(args.diff_out, "w", encoding="utf-8") as f:
        f.write(raw)
    print("DIFF_STATUS", status, "DIFF_FILE", args.diff_out, "BYTES", len(raw), flush=True)


if __name__ == "__main__":
    main()
