"""The transport talks to GitHub with the Python standard library only (no gh CLI on the VPS)."""
import io
import json
import os
import unittest
from unittest.mock import patch

import test_module_release  # noqa: F401  (sets sys.path like the other suites)
from module_release import transport
from module_release.contract import Held


class Response:
    def __init__(self, status, body=b"", location=None):
        self.status, self._body, self._location = status, io.BytesIO(body), location

    def getheader(self, name):
        return self._location if name == "Location" else None

    def read(self, n=-1):
        return self._body.read(n)


class Connections:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, host, timeout):
        outer = self

        class Conn:
            def request(self, method, path, headers=None):
                outer.calls.append((host, method, path, dict(headers or {})))

            def getresponse(self):
                return outer.responses.pop(0)

            def close(self):
                pass
        return Conn()


class TransportHttp(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"GH_TOKEN": "ghs_test-token"}))

    def test_json_from_api(self):
        conns = Connections([Response(200, json.dumps({"id": 7}).encode())])
        with patch.object(transport.http.client, "HTTPSConnection", conns):
            self.assertEqual(transport.github("repos/o/r/actions/runs/7"), {"id": 7})
        host, method, path, headers = conns.calls[0]
        self.assertEqual((host, method, path), ("api.github.com", "GET", "/repos/o/r/actions/runs/7"))
        self.assertEqual(headers["Authorization"], "Bearer ghs_test-token")

    def test_zip_follows_one_https_redirect_without_bearer(self):
        conns = Connections([Response(302, location="https://blob.example.test/a.zip?sig=x"),
                             Response(200, b"PK" + b"x" * (3 << 20))])
        out = io.BytesIO()
        with patch.object(transport.http.client, "HTTPSConnection", conns):
            transport.github("repos/o/r/actions/artifacts/9/zip", out)
        self.assertEqual(len(out.getvalue()), 2 + (3 << 20))
        host, _, path, headers = conns.calls[1]
        self.assertEqual((host, path), ("blob.example.test", "/a.zip?sig=x"))
        self.assertNotIn("Authorization", headers)

    def test_rejects_plain_http_redirect_bad_path_and_missing_token(self):
        conns = Connections([Response(302, location="http://blob.example.test/a.zip")])
        with patch.object(transport.http.client, "HTTPSConnection", conns):
            with self.assertRaises(Held):
                transport.github("repos/o/r/actions/artifacts/9/zip", io.BytesIO())
        with self.assertRaises(Held):
            transport.github("repos/o/r/../../x", None)
        with patch.dict(os.environ, {"GH_TOKEN": ""}):
            with self.assertRaises(Held):
                transport.github("repos/o/r/actions/runs/7")


if __name__ == "__main__":
    unittest.main()
