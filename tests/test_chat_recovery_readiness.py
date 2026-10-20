import unittest
from tools.chat_recovery_update.readiness import classify, ReadinessDenied

class ReadinessContracts(unittest.TestCase):
    def check(self, contract, status, body=b"", retry_after=None):
        return classify(contract, status, body, retry_after=retry_after,
                        now=1445412480)

    def test_component_contracts_are_not_interchangeable(self):
        self.assertEqual(self.check("empty-204", 204),
                         ("APPLIED", {"httpStatus": 204}))
        self.assertEqual(self.check("spring-readiness", 200, b'{"status":"UP"}'),
                         ("APPLIED", {"httpStatus": 200}))
        for contract, status, body in (
            ("empty-204", 200, b'{"status":"UP"}'),
            ("empty-204", 204, b" "),
            ("spring-readiness", 204, b""),
            ("spring-readiness", 200, b'{"status":"DOWN"}'),
            ("spring-readiness", 200, b'["UP"]'),
            ("spring-readiness", 200, b"invalid"),
            ("spring-readiness", 200, b"\xff"),
        ):
            with self.subTest(contract=contract, status=status, body=body):
                with self.assertRaises(ReadinessDenied):
                    self.check(contract, status, body)

    def test_transient_statuses_and_retry_after(self):
        for contract in ("spring-readiness", "empty-204"):
            for status in (429, 502, 503, 504):
                self.assertEqual(self.check(contract, status, retry_after="60"),
                                 ("TRANSIENT", {"retryAfterSeconds": 60}))
                self.assertEqual(self.check(contract, status)[1],
                                 {"retryAfterSeconds": 0})
        self.assertEqual(self.check("empty-204", 503, retry_after=
                         "Wed, 21 Oct 2015 07:29:00 GMT")[1],
                         {"retryAfterSeconds": 60})
        self.assertEqual(self.check("empty-204", 503,
                                    retry_after="999999")[1],
                         {"retryAfterSeconds": 999999})

    def test_unknown_permanent_and_malformed_responses_block(self):
        for status in (301, 400, 401, 403, 404, 409, 500):
            with self.subTest(status=status), self.assertRaises(ReadinessDenied):
                self.check("empty-204", status)
        for value in ("", "-1", "1.5", "nonsense", "9" * 129,
                      "Wed, 21 Oct 2015 07:29:00"):
            with self.subTest(value=value), self.assertRaises(ReadinessDenied):
                self.check("empty-204", 503, retry_after=value)
        with self.assertRaises(ReadinessDenied):
            self.check("unknown", 204)

    def test_payload_and_clock_bounds(self):
        for status in (200, 503):
            with self.assertRaises(ReadinessDenied):
                self.check("spring-readiness", status, b"x" * 65537)
        for now in (float("nan"), float("inf"), True):
            with self.assertRaises(ReadinessDenied):
                classify("empty-204", 204, b"", now=now)

if __name__ == "__main__":
    unittest.main()
