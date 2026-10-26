"""Tests for the GM-KMS Python SDK.

The fake server below enforces the same credential contract as the real one:
the API key has to arrive in the ``x-api-key`` header, and anything else is
refused with 401. That is what makes these tests worth running - a SDK that
puts the key in the wrong header fails here instead of in production.
"""

import json
import os
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gmsdk.kms import Client, Error, PolicyEffect  # noqa: E402

API_KEY = "test-api-key"
TENANT = "tenant-a"


def _policy_json(policy_id, **overrides):
    policy = {
        "id": policy_id,
        "name": "default-allow",
        "effect": "Allow",
        "condition": {"operator": "always"},
        "resources": ["*"],
        "subjects": ["*"],
        "tenant": TENANT,
        "enabled": True,
    }
    policy.update(overrides)
    return policy


class _Handler(BaseHTTPRequestHandler):
    """A stand-in for the KMS REST API."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # keep the test output clean

    def _send(self, status, payload=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorized(self):
        # The real server reads the credential from `x-api-key` only.
        if self.headers.get("x-api-key") != API_KEY:
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    def _record(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self.server.requests.append(
            {
                "method": method,
                "path": self.path,
                # Keep the message object: HTTP header names are
                # case-insensitive, and urllib capitalises them on the way
                # out.
                "headers": self.headers,
                "body": json.loads(raw.decode("utf-8")) if raw else None,
            }
        )

    def do_GET(self):
        if not self._authorized():
            return
        self._record("GET")
        path = urllib.parse.urlparse(self.path).path
        if path == "/v1/keys":
            self._send(200, [])
            return
        if path == "/v1/policies":
            self._send(200, list(self.server.policies.values()))
            return
        if path.startswith("/v1/policies/"):
            policy_id = path.rsplit("/", 1)[1]
            policy = self.server.policies.get(policy_id)
            if policy is None:
                self._send(404, {"error": f"policy {policy_id} not found"})
            else:
                self._send(200, policy)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        self._record("POST")
        if self.path == "/v1/policies":
            body = self.server.requests[-1]["body"]
            policy_id = f"policy-{len(self.server.policies) + 1}"
            policy = _policy_json(policy_id)
            policy["name"] = body["name"]
            policy["effect"] = body["effect"].capitalize()
            policy["condition"] = body["condition"]
            policy["resources"] = body["resources"]
            policy["subjects"] = body["subjects"]
            policy["enabled"] = body.get("enabled", True)
            policy["tenant"] = body.get("tenant")
            self.server.policies[policy_id] = policy
            self._send(201, policy)
            return
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._authorized():
            return
        self._record("DELETE")
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/v1/policies/"):
            policy_id = path.rsplit("/", 1)[1]
            if policy_id not in self.server.policies:
                self._send(404, {"error": f"policy {policy_id} not found"})
                return
            del self.server.policies[policy_id]
            # 204 No Content: no body at all.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/v1/keys/"):
            # 204 No Content as well.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(404, {"error": "not found"})


class KmsClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.policies = {}
        cls.server.requests = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.server.policies.clear()
        self.server.requests.clear()
        self.client = Client(
            server_url=self.base_url,
            api_key=API_KEY,
            tenant_id=TENANT,
        )

    def test_the_api_key_travels_in_the_x_api_key_header(self):
        # The fake server refuses anything but `x-api-key`, so reaching it at
        # all proves the credential is presented the way the real server
        # expects it.
        self.client.list_keys()

        sent = self.server.requests[-1]
        self.assertEqual(sent["headers"].get("x-api-key"), API_KEY)
        self.assertNotIn("Authorization", sent["headers"])

    def test_a_wrong_credential_is_reported_as_unauthorized(self):
        client = Client(server_url=self.base_url, api_key="not-the-key")
        with self.assertRaises(Error) as caught:
            client.list_keys()
        self.assertEqual(caught.exception.status, 401)

    def test_create_policy_sends_the_policy_and_the_tenant(self):
        policy = self.client.create_policy(
            name="tenant-scoped-allow",
            effect=PolicyEffect.ALLOW,
            condition={"operator": "always"},
            resources=["*"],
            subjects=["*"],
            tenant=TENANT,
        )

        sent = self.server.requests[-1]
        self.assertEqual(sent["method"], "POST")
        self.assertEqual(sent["path"], "/v1/policies")
        self.assertEqual(sent["body"]["name"], "tenant-scoped-allow")
        self.assertEqual(sent["body"]["effect"], "allow")
        self.assertEqual(sent["body"]["condition"], {"operator": "always"})
        self.assertEqual(sent["body"]["resources"], ["*"])
        self.assertEqual(sent["body"]["subjects"], ["*"])
        self.assertEqual(sent["body"]["tenant"], TENANT)
        self.assertTrue(sent["body"]["enabled"])

        self.assertEqual(policy.id, "policy-1")
        self.assertEqual(policy.name, "tenant-scoped-allow")
        self.assertEqual(policy.tenant, TENANT)
        self.assertTrue(policy.enabled)

    def test_create_policy_without_a_tenant_leaves_the_field_out(self):
        self.client.create_policy(
            name="unscoped-allow",
            effect=PolicyEffect.ALLOW,
            condition={"operator": "always"},
            resources=["*"],
            subjects=["*"],
        )

        sent = self.server.requests[-1]
        self.assertNotIn("tenant", sent["body"])

    def test_the_effect_is_read_back_case_insensitively(self):
        # The server answers "Allow" and "Deny" while accepting "allow" and
        # "deny", so the SDK has to understand both spellings.
        self.server.policies["policy-1"] = _policy_json("policy-1", effect="Deny")
        policy = self.client.get_policy("policy-1")
        self.assertIs(policy.effect, PolicyEffect.DENY)

    def test_list_policies_returns_every_policy(self):
        self.server.policies["policy-1"] = _policy_json("policy-1")
        self.server.policies["policy-2"] = _policy_json("policy-2", name="second")

        policies = self.client.list_policies()
        self.assertEqual([p.id for p in policies], ["policy-1", "policy-2"])
        self.assertEqual(self.server.requests[-1]["path"], "/v1/policies")

    def test_get_policy_returns_the_policy(self):
        self.server.policies["policy-1"] = _policy_json("policy-1")
        policy = self.client.get_policy("policy-1")
        self.assertEqual(policy.id, "policy-1")
        self.assertEqual(policy.tenant, TENANT)

    def test_delete_policy_answers_204_without_a_body(self):
        self.server.policies["policy-1"] = _policy_json("policy-1")

        # A 204 carries no body; the SDK must not choke on the empty payload.
        self.client.delete_policy("policy-1")

        sent = self.server.requests[-1]
        self.assertEqual(sent["method"], "DELETE")
        self.assertEqual(sent["path"], "/v1/policies/policy-1")
        self.assertNotIn("policy-1", self.server.policies)

    def test_delete_policy_reports_an_unknown_policy(self):
        with self.assertRaises(Error) as caught:
            self.client.delete_policy("policy-missing")
        self.assertEqual(caught.exception.status, 404)
        self.assertIn("policy-missing", str(caught.exception))

    def test_delete_key_tolerates_an_empty_answer(self):
        # Same empty-body situation as the policy deletion: the key deletion
        # answers 204 as well.
        self.client.delete_key("key-1")
        self.assertEqual(self.server.requests[-1]["method"], "DELETE")


if __name__ == "__main__":
    unittest.main()
