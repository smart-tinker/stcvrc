import hashlib
import http.client
import pathlib
import socket
import sys
import tempfile
import unittest
from unittest import mock

import lab


class LabTests(unittest.TestCase):
    def test_new_invocation_uses_distinct_ephemeral_ports(self):
        original_ports, original_target = lab.PORTS.copy(), lab.TARGET
        try:
            lab.select_ports()
            self.assertEqual(len(set(lab.PORTS.values())), 4)
            self.assertTrue(all(0 < port < 65536 for port in lab.PORTS.values()))
            self.assertEqual(lab.TARGET, f"http://{lab.HOST}:{lab.PORTS['direct']}")
        finally:
            lab.PORTS.update(original_ports)
            lab.TARGET = original_target

    def setUp(self):
        self.configs = lab.configs("/temporary/lab", "TEST CA", "test-uuid", {"A": 20001, "B": 20002})

    def test_client_is_local_and_no_system_network_changes(self):
        core = self.configs["core"]
        self.assertFalse(core["allow-lan"])
        self.assertEqual(core["bind-address"], "127.0.0.1")
        for option in ("tun", "dns", "ntp"):
            self.assertFalse(core[option]["enable"])
        self.assertNotIn("external-controller", core)
        self.assertFalse(core["geo-auto-update"])

    def test_real_tls_and_candidate_trust_field(self):
        core = self.configs["core"]
        self.assertEqual(core["tls"], {"custom-certifactes": ["TEST CA"]})
        for proxy in core["proxies"]:
            self.assertTrue(proxy["tls"])
            self.assertFalse(proxy["skip-cert-verify"])
            self.assertEqual(proxy["servername"], "stcvrc-lab.invalid")

    def test_automatic_fallback_has_no_direct_member(self):
        core = self.configs["core"]
        group = core["proxy-groups"][0]
        self.assertEqual(group["type"], "fallback")
        self.assertEqual(group["proxies"], ["A", "B"])
        self.assertFalse(group["lazy"])
        self.assertEqual(core["rules"], ["MATCH,LAB"])

    def test_endpoints_only_target_distinct_loopback_backends(self):
        for name, port in (("A", 20001), ("B", 20002)):
            config = self.configs[name]
            self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
            outbound = config["outbounds"][0]["settings"]
            self.assertEqual(outbound["redirect"], f"127.0.0.1:{port}")
            self.assertEqual(outbound["finalRules"][-1], {"action": "block"})

    def test_hash_mismatch_blocks_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "fixture.bin"
            path.write_bytes(b"not executable")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(lab.checked_binary(path, digest), str(path))
            with self.assertRaises(ValueError):
                lab.checked_binary(path, "0" * 64)
            with self.assertRaises(ValueError):
                lab.checked_binary(path, "latest")

    def test_direct_path_is_a_failure_even_during_recovery(self):
        with mock.patch.object(lab, "probe", return_value="DIRECT"):
            with self.assertRaisesRegex(AssertionError, "Unexpected traffic path"):
                lab.wait_for("B")

    def test_wait_observes_new_connection_path(self):
        with mock.patch.object(lab, "probe", side_effect=[None, "A", "B"]), mock.patch.object(lab.time, "sleep"):
            self.assertGreaterEqual(lab.wait_for("B"), 0)

    def test_fault_timer_includes_process_shutdown(self):
        with mock.patch.object(lab, "probe", return_value="B"), mock.patch.object(lab.time, "monotonic", return_value=105):
            self.assertEqual(lab.wait_for("B", start=100), 5)

    def test_both_down_requires_live_proxy_http_error(self):
        client = mock.Mock()
        client.poll.return_value = None
        with mock.patch.object(lab, "request", return_value=(502, "")) as request:
            lab.check_both_down(client)
            self.assertEqual(request.call_args_list, [mock.call(timeout=10)] * 3)
        for status in (None, 200, 503):
            with self.subTest(status=status), mock.patch.object(lab, "request", return_value=(status, "")):
                with self.assertRaises(AssertionError):
                    lab.check_both_down(client)

    def test_client_exit_during_final_probe_is_not_pass(self):
        client = mock.Mock()
        client.poll.side_effect = [None, None, None, None, None, 1]
        with mock.patch.object(lab, "request", return_value=(502, "")):
            with self.assertRaisesRegex(AssertionError, "Client exited"):
                lab.check_both_down(client)

    def test_tls_rejection_requires_specific_runtime_evidence(self):
        logs = mock.Mock()
        client = mock.Mock()
        client.poll.return_value = None
        logs.read_text.return_value = "certificate is valid for stcvrc-lab.invalid, not wrong-stcvrc-lab.invalid"
        with mock.patch.object(lab.socket, "create_connection"), mock.patch.object(lab, "request", return_value=(502, "")):
            self.assertEqual(lab.check_tls_rejection(logs, client), {"tls_hostname_mismatch_rejected": True})
            logs.read_text.return_value = "unrelated startup failure"
            with self.assertRaises(AssertionError):
                lab.check_tls_rejection(logs, client)

    def test_tls_rejection_does_not_accept_either_endpoint_or_direct(self):
        logs = mock.Mock()
        client = mock.Mock()
        client.poll.return_value = None
        for body in ("A", "B", "DIRECT"):
            with self.subTest(body=body), mock.patch.object(lab.socket, "create_connection"), mock.patch.object(lab, "request", return_value=(200, body)):
                with self.assertRaisesRegex(AssertionError, "Expected a live proxy"):
                    lab.check_tls_rejection(logs, client)

    def test_tls_rejection_does_not_pass_after_client_exit(self):
        client = mock.Mock()
        client.poll.side_effect = [None, None, 1]
        with mock.patch.object(lab.socket, "create_connection"), mock.patch.object(lab, "request", return_value=(502, "")):
            with self.assertRaisesRegex(AssertionError, "Client exited"):
                lab.check_tls_rejection(mock.Mock(), client)

    def test_backend_negative_control_really_returns_direct(self):
        with lab.backend("DIRECT") as port:
            self.assertEqual(lab.probe(port, proxy=False), "DIRECT")

    def test_port_preflight_rejects_an_existing_listener(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((lab.HOST, 0))
            listener.listen()
            with self.assertRaises(OSError):
                lab.check_ports_available([listener.getsockname()[1]])

    @unittest.skipUnless(sys.platform == "linux", "Linux TIME_WAIT regression")
    def test_port_preflight_allows_time_wait_after_previous_run(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((lab.HOST, 0))
            port = listener.getsockname()[1]
            listener.listen()
            with socket.create_connection((lab.HOST, port), timeout=1) as client:
                connection, _ = listener.accept()
                connection.close()
                self.assertEqual(client.recv(1), b"")
        with socket.socket() as strict:
            with self.assertRaises(OSError):
                strict.bind((lab.HOST, port))
        lab.check_ports_available([port])

    def test_health_check_head_matches_candidate_urltest(self):
        for identity, status in (("A", 204), ("B", 204), ("DIRECT", 200)):
            with self.subTest(identity=identity), lab.backend(identity) as port:
                connection = http.client.HTTPConnection(lab.HOST, port, timeout=1)
                try:
                    connection.request("HEAD", "/generate_204")
                    response = connection.getresponse()
                    self.assertEqual(response.status, status)
                    self.assertEqual(response.read(), b"")
                finally:
                    connection.close()


if __name__ == "__main__":
    unittest.main()
