import hashlib
import io
import http.client
import http.server
import pathlib
import socket
import sys
import threading
import tempfile
import unittest
from unittest import mock

import lab


class LabTests(unittest.TestCase):
    def test_requests_connect_to_current_core_port(self):
        original_ports, original_target = lab.PORTS.copy(), lab.TARGET
        try:
            lab.select_ports()
            selected_port = lab.PORTS["core"]
            with mock.patch.object(lab.http.client, "HTTPConnection") as connection:
                connection.return_value.getresponse.return_value.status = 200
                connection.return_value.getresponse.return_value.read.return_value = b"A"
                self.assertEqual(lab.request(), (200, "A"))
                self.assertEqual(lab.probe(), "A")
                self.assertEqual(connection.call_args_list,
                                 [mock.call(lab.HOST, selected_port, timeout=1)] * 2)
                lab.probe(43210, proxy=False)
                connection.assert_called_with(lab.HOST, 43210, timeout=1)
        finally:
            lab.PORTS.update(original_ports)
            lab.TARGET = original_target

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

    def test_selected_core_port_is_available_for_udp(self):
        original_ports, original_target = lab.PORTS.copy(), lab.TARGET
        try:
            with mock.patch.object(lab.socket, "socket", wraps=socket.socket) as socket_factory:
                lab.select_ports()
            self.assertIn(mock.call(socket.AF_INET, socket.SOCK_DGRAM), socket_factory.call_args_list)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind((lab.HOST, lab.PORTS["core"]))
        finally:
            lab.PORTS.update(original_ports)
            lab.TARGET = original_target

    def test_mixed_port_reservation_retries_protocol_specific_collision(self):
        original_ports, original_target = lab.PORTS.copy(), lab.TARGET
        next_tcp_port = [52000]
        active = {"tcp": set(), "udp": set()}
        mixed_ports = []
        tcp_exclusions = []
        udp_collisions = []
        sockets = []

        class FakeSocket:
            def __init__(self, protocol):
                self.protocol = protocol
                self.port = None
                self.closed = False

            def bind(self, address):
                host, requested_port = address
                if host != lab.HOST:
                    raise AssertionError("allocator changed its loopback host")
                if self.protocol == "tcp" and requested_port == 0:
                    next_tcp_port[0] += 1
                    port = next_tcp_port[0]
                elif self.protocol == "udp" and requested_port == 0:
                    port = 52000
                else:
                    port = requested_port

                if sys.platform == "win32":
                    if self.protocol == "tcp" and requested_port != 0 and port == 52000:
                        tcp_exclusions.append(port)
                        raise OSError("synthetic TCP-specific bind rejection")
                    if self.protocol == "udp" and port == 52001:
                        udp_collisions.append(port)
                        raise OSError("synthetic UDP-specific bind rejection")

                self.port = port
                active[self.protocol].add(port)
                other = "udp" if self.protocol == "tcp" else "tcp"
                if port in active[other]:
                    mixed_ports.append(port)

            def getsockname(self):
                return (lab.HOST, self.port)

            def close(self):
                if self.port is not None:
                    active[self.protocol].discard(self.port)
                    self.port = None
                self.closed = True

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()

        def socket_factory(family=socket.AF_INET, socket_type=socket.SOCK_STREAM, *args, **kwargs):
            protocol = "udp" if socket_type == socket.SOCK_DGRAM else "tcp"
            result = FakeSocket(protocol)
            sockets.append(result)
            return result

        try:
            with mock.patch.object(lab.socket, "socket", side_effect=socket_factory):
                try:
                    lab.select_ports()
                except OSError as error:
                    if sys.platform == "win32":
                        self.assertEqual(tcp_exclusions, [52000] * 32)
                        self.fail(
                            f"allocator exhausted after {len(tcp_exclusions)} "
                            f"synthetic TCP bind conflicts: {error}"
                        )
                    raise

            self.assertEqual(mixed_ports, [lab.PORTS["core"]])
            self.assertTrue(sockets and all(item.closed for item in sockets))
            self.assertEqual(active, {"tcp": set(), "udp": set()})
            if sys.platform == "win32":
                self.assertEqual(lab.PORTS["core"], 52002)
                self.assertEqual(tcp_exclusions, [])
                self.assertEqual(udp_collisions, [52001])
            else:
                self.assertEqual(tcp_exclusions, [])
                self.assertEqual(udp_collisions, [])
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
            self.assertEqual(lab.checked_binary(path, digest), str(path.resolve()))
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

    def test_failed_loopback_keeps_core_and_xray_log_tail(self):
        original_ports, original_target = lab.PORTS.copy(), lab.TARGET
        try:
            lab.select_ports()

            def fake_run(command, **kwargs):
                if command[0] == "openssl":
                    pathlib.Path(command[command.index("-keyout") + 1]).write_text("fixture key")
                    pathlib.Path(command[command.index("-out") + 1]).write_text("fixture cert")
                return mock.Mock(returncode=0)

            process = mock.Mock()
            process.poll.return_value = None

            def fake_popen(command, **kwargs):
                kwargs["stdout"].write(b"fixture process log marker\\n")
                kwargs["stdout"].flush()
                return process

            with mock.patch.object(lab, "check_ports_available"):
                with mock.patch.object(lab.subprocess, "run", side_effect=fake_run):
                    with mock.patch.object(lab.subprocess, "Popen", side_effect=fake_popen):
                        with mock.patch.object(
                            lab, "wait_for", side_effect=AssertionError("Did not reach A")
                        ):
                            with self.assertRaisesRegex(
                                AssertionError, "Did not reach A"
                            ) as failure:
                                lab.run("core.exe", "xray.exe", "openssl")

            self.assertTrue(any(
                "fixture process log marker" in note
                for note in getattr(failure.exception, "__notes__", [])
            ))
        finally:
            lab.PORTS.update(original_ports)
            lab.TARGET = original_target

    def test_fault_timer_includes_process_shutdown(self):
        with mock.patch.object(lab, "probe", return_value="B"), mock.patch.object(lab.time, "monotonic", return_value=105):
            self.assertEqual(lab.wait_for("B", start=100), 5)

    def test_both_down_requires_live_proxy_http_error(self):
        client = mock.Mock()
        client.poll.return_value = None
        with mock.patch.object(lab, "request", return_value=(502, "")) as request:
            lab.check_both_down(client)
            self.assertEqual(request.call_args_list, [mock.call(timeout=10, strict=True)] * 3)
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
        logs.read_text.return_value = ""
        client = mock.Mock()
        client.poll.return_value = None
        for body in ("A", "B", "DIRECT"):
            with self.subTest(body=body), mock.patch.object(lab.socket, "create_connection"), mock.patch.object(lab, "request", return_value=(200, body)), mock.patch.object(lab, "add_process_log_tail"):
                with self.assertRaisesRegex(AssertionError, "Expected a live proxy"):
                    lab.check_tls_rejection(logs, client)

    def test_tls_rejection_does_not_pass_after_client_exit(self):
        logs = mock.Mock()
        logs.read_text.return_value = ""
        client = mock.Mock()
        client.poll.side_effect = [None, None, 1]
        with mock.patch.object(lab.socket, "create_connection"), mock.patch.object(lab, "request", return_value=(502, "")), mock.patch.object(lab, "add_process_log_tail"):
            with self.assertRaisesRegex(AssertionError, "Client exited"):
                lab.check_tls_rejection(logs, client)

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


    def test_add_process_log_tail_reads_bounded_suffix(self):
        class TrackedLog(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                return super().read(size)

        stream = TrackedLog(b"before\n" * 5000 + b"last line\n")
        log_path = mock.MagicMock()
        log_path.open.return_value.__enter__.return_value = stream
        log_path.read_text.side_effect = AssertionError("must not read the whole log")
        failure = RuntimeError("synthetic failure")

        lab.add_process_log_tail(failure, log_path)

        self.assertEqual(stream.read_sizes, [16 * 1024])
        notes = "\n".join(getattr(failure, "__notes__", []))
        self.assertIn("last line", notes)


    def test_tls_negative_reports_truncated_502_diagnostics(self):
        class SyntheticResponse(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            response_mode = "chunked"
            body = b"short"
            requests = 0

            def do_GET(self):
                type(self).requests += 1
                self.close_connection = True
                self.send_response(502)
                if self.response_mode == "chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", "12")
                self.send_header("Connection", "close")
                self.end_headers()
                if self.response_mode == "chunked":
                    self.wfile.write(b"5\r\nshort\r\n")
                else:
                    self.wfile.write(self.body)
                self.wfile.flush()

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer((lab.HOST, 0), SyntheticResponse)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original_port = lab.PORTS["core"]
        try:
            lab.PORTS["core"] = server.server_port
            marker = "certificate is valid for stcvrc-lab.invalid, not wrong-stcvrc-lab.invalid"
            with tempfile.TemporaryDirectory() as folder:
                log_path = pathlib.Path(folder) / "process.log"
                log_path.write_text(
                    "\n".join([*(f"synthetic line {index}" for index in range(50)), marker]),
                    encoding="utf-8",
                )
                client = mock.Mock()
                client.poll.return_value = None

                for response_mode in ("chunked", "content-length"):
                    with self.subTest(response_mode=response_mode):
                        SyntheticResponse.response_mode = response_mode
                        SyntheticResponse.body = b"short"
                        SyntheticResponse.requests = 0
                        with self.assertRaises(lab.RequestFailure) as failure:
                            lab.check_tls_rejection(log_path, client)

                        self.assertEqual(failure.exception.phase, "response body")
                        self.assertEqual(failure.exception.exception_type, "IncompleteRead")
                        self.assertEqual(failure.exception.status, 502)
                        self.assertEqual(SyntheticResponse.requests, 1)
                        notes = "\n".join(getattr(failure.exception, "__notes__", []))
                        self.assertIn(marker, notes)
                        self.assertIn("synthetic line 49", notes)
                        self.assertNotIn("synthetic line 0", notes)

                SyntheticResponse.response_mode = "content-length"
                SyntheticResponse.body = b"012345678901"
                SyntheticResponse.requests = 0
                self.assertEqual(
                    lab.check_tls_rejection(log_path, client),
                    {"tls_hostname_mismatch_rejected": True},
                )
                self.assertEqual(SyntheticResponse.requests, 3)
        finally:
            lab.PORTS["core"] = original_port
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

if __name__ == "__main__":
    unittest.main()
