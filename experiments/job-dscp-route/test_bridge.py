import json
import pathlib
import socket
import tempfile
import threading
import time
import unittest

import bridge

AUTH = "Basic dXNlcjpwYXNz"


class FakeProxy:
    def __init__(self, mode="ok", early=b""):
        self.mode = mode
        self.early = early
        self.requests = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.address = self.sock.getsockname()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.sock.accept()
                break
            except socket.timeout:
                continue
            except OSError:
                return
        else:
            return
        with connection:
            connection.settimeout(5)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                head += chunk
            self.requests.append(head.decode("ascii"))
            if self.mode == "refuse":
                connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return
            if self.mode == "close":
                return
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + self.early)
            received = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                received += chunk
                connection.sendall(chunk)
            connection.sendall(b"bye:" + received)

    def close(self):
        self.stopping.set()
        self.thread.join(timeout=5)
        self.sock.close()


def translation(peer, listener_port, original=("192.0.2.10", 443), generation=1):
    return json.dumps(dict(kind="translation", peer_ip=peer[0], peer_port=peer[1], listener_ip="127.0.0.1",
                           listener_port=listener_port, original_ip=original[0], original_port=original[1],
                           generation=generation))


def read_all(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.map = self.root / "map.jsonl"
        self.map.write_text("")
        self.bridges = []

    def tearDown(self):
        for item in self.bridges:
            item.close()
        self.directory.cleanup()

    def start(self, proxy_address, authorization=AUTH, attribute=None):
        item = bridge.Bridge("127.0.0.1", proxy_address, authorization, self.map, self.root / "bridge.jsonl",
                             lookup_seconds=0.5, attribute=attribute)
        item.start()
        self.bridges.append(item)
        return item

    def client(self):
        sock = socket.socket()
        sock.settimeout(5)
        sock.bind(("127.0.0.1", 0))
        return sock

    def wait_for(self, item, key, value):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and item.stats()[key] != value:
            time.sleep(0.01)
        self.assertEqual(value, item.stats()[key])

    def test_tunnels_the_original_destination_with_half_close(self):
        proxy = FakeProxy(early=b"early|")
        item = self.start(proxy.address)
        sock = self.client()
        with self.map.open("a") as stream:
            stream.write('{"kind":"translation","peer_ip":"127.0.0.1"\n')
            stream.write(translation(sock.getsockname(), item.port + 1, original=("192.0.2.99", 80)) + "\n")
            stream.write(translation(sock.getsockname(), item.port) + "\n")
        sock.connect(("127.0.0.1", item.port))
        sock.sendall(b"ping")
        sock.shutdown(socket.SHUT_WR)
        self.assertEqual(b"early|pingbye:ping", read_all(sock))
        sock.close()
        proxy.close()
        lines = proxy.requests[0].split("\r\n")
        self.assertEqual("CONNECT 192.0.2.10:443 HTTP/1.1", lines[0])
        self.assertIn("Host: 192.0.2.10:443", lines)
        self.assertIn(f"Proxy-Authorization: {AUTH}", lines)
        self.wait_for(item, "tunnels", 1)
        self.assertEqual(dict(started=True, accepted=1, tunnels=1, errors=0, error_kinds={}),
                         {k: v for k, v in item.stats().items() if k != "close_ok"})
        self.assertTrue(item.close())
        self.assertTrue(item.stats()["close_ok"])

    def assert_error(self, kind, proxy_address, authorization=AUTH, records=None):
        item = self.start(proxy_address, authorization)
        sock = self.client()
        if records is None:
            records = [translation(sock.getsockname(), item.port)]
        self.map.write_text("".join(line + "\n" for line in records))
        sock.connect(("127.0.0.1", item.port))
        self.assertEqual(b"", read_all(sock))
        sock.close()
        self.wait_for(item, "errors", 1)
        self.assertEqual({kind: 1}, item.stats()["error_kinds"])
        self.assertEqual(0, item.stats()["tunnels"])
        log = (self.root / "bridge.jsonl").read_text()
        self.assertIn(f'"error_kind": "{kind}"', log)
        return item

    def test_missing_mapping(self):
        proxy = FakeProxy()
        self.assert_error("lookup", proxy.address, records=[])
        proxy.close()
        self.assertEqual([], proxy.requests)

    def test_ambiguous_mapping(self):
        proxy = FakeProxy()
        holder = self.client()
        port = holder.getsockname()
        holder.close()
        item = self.start(proxy.address)
        sock = socket.socket()
        sock.settimeout(5)
        sock.bind(port)
        self.map.write_text(translation(port, item.port) + "\n" +
                            translation(port, item.port, original=("192.0.2.10", 80)) + "\n")
        sock.connect(("127.0.0.1", item.port))
        self.assertEqual(b"", read_all(sock))
        sock.close()
        self.wait_for(item, "errors", 1)
        self.assertEqual({"lookup": 1}, item.stats()["error_kinds"])
        proxy.close()

    def test_proxy_refusal(self):
        proxy = FakeProxy(mode="refuse")
        self.assert_error("proxy_refused", proxy.address)
        proxy.close()

    def test_proxy_closed(self):
        proxy = FakeProxy(mode="close")
        self.assert_error("proxy_closed", proxy.address)
        proxy.close()

    def test_proxy_unreachable(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        address = closed.getsockname()
        closed.close()
        self.assert_error("proxy_connect", address)

    def test_invalid_authorization(self):
        proxy = FakeProxy()
        self.assert_error("other", proxy.address, authorization="Basic x\r\nInjected: 1")
        proxy.close()
        self.assertEqual([], proxy.requests)

    def test_close_stops_accepting(self):
        proxy = FakeProxy()
        item = self.start(proxy.address)
        port = item.port
        self.assertTrue(item.close())
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)
        proxy.close()

    def tunnel_with(self, attribute):
        proxy = FakeProxy()
        item = self.start(proxy.address, attribute=attribute)
        sock = self.client()
        self.map.write_text(translation(sock.getsockname(), item.port) + "\n")
        sock.connect(("127.0.0.1", item.port))
        sock.sendall(b"x")
        sock.shutdown(socket.SHUT_WR)
        self.assertEqual(b"xbye:x", read_all(sock))
        port = sock.getsockname()[1]
        sock.close()
        proxy.close()
        self.wait_for(item, "tunnels", 1)
        self.assertEqual(1, len(proxy.requests))
        return item, port

    def test_attribution_runs_before_connect_and_is_recorded(self):
        calls = []

        def attribute(connection):
            calls.append(connection)
            return {"kind": "owner", "found": True}

        item, port = self.tunnel_with(attribute)
        self.assertEqual([dict(local_ip="127.0.0.1", local_port=port, remote_ip="192.0.2.10", remote_port=443)],
                         calls)
        self.assertEqual([dict(local_port=port, owner={"kind": "owner", "found": True}, error=None)],
                         item.attributions())

    def test_attribution_failure_never_breaks_the_relay(self):
        def labelled(connection):
            raise bridge.AttributionError("owner_timeout")

        item, port = self.tunnel_with(labelled)
        self.assertEqual([dict(local_port=port, owner=None, error="owner_timeout")], item.attributions())

        def crashing(connection):
            raise ValueError("C:\\secret")

        item, port = self.tunnel_with(crashing)
        self.assertEqual([dict(local_port=port, owner=None, error="exception_valueerror")], item.attributions())

    def test_original_lookup_is_exact(self):
        self.map.write_text("\n".join([
            translation(("127.0.0.1", 5000), 7000),
            translation(("127.0.0.1", 5000), 7001, original=("192.0.2.11", 443)),
            translation(("127.0.0.1", 5001), 7000, original=("192.0.2.12", 443)),
            translation(("127.0.0.1", 5000), 7000, generation=1)]) + "\n")
        self.assertEqual(("192.0.2.10", 443), bridge.find_original(self.map, ("127.0.0.1", 5000), 7000))
        self.assertIsNone(bridge.find_original(self.map, ("127.0.0.1", 5002), 7000))
        self.assertIsNone(bridge.find_original(self.root / "missing", ("127.0.0.1", 5000), 7000))
        with self.map.open("a") as stream:
            stream.write(translation(("127.0.0.1", 5000), 7000, original=("192.0.2.10", 80)) + "\n")
        with self.assertRaises(bridge.BridgeError):
            bridge.find_original(self.map, ("127.0.0.1", 5000), 7000)


if __name__ == "__main__":
    unittest.main()
