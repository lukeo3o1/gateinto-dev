import json
import select
import socket
import threading
import time


class Bridge:
    def __init__(self, manifest, packet_file, output):
        self.manifest = manifest
        self.packet_file = packet_file
        self.output = output.open("w", encoding="utf-8")
        self.listener = socket.socket()
        self.listener.bind((manifest.get("bridge_ip", manifest["target_ip"]), 0))
        self.listener.listen(32)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.workers = []
        self.connections = set()
        self.successful_tunnels = 0

    def log(self, **record):
        with self.lock:
            self.output.write(json.dumps(dict(time_ns=time.time_ns(), **record)) + "\n")
            self.output.flush()

    def start(self):
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections.add(client)
            worker = threading.Thread(target=self.handle, args=(client, peer), daemon=True)
            self.workers.append(worker)
            worker.start()

    def original(self, peer, local):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.stop.is_set():
            entries = []
            if self.packet_file.exists():
                for line in self.packet_file.read_text(encoding="utf-8").splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if (item.get("kind") == "translation" and
                        (item.get("peer_ip"), item.get("peer_port")) == peer and
                        (item.get("listener_ip"), item.get("listener_port")) == local):
                        entries.append(item)
            if entries:
                destinations = {(item["original_ip"], item["original_port"], item["generation"]) for item in entries}
                if len(destinations) != 1:
                    raise RuntimeError("ambiguous translated endpoint")
                return entries[0]
            time.sleep(.005)
        raise RuntimeError("no original destination mapping")

    def handle(self, client, peer):
        upstream = None
        try:
            mapping = self.original(peer, client.getsockname())
            client.settimeout(10)
            upstream = socket.create_connection((self.manifest["proxy_host"], self.manifest["proxy_port"]), timeout=10)
            with self.lock:
                self.connections.add(upstream)
            authority = f'{mapping["original_ip"]}:{mapping["original_port"]}'
            auth = self.manifest["proxy_authorization"]
            if "\r" in auth or "\n" in auth:
                raise RuntimeError("invalid proxy authorization")
            request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {auth}\r\n\r\n"
            upstream.sendall(request.encode("ascii"))
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = upstream.recv(4096)
                if not chunk:
                    raise RuntimeError("proxy closed before CONNECT response")
                response += chunk
                if len(response) > 65536:
                    raise RuntimeError("proxy CONNECT response exceeds limit")
            head, early = response.split(b"\r\n\r\n", 1)
            status = head.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[0] not in [b"HTTP/1.0", b"HTTP/1.1"] or status[1] != b"200":
                raise RuntimeError("proxy refused CONNECT")
            if early:
                client.sendall(early)
            with self.lock:
                self.successful_tunnels += 1
            self.log(kind="connected", original_ip=mapping["original_ip"], original_port=mapping["original_port"],
                     generation=mapping["generation"], peer_ip=peer[0], peer_port=peer[1])
            client.settimeout(10)
            upstream.settimeout(10)
            readers = [client, upstream]
            last_data = time.monotonic()
            while readers and not self.stop.is_set():
                ready, _, _ = select.select(readers, [], [], .2)
                if not ready and time.monotonic() - last_data > 15:
                    raise TimeoutError("bridge idle timeout")
                for source in ready:
                    destination = upstream if source is client else client
                    chunk = source.recv(65536)
                    if chunk:
                        destination.sendall(chunk)
                        last_data = time.monotonic()
                    else:
                        readers.remove(source)
                        destination.shutdown(socket.SHUT_WR)
            self.log(kind="closed", generation=mapping["generation"])
        except Exception as error:
            self.log(kind="error", error=str(error), peer_ip=peer[0], peer_port=peer[1])
        finally:
            for connection in [client, upstream]:
                if connection is not None:
                    with self.lock:
                        self.connections.discard(connection)
                    connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        if hasattr(self, "thread"):
            self.thread.join(timeout=2)
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        for worker in self.workers:
            worker.join(timeout=2)
        self.output.close()
