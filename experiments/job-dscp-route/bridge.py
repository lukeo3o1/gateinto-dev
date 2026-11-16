import collections
import json
import pathlib
import select
import socket
import threading
import time

RESPONSE_LIMIT = 65536


class BridgeError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


class AttributionError(Exception):
    def __init__(self, label):
        super().__init__(label)
        self.label = label


def find_original(map_path, peer, listener_port):
    try:
        text = pathlib.Path(map_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found = set()
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if (isinstance(item, dict) and item.get("kind") == "translation"
                and (item.get("peer_ip"), item.get("peer_port")) == tuple(peer[:2])
                and item.get("listener_port") == listener_port):
            found.add((item.get("original_ip"), item.get("original_port")))
    if len(found) > 1:
        raise BridgeError("lookup")
    return next(iter(found)) if found else None


class Bridge:
    def __init__(self, listen_ip, proxy_address, authorization, map_path, log_path, lookup_seconds=2.0,
                 idle_seconds=15.0, attribute=None):
        self.attribute = attribute
        self.attribution_records = []
        self.proxy_address = tuple(proxy_address)
        self.authorization = authorization
        self.map_path = pathlib.Path(map_path)
        self.lookup_seconds = lookup_seconds
        self.idle_seconds = idle_seconds
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind((listen_ip, 0))
            self.listener.listen(64)
            self.listener.settimeout(0.2)
        except OSError:
            self.listener.close()
            raise
        self.port = self.listener.getsockname()[1]
        self.output = pathlib.Path(log_path).open("a", encoding="utf-8")
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.workers = []
        self.connections = set()
        self.accepted = 0
        self.tunnels = 0
        self.error_kinds = collections.Counter()
        self.thread = None
        self.close_ok = None

    def log(self, **record):
        with self.lock:
            if not self.output.closed:
                self.output.write(json.dumps(record) + "\n")
                self.output.flush()

    def start(self):
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def stats(self):
        with self.lock:
            return dict(started=self.thread is not None, accepted=self.accepted, tunnels=self.tunnels,
                        errors=sum(self.error_kinds.values()), error_kinds=dict(sorted(self.error_kinds.items())),
                        close_ok=self.close_ok is True)

    def accept(self):
        while not self.stopping.is_set():
            try:
                client, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.handle, args=(client, peer), daemon=True)
            with self.lock:
                self.accepted += 1
                self.connections.add(client)
                self.workers.append(worker)
            worker.start()

    def attributions(self):
        with self.lock:
            return [dict(record) for record in self.attribution_records]

    def attribute_connection(self, client, peer, original_ip, original_port):
        record = dict(local_port=peer[1], owner=None, error=None)
        try:
            record["owner"] = self.attribute(dict(local_ip=client.getsockname()[0], local_port=peer[1],
                                                  remote_ip=original_ip, remote_port=original_port))
        except AttributionError as error:
            record["error"] = error.label
        except Exception as error:
            record["error"] = "exception_" + type(error).__name__.lower()
        with self.lock:
            self.attribution_records.append(record)

    def lookup(self, peer):
        deadline = time.monotonic() + self.lookup_seconds
        while not self.stopping.is_set():
            original = find_original(self.map_path, peer, self.port)
            if original is not None:
                return original
            if time.monotonic() >= deadline:
                break
            time.sleep(0.005)
        raise BridgeError("lookup")

    def open_tunnel(self, authority):
        try:
            upstream = socket.create_connection(self.proxy_address, timeout=10)
        except OSError:
            raise BridgeError("proxy_connect")
        with self.lock:
            self.connections.add(upstream)
        try:
            return upstream, self.handshake(upstream, authority)
        except BaseException:
            with self.lock:
                self.connections.discard(upstream)
            upstream.close()
            raise

    def handshake(self, upstream, authority):
        request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {self.authorization}\r\n\r\n"
        response = b""
        try:
            upstream.sendall(request.encode("ascii"))
            while b"\r\n\r\n" not in response:
                chunk = upstream.recv(4096)
                if not chunk:
                    raise BridgeError("proxy_closed")
                response += chunk
                if len(response) > RESPONSE_LIMIT:
                    raise BridgeError("proxy_refused")
        except OSError:
            raise BridgeError("proxy_closed")
        head, early = response.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] != b"200":
            raise BridgeError("proxy_refused")
        return early

    def relay(self, client, upstream):
        readers = [client, upstream]
        last_data = time.monotonic()
        while readers and not self.stopping.is_set():
            ready, _, _ = select.select(readers, [], [], 0.2)
            if not ready and time.monotonic() - last_data > self.idle_seconds:
                raise TimeoutError("bridge idle timeout")
            for source in ready:
                destination = upstream if source is client else client
                chunk = source.recv(65536)
                if chunk:
                    destination.sendall(chunk)
                    last_data = time.monotonic()
                else:
                    readers.remove(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

    def handle(self, client, peer):
        upstream = None
        tunneled = False
        try:
            client.settimeout(10)
            original_ip, original_port = self.lookup(peer)
            if self.attribute is not None:
                self.attribute_connection(client, peer, original_ip, original_port)
            if any(c in self.authorization for c in "\r\n"):
                raise BridgeError("other")
            upstream, early = self.open_tunnel(f"{original_ip}:{original_port}")
            if early:
                client.sendall(early)
            tunneled = True
            with self.lock:
                self.tunnels += 1
            self.log(kind="connected", original_ip=original_ip, original_port=original_port)
            upstream.settimeout(10)
            self.relay(client, upstream)
            self.log(kind="closed")
        except Exception as error:
            kind = error.kind if isinstance(error, BridgeError) else "relay" if tunneled else "other"
            with self.lock:
                self.error_kinds[kind] += 1
            self.log(kind="error", error_kind=kind, error_type=type(error).__name__)
        finally:
            for connection in (client, upstream):
                if connection is not None:
                    with self.lock:
                        self.connections.discard(connection)
                    connection.close()

    def close(self):
        if self.close_ok is not None:
            return self.close_ok
        self.stopping.set()
        self.listener.close()
        clean = True
        if self.thread is not None:
            self.thread.join(timeout=5)
            clean = not self.thread.is_alive()
        with self.lock:
            connections = list(self.connections)
            workers = list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in workers:
            worker.join(timeout=5)
            clean = clean and not worker.is_alive()
        with self.lock:
            self.output.close()
            self.close_ok = clean
        return clean
