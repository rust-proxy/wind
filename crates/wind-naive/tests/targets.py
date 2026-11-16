"""Synthetic EOF-delimited TCP targets for the Naive Docker regression."""
import socket
import socketserver
import threading

SIZES = (0, 7, 256 * 1024)
RESPONSE = bytes([0xA5]) * (256 * 1024)

class Target(socketserver.BaseRequestHandler):
    def handle(self):
        expected = bytes(i % 251 for i in range(self.server.request_size))
        received = bytearray()
        while chunk := self.request.recv(65536):
            received.extend(chunk)
            if len(received) > len(expected):
                raise AssertionError("request is longer than expected")
        assert received == expected, "request contents differ"
        # The response is released only by the destination's real TCP EOF.
        self.request.sendall(RESPONSE)
        self.request.shutdown(socket.SHUT_WR)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

servers = []
for index, size in enumerate(SIZES):
    server = Server(("127.0.0.1", 10003 + index), Target)
    server.request_size = size
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
print("half-close targets ready", flush=True)
threading.Event().wait()
