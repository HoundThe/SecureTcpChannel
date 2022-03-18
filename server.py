from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET
from noise.connection import NoiseConnection
from itertools import cycle
import logging


class Server:
    host: str = "127.0.0.1"
    port: int = 65432
    recv_buffer: int = 4096
    pattern_nn: bytes = b"Noise_NN_25519_ChaChaPoly_SHA256"

    def send(self, soc: socket, data: bytes):
        # For consistency with rest of the interface, even if it is just 1 call
        soc.sendall(data)

    def receive(self, soc: socket) -> bytes:
        # TODO idea is to read whole message here if its longer than limit
        # to recv()
        return soc.recv(self.recv_buffer)

    def handshake_NN(self, soc: socket) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.pattern_nn)
        # Set role in this connection as responder
        noise.set_as_responder()
        # Enter handshake mode
        noise.start_handshake()

        for action in cycle(["receive", "send"]):
            if noise.handshake_finished:
                break
            elif action == "receive":
                data = self.receive(soc)
                plaintext = noise.read_message(data)
                # Extra payload opportunity
            elif action == "send":
                ciphertext = noise.write_message()
                self.send(soc, ciphertext)

        return noise

    def register_command(self, soc: socket):
        noise = self.handshake_NN(soc)
        while True:
            data = self.receive(soc)
            if not data:
                break
            # get the register data
            received = noise.decrypt(data)
            # TODO add processing when we'll decide what the data should be
            logging.info(f"Received:\n{received}")

            self.send(soc, noise.encrypt(b"OK\n"))
            break

    def handler(self, soc: socket):
        command = self.receive(soc)
        if command not in [b"REGISTER\n"]:
            logging.error(f"Unsupported command {command}, closing connection")
            return

        if command == b"REGISTER\n":
            self.register_command(soc)

    def run(self):
        with socket(AF_INET, SOCK_STREAM) as s:
            s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                logging.info(f"Connection from {addr}")
                with conn:
                    self.handler(conn)


if __name__ == "__main__":
    server = Server()
    server.run()
