from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET
from noise.connection import NoiseConnection
from itertools import cycle
import noise.constants as constants
import logging


class RegisterChannel:
    pattern_nn: bytes = b"Noise_NN_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket

    def __init__(self, soc: socket) -> None:
        self.soc = soc
        self.handshake()

        # By now we should have noise connection setup

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.pattern_nn)
        # Set role in this connection as responder
        noise.set_as_responder()
        # Enter handshake mode
        noise.start_handshake()

        for action in cycle(["receive", "send"]):
            if noise.handshake_finished:
                break
            elif action == "receive":
                data = self.soc.recv(self.recv_buffersize)
                plaintext = noise.read_message(data)
                # Extra payload opportunity
            elif action == "send":
                ciphertext = noise.write_message()
                self.soc.sendall(ciphertext)

        self.noise = noise

    def send(self, data: bytes) -> None:
        self.soc.sendall(self.noise.encrypt(data))

    def receive(self) -> bytes:
        data = self.soc.recv(self.recv_buffersize)
        if data:
            return self.noise.decrypt(data)

        return None


class Server:
    host: str = "127.0.0.1"
    port: int = 65432
    recv_buffer: int = 4096

    def register_command(self, soc: socket):
        channel = RegisterChannel(soc)

        register_data = channel.receive()
        logging.info(f"Received register data:\n{register_data}")

        # TODO add processing when we'll decide what the data should be

        # Confirm and finish connection
        channel.send(b"OK\n")

    def handler(self, soc: socket):
        command = soc.recv(self.recv_buffer)
        logging.debug(f"Handling command: {command}")

        if command not in [b"REGISTER\n", b"MESSAGE\n"]:
            logging.error(f"Unsupported command {command}, closing connection")
            return

        # Valid command, confirm
        soc.sendall(b"OK\n")

        if command == b"REGISTER\n":
            self.register_command(soc)

        if command == b"MESSAGE\n":
            logging.error("Message command not yet implemented")

        logging.debug("Request finished, closing connection")
        soc.close()

    def run(self):
        with socket(AF_INET, SOCK_STREAM) as s:
            s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                logging.debug(f"Connection from {addr}")
                with conn:
                    self.handler(conn)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")

    server = Server()
    server.run()
