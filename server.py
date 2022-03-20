import json
from typing import Dict
import noise.constants as constants
import logging
from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET
from noise.connection import NoiseConnection
from itertools import cycle
from noise.connection import Keypair
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class MessageChannel:
    protocol_name: bytes = b"Noise_KK_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket
    user_key: x25519.X25519PublicKey
    server_key: x25519.X25519PrivateKey

    def __init__(
        self,
        soc: socket,
        user_key: x25519.X25519PublicKey,
        server_key: x25519.X25519PrivateKey,
    ) -> None:
        self.soc = soc
        self.user_key = user_key
        self.server_key = server_key
        self.handshake()

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.protocol_name)
        noise.set_as_responder()
        noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self.server_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )
        noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            self.user_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
        # Enter handshake mode
        noise.start_handshake()

        for action in cycle(["receive", "send"]):
            if noise.handshake_finished:
                break
            elif action == "receive":
                data = self.soc.recv(self.recv_buffersize)
                noise.read_message(data)
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


class RegisterChannel:
    protocol_name: bytes = b"Noise_NN_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket

    def __init__(self, soc: socket) -> None:
        self.soc = soc
        self.handshake()

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.protocol_name)
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
    server_key: x25519.X25519PrivateKey
    users: Dict[str, x25519.X25519PublicKey] = {}

    def __init__(self) -> None:
        self.server_key = x25519.X25519PrivateKey.generate()

    def register_command(self, soc: socket):
        channel = RegisterChannel(soc)

        register_data = channel.receive()
        logging.info(f"Received register data:\n{register_data}")

        reg_js = json.loads(register_data)
        self.users[reg_js["login"]] = serialization.load_pem_public_key(
            reg_js["pubkey"].encode("utf8")
        )

        # TODO add processing when we'll decide what the data should be

        # Send back server public key
        pub_bytes = self.server_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        channel.send(json.dumps({"pubkey": pub_bytes.decode("utf8")}).encode("utf8"))

        # Confirm and finish connection
        channel.send(b"OK\n")

    def message_command(self, soc: socket):
        login = soc.recv(2048).decode("utf8")
        if login not in self.users.keys():
            logging.error(f"User {login} not registered")
            soc.sendall(b"ERROR\n")
            return

        logging.debug(f"Found user {login}")

        soc.sendall(b"OK\n")

        logging.debug("Opening Message channel")
        channel = MessageChannel(soc, self.users[login], self.server_key)

        logging.debug("Echoing messages")
        response = b""
        while response != b"END\n":
            response = channel.receive()
            channel.send(response)
            logging.debug(f"Received {response}")

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
            self.message_command(soc)

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