from ast import arg
import json
import logging
import argparse
import noise.constants as constants
from socket import socket, AF_INET, SOCK_STREAM
from typing import Tuple
from noise.connection import NoiseConnection
from noise.connection import Keypair
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from tpm import get_signed_pcr, init_tpm, shutdown_tpm

excpected_pub_key = b'\x9cHb\x02\xfe0s\xc9\x876A\x99AZ\xf4\xaf\x18\xbdI\x98CB\xce\xb3\xa2Xx|@\x97aZ'


class MessageChannel:
    protocol_name = b"Noise_KK_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket
    user_key: x25519.X25519PrivateKey
    server_key: x25519.X25519PublicKey

    def __init__(
            self,
            soc: socket,
            user_key: x25519.X25519PrivateKey,
            server_key: x25519.X25519PublicKey,
    ) -> None:
        self.soc = soc
        self.user_key = user_key
        self.server_key = server_key
        self.handshake()

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.protocol_name)
        noise.set_as_initiator()
        noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            self.user_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )
        noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            self.server_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
        noise.start_handshake()
        message = noise.write_message()
        self.soc.sendall(message)

        received = self.soc.recv(self.recv_buffersize)
        noise.read_message(received)

        self.noise = noise

    def send(self, data: bytes) -> None:
        self.soc.sendall(self.noise.encrypt(data))

    def receive(self) -> bytes:
        data = self.soc.recv(self.recv_buffersize)
        if data:
            return self.noise.decrypt(data)

        return None


class RegisterChannel:
    protocol_name: bytes = b"Noise_NK_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket

    def __init__(self, soc: socket) -> None:
        self.soc = soc
        self.handshake()

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.protocol_name)
        # Set role in this connection as initiator
        noise.set_as_initiator()
        noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            excpected_pub_key
        )
        # Enter handshake mode
        noise.start_handshake()

        # Perform handshake - as we are the initiator, we need to generate first message.
        # We don't provide any payload (although we could, but it would be cleartext for this pattern).
        message = noise.write_message()
        self.soc.sendall(message)

        # Receive the message from the responder
        received = self.soc.recv(self.recv_buffersize)
        # Feed the received message into noise
        payload = noise.read_message(received)
        # Payload, probably extra data? Might be something used for certificate?

        self.noise = noise

    def send(self, data: bytes) -> None:
        self.soc.sendall(self.noise.encrypt(data))

    def receive(self) -> bytes:
        data = self.soc.recv(self.recv_buffersize)
        if data:
            return self.noise.decrypt(data)

        return None


class Client:
    server_address: Tuple[str, int]
    key_store: str
    client_key: x25519.X25519PrivateKey
    server_key: x25519.X25519PublicKey

    def __init__(self, host, port) -> None:
        self.server_address = (host, port)
        self.client_key = x25519.X25519PrivateKey.generate()

    def register(self, login, ectx):
        """Register creates keypair for the client,
        it then sends server the user login and its
        public key. Server responds with its own public
        key, so they can use these longterm static keys
        for future authentication during messaging"""

        soc = socket(AF_INET, SOCK_STREAM)
        soc.connect(self.server_address)

        logging.debug("Registering...")
        soc.sendall(b"REGISTER\n")

        status = soc.recv(2048)
        if status != b"OK\n":
            logging.error("Register command failed")
            return

        channel = RegisterChannel(soc)

        pub_bytes = self.client_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        _, _, _, _, quote_data = get_signed_pcr(ectx, b"123456789")
        pcr_hash = quote_data[-32:]
        register_data = {"login": login, "pubkey": pub_bytes.decode("utf8"), "pcr_hash": pcr_hash.hex()}
        logging.debug(f"Sending register data:\n{register_data}")
        channel.send(json.dumps(register_data).encode("utf8"))

        response = channel.receive()
        logging.debug(f"Server responded with:\n{response}")

        resp_js = json.loads(response)
        server_pub = resp_js["pubkey"]
        logging.debug(f"Got server public key:\n{server_pub}")

        self.server_key = serialization.load_pem_public_key(server_pub.encode("utf8"))

        logging.debug("Sending OK")
        channel.send(b"OK\n")

        status = channel.receive()
        logging.debug(f"Got status {status} back")
        if status != b"OK\n":
            logging.error("Registration failed")
            return

        print("Registration was successful, closing connection")
        soc.close()

    def message(self, login, ectx):
        soc = socket(AF_INET, SOCK_STREAM)
        soc.connect(self.server_address)

        logging.debug("Messaging...")
        soc.sendall(b"MESSAGE\n")

        status = soc.recv(2048)
        if status != b"OK\n":
            logging.error("Message command failed")
            return

        soc.sendall(login.encode("utf8"))
        status = soc.recv(2048)
        if status != b"OK\n":
            logging.error("Message command failed")
            return

        rand_nonce = soc.recv(2048)
        x, y, r, s, quote = get_signed_pcr(ectx, rand_nonce)
        pcr_quote_data = {"x": x.hex(), "y": y.hex(), "r": r.hex(), "s": s.hex(), "quote": quote.hex()}
        logging.debug(f"Sending PCR quote data:\n{pcr_quote_data}")
        soc.sendall(json.dumps(pcr_quote_data).encode("utf8"))
        status = soc.recv(2048)
        if status != b"OK\n":
            logging.error("Message command failed")
            return

        logging.debug("Creating Message channel")
        print("Logging in")
        channel = MessageChannel(soc, self.client_key, self.server_key)

        print(
            "Connected to server, you can type your messages now\nYou can end the communication by typing END or pressing Ctrl + C\n")

        try:
            while True:
                print("Your message:", end='')
                message = input()
                if (message == "END"):
                    break
                channel.send(message.encode("utf8"))
                response = channel.receive()
                print(f"Server: {response}")
        except (EOFError, KeyboardInterrupt):
            pass
        except Exception as ex:
            print(f"An unexpected error happened, reason: {str(ex)}")
        finally:
            pass
            channel.send(b"END\n")

        print("Communication finished, closing connection")
        soc.close()


def parse_arguments():
    arg_parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=
    f"""
    This is a simple communication application which allows you to store messages on a server
    provided in server.py. Keep in mind, that the messages are stored in memory only, so stored
    keys and messages will be deleted when the server is shut down.\n
    This client will first register itself on the provided server (currently pointing
    to localhost for the sake of the project) and then log in along with TPM-based authentication.
    """)

    arg_parser.add_argument("-d", "--debug", help="Turns on debugging messages", action="store_true")
    args = arg_parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")


if __name__ == "__main__":
    parse_arguments()

    client = Client("127.0.0.1", 65432)
    ectx = init_tpm()
    try:
        client.register("xhajek10", ectx)
        client.message("xhajek10", ectx)
        shutdown_tpm(ectx)
    except Exception as ex:
        print(f"An unexpected error happened, reason: {str(ex)}")
