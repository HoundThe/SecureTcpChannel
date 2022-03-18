import logging
from socket import socket, AF_INET, SOCK_STREAM
from noise.connection import NoiseConnection
import noise.constants as constants


class RegisterChannel:
    pattern_nn: bytes = b"Noise_NN_25519_ChaChaPoly_SHA256"
    # Using that by specification, maximum noise message is 64k
    recv_buffersize = constants.MAX_MESSAGE_LEN
    noise: NoiseConnection
    soc: socket

    def __init__(self, soc: socket) -> None:
        self.soc = soc
        self.handshake()

    def handshake(self) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.pattern_nn)
        # Set role in this connection as initiator
        noise.set_as_initiator()
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
    def register(self, host, port):
        soc = socket(AF_INET, SOCK_STREAM)
        soc.connect((host, port))

        logging.debug("Registering...")
        soc.sendall(b"REGISTER\n")
        status = soc.recv(2048)
        if status != b"OK\n":
            logging.error("Register command failed")
            return

        channel = RegisterChannel(soc)

        channel.send(b'{user: "pepa", shared_key: "kappa123"}')
        status = channel.receive()

        logging.debug(f"Server responded with:\n{status}")

        if status != b"OK\n":
            logging.error("Register command failed")
            return

        logging.debug("Register was successfull, closing connection")
        soc.close()


if __name__ == "__main__":
    # TODO let user set logging level in CLI
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")

    client = Client()
    client.register("127.0.0.1", 65432)
