import logging
from socket import socket, AF_INET, SOCK_STREAM
from noise.connection import NoiseConnection


class Client:
    recv_buffer: int = 4096
    pattern_nn: bytes = b"Noise_NN_25519_ChaChaPoly_SHA256"

    def connect(self, host, port) -> socket:
        soc = socket(AF_INET, SOCK_STREAM)
        soc.connect((host, port))

        return soc

    def send(self, soc: socket, data: bytes):
        # For consistency with rest of the interface, even if it is just 1 call
        soc.sendall(data)

    def receive(self, soc: socket) -> bytes:
        # TODO idea is to read whole message here if its longer than limit
        # to recv()
        return soc.recv(self.recv_buffer)

    def disconnect(self, soc: socket):
        soc.close()

    def handshake_NN(self, soc: socket) -> NoiseConnection:
        noise = NoiseConnection.from_name(self.pattern_nn)
        # Set role in this connection as initiator
        noise.set_as_initiator()
        # Enter handshake mode
        noise.start_handshake()

        # Perform handshake - as we are the initiator, we need to generate first message.
        # We don't provide any payload (although we could, but it would be cleartext for this pattern).
        message = noise.write_message()
        self.send(soc, message)

        # Receive the message from the responder
        received = self.receive(soc)
        # Feed the received message into noise
        payload = noise.read_message(received)
        # Payload, probably extra data? Might be something used for certificate?

        return noise

    def register(self, host, port):
        soc = self.connect(host, port)

        # Send server that we want to register
        logging.info("Sending command")
        self.send(soc, b"REGISTER\n")

        noise = self.handshake_NN(soc)

        # As of now, the handshake should be finished (as we are using NN pattern).
        # Any further calls to write_message or read_message would raise NoiseHandshakeError exception.
        # We can use encrypt/decrypt methods of NoiseConnection now for encryption and decryption of messages.
        encrypted_message = noise.encrypt(b'{user: "pepa", shared_key: "kappa123"}')
        # TODO maybe hide the noise encrypt/decrypt into the sending/receiving interface?
        # we never communicate without noise anyway
        self.send(soc, encrypted_message)

        ciphertext = self.receive(soc)
        plaintext = noise.decrypt(ciphertext)

        print(plaintext)

        self.disconnect(soc)


if __name__ == "__main__":
    client = Client()
    client.register("127.0.0.1", 65432)
