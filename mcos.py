import socket
import sys
from traceback import print_exc
import Crypto
import cryptography
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    CipherContext,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import logging


def printExceptionAndExit():
    """Print the exception and exit"""
    print_exc()
    sys.exit(1)


def get_private_key_from_file(filename: str):
    """Get the private key from a file
    :param filename: The filename to read the key from

    :returns: The private key"""
    file = open(filename, "r")
    key = file.read()
    file.close()

    private_key = load_pem_private_key(
        key.encode(),
        password=None,
    )

    return private_key


class McosEncryptionPair:
    """Mcos encryption pair
    :param type: The type of encryption pair
    :param tsCipher: The cipher for the encryption pair
    :param tsDecipher: The decipher for the encryption pair

    :raises ValueError: If the key is too short"""

    def __init__(self, type: str, tsCipher: CipherContext, tsDecipher: CipherContext):
        self._Type = type
        self._Cipher = tsCipher
        self._Decipher = tsDecipher


def decryptSessionKey(key: bytes, private_key: rsa.RSAPrivateKey):
    """Decrypt the session key
    :param key: The key to decrypt
    :param private_key: The private key to use

    :returns: The decrypted session key"""

    # Decrypt the session key
    sessionKey = private_key.decrypt(
        key,
        padding=padding.PKCS1v15(),
    )

    return sessionKey


def createDataEncryptionPair(key):
    if len(key) < 16:
        raise ValueError("Key too short")

    # Convert the hex key to bytes
    stringKey = bytes.fromhex(key)

    # Create a cipher with RC4 algorithm
    tsCipher = Cipher(algorithms.ARC4(stringKey[:16]), mode=None).encryptor()
    tsDecipher = Cipher(algorithms.ARC4(stringKey[:16]), mode=None).decryptor()

    return McosEncryptionPair("data", tsCipher, tsDecipher)


def createCommandEncryptionPair(key):
    """Create a command encryption pair
    :param key: The key to use

    :returns: A McosEncryptionPair

    :raises ValueError: If the key is too short"""
    if len(key) < 16:
        raise ValueError("Key too short")

    # Convert the hex key to bytes
    stringKey = bytes.fromhex(key)

    # Create a cipher with 3DES algorithm
    gsCipher = Cipher(
        algorithms.TripleDES(stringKey),
        mode=modes.CBC(bytes.fromhex("0000000000000000")),
    ).encryptor()
    gsDecipher = Cipher(
        algorithms.TripleDES(stringKey),
        mode=modes.CBC(bytes.fromhex("0000000000000000")),
    ).decryptor()

    return McosEncryptionPair("command", gsCipher, gsDecipher)


def parseStringWithLengthPrefix(data: bytes):
    """Parse a string with a length prefix
    :param data: The data to parse

    :returns: The parsed string"""
    # Get the length of the string
    length = int(data[0:2].hex(), 16)

    # Get the string
    string = data[2 : 2 + length].decode("utf-8")

    return string


class BasePacketHeader:
    """Base packet header"""

    def __init__(self, opcode: int, length: int):
        self._opcode: int = opcode  # 2 bytes
        self._length: int = length  # 2 bytes

    def __str__(self):
        return "Opcode: {0}\nLength: {1}".format(self._opcode, self._length)


class RawPacket:
    """Raw packet"""

    def __init__(self, buf: bytes, length: int = 4):
        try:
            # Parse the packet
            assert len(buf) >= length
            self.parse(buf)
        except AssertionError:
            raise ValueError(
                "Packet length mismatch. Expected at least {0} bytes, got {1} bytes".format(
                    length, len(buf)
                )
            )

        except:
            printExceptionAndExit()

    def parse(self, buf: bytes):
        """Parse a packet"""
        try:
            self._header = new = BasePacketHeader(
                int(buf[0:2].hex(), 16), int(buf[2:4].hex(), 16)
            )
            assert len(buf) >= (self._header._length)
            self._data = buf[4:].hex()
        except AssertionError:
            raise ValueError(
                "Packet length mismatch. Expected {0} bytes, got {1} bytes".format(
                    4 + self._header._length, len(buf)
                )
            )
        except:
            printExceptionAndExit()

    def __str__(self):
        return "Header:\n{0}\nData:\n{1}".format(self._header, self._data)


class VersionedPacketHeader(BasePacketHeader):
    """Versioned packet header"""

    def __init__(self, opcode, length, version):
        super().__init__(opcode, length)
        self._Version = version
        self._Reserved = 0
        self._Checksum = 0

        assert self._Checksum == self._length

    def __str__(self):
        return "Opcode: {0}\nLength: {1}\nVersion: {2}".format(
            self._opcode, self._length, self._Version
        )


class LoginPacket(RawPacket):
    """Login packet"""

    def __init__(self, buf: bytes):
        super().__init__(buf, 12)
        self.parse(buf)

    def parse(self, buf: bytes):
        """Parse a login packet"""
        try:
            self._header = new = VersionedPacketHeader(
                int(buf[0:2].hex(), 16),
                int(buf[2:4].hex(), 16),
                int(buf[4:6].hex(), 16),
            )
            assert len(buf) >= (self._header._length)
            self._data = buf[12:].hex()
        except AssertionError:
            raise ValueError(
                "Packet length mismatch. Expected {0} bytes, got {1} bytes".format(
                    4 + self._header._length, len(buf)
                )
            )
        except:
            printExceptionAndExit()

    def __str__(self):
        return "Header:\n{0}\nData:\n{1}".format(self._header, self._data)


def parsePacket(data: bytes):
    """Parse a packet"""
    # Parse the packet
    try:
        packet = RawPacket(data)

        # Check the opcode
        opcode = packet._header._opcode

        match opcode:
            case 0x501:
                print("Login packet")
            case _:
                print("Unknown packet")

        print(packet)

        return packet
    except ValueError:
        print_exc()
        sys.exit(1)

    except:
        print("Unknown error")
        sys.exit(1)


def main():
    __name__ = "mcos"
    logging.basicConfig(filename="mcos.log", level=logging.DEBUG, encoding="utf-8")
    logger = logging.getLogger(__name__)

    HOST = "0.0.0.0"
    EXTERNAL_HOST = "mcouniverse.com"
    LOGIN_PORT = 8226

    try:
        with socket.create_server((HOST, LOGIN_PORT)) as s:
            logger.info("Server started")
            conn, addr = s.accept()
            with conn:
                logger.info(
                    "Connected by %s : %s", addr.__getitem__(0), addr.__getitem__(1)
                )
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break

                    logger.info("Received data: %s", data.hex())

                    # Parse the packet
                    packet = parsePacket(data)

    except ConnectionRefusedError:
        logger.error("Connection refused")
        sys.exit(1)

    except ConnectionResetError:
        logger.error("Connection reset")
        sys.exit(1)

    except ConnectionAbortedError:
        logger.error("Connection aborted")
        sys.exit(1)

    except OSError as e:
        logger.error("OS Error: {0}".format(e))
        sys.exit(1)

    except:
        logger.error("Unknown error")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except:
        printExceptionAndExit()
