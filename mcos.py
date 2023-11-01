from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class McosEncryptionPair:
    def __init__(self, type, tsCipher, tsDecipher):
        self._Type = type
        self._Cipher = tsCipher
        self._Decipher = tsDecipher


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
    if len(key) < 16:
        raise ValueError("Key too short")

    # Convert the hex key to bytes
    stringKey = bytes.fromhex(key)

    # Create a cipher with 3DES algorithm
    gsCipher = Cipher(
        algorithms.TripleDES(stringKey[:16]),
        mode=modes.CBC(bytes.fromhex("0000000000000000")),
    ).encryptor()
    gsDecipher = Cipher(
        algorithms.TripleDES(stringKey[:16]),
        mode=modes.CBC(bytes.fromhex("0000000000000000")),
    ).decryptor()

    return McosEncryptionPair("command", gsCipher, gsDecipher)


def main():
    # Create a key
    skey = "f31b45589438463a"
    sessionKey = "84d2b3b979dc230c150f173101068593"

    dataStart = bytearray.fromhex(
        "d50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )

    commandStart = bytearray.fromhex("02dec1bc8578b687")

    # Create a data encryption pair
    dataEncryptionPair = createDataEncryptionPair(sessionKey)
    
    print(dataEncryptionPair._Type)
    print(dataStart.hex())

    # Encrypt some data
    dataCt = dataEncryptionPair._Cipher.update(dataStart)

    print(dataCt.hex())

    # Decrypt the data
    data_pt = dataEncryptionPair._Decipher.update(dataCt)

    # Print the decrypted data
    print(data_pt.hex())

    # ---------------------------------------------------------------------------------------------
    print("-----------------------------------------------------------------------------------------------")
    # Now encrypt the command


    # Create a command encryption pair
    commandEncryptionPair = createCommandEncryptionPair(skey)
    
    print(commandEncryptionPair._Type)
    print(commandStart.hex())

    # Encrypt some data
    commandCt = commandEncryptionPair._Cipher.update(commandStart)

    print(commandCt.hex())

    # Decrypt the data
    command_pt = commandEncryptionPair._Decipher.update(commandCt)

    # Print the decrypted data
    print(command_pt.hex())


if __name__ == "__main__":
    main()
