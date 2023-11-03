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
    
    print(stringKey.hex())

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


def main():
    # Create a key
    skey = "1393b98ba384b184"
    sessionKey = "1393b98ba384b184122dff374d196ce9ec75ea5d55763bce8cef8f136bb628a1"

    dataStart = bytearray.fromhex(
        "d50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )

    commandStart = bytearray.fromhex("030c0004cdcdcdcd")

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
