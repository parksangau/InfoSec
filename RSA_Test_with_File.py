from Crypto.PublicKey import RSA
from RSA_and_DigSign import rsaEncrypt, rsaDecrypt


def read_RSA_Private_Key_from_File(userName):
    priKeyFileName = "./"+userName+"/" + userName + "_private_Key.bin"
    privateKey = RSA.importKey(open(priKeyFileName, 'rb').read())
    priKey = privateKey.exportKey('PEM')
    return priKey

def read_RSA_Public_Key_from_File(userName):
    pubKeyFileName = "./" + userName + "/" + userName + "_public_Key.bin"
    publicKey = RSA.importKey(open(pubKeyFileName, 'rb').read())
    return publicKey


def main():

    # ##### Alice
    message = b'Information security and Programming, Test Message!!! Name : Brother.. '
    print("Message: ", message)

    print("\n**Message Encryption using RSA Key(Receiver's pubKey)")
    bob_pubKey_read = read_RSA_Public_Key_from_File("Bob")

    encrypted = rsaEncrypt(message, bob_pubKey_read)
    print("Size of Encrypted(CipherText): ", len(encrypted))  # 2048 / 8 = 256 byte
    print("Encrypted(CipherText): ", encrypted.hex())

    # """
    # By Client-Server Network(TCP/IP), encrypted
    # """
    # Receiver Bob : Decrypt Message By Bob

    # print("\n**Ciphertext Decryption using RSA Key(Receiver's priKey)")
    # bob_priKey_read = read_RSA_Private_Key_from_File("Bob")
    # decrypted = rsaDecrypt(encrypted, bob_priKey_read)
    # print("Decrypted(PlainText): ", decrypted.decode())

    bob_priKey_read=read_RSA_Private_Key_from_File("Bob")
    encrypted_hexadecimal_string = "45383d8f28470de80ee5aba760550826e9effd2ec211049d5a5b99731061c34ebee5e1d3c4f3a18bc5382bccfc1c90ee52f54223cb678993157f96b87a34c836cc42ce8f0aaf802bc70b1d80d1517ca9dafd7ae9aea909658354288206cc59300dbfd11b260862610cdcc94ba3b75125ae734faf505fd4a883e85114f88174398f5eedb8e9f3939c0781973af956dcb89c5d295a9086e35be862bffdf4449a6c237828faca5bbfbaff36361662e441246dd4c0e5e3b6e3ff2c79ea936576d38917aec51351a3ba178c20d23329e346a09e8d01f976b19a185910559b9a3d52bd8b14368ed32e77a8e1983ff133173532988b087edcf4e39e19e72f04dc9df3ed"
    encrypted_byte_array = bytearray.fromhex(encrypted_hexadecimal_string)
    decrypted = rsaDecrypt(encrypted_byte_array, bob_priKey_read)
    print("Decrypted(from Console): ", decrypted.decode())


if __name__ == "__main__":
    main()