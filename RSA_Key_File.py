from Crypto.PublicKey import RSA

def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')
    print("%s private Key: %s" % (userName, priKey))
    pubKey = privateKey.publickey()
    print("%s public Key: %s" % (userName, pubKey.exportKey('PEM')))
    return priKey, pubKey


def write_RSA_Key_to_File(userName):
    priKeyFileName = "./"+userName+"/" + userName + "_private_Key.bin"
    file_out = open(priKeyFileName, 'wb')
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')
    file_out.write(bytes(priKey))
    file_out.close()
    pubKeyFileName = "./" + userName + "/" + userName + "_public_Key.bin"
    file_out = open(pubKeyFileName, 'wb')
    pubKey = privateKey.publickey()
    file_out.write(bytes(pubKey.exportKey('PEM')))
    file_out.close()
    return priKey, pubKey


def main():

    alice_priKey, alice_pubKey = write_RSA_Key_to_File("Alice")
    print("%s's private Key: %s" % ("Alice", alice_priKey))
    print("%s's public Key: %s" % ("Alice", alice_pubKey.exportKey('PEM')))

    bob_priKey, bob_pubKey = write_RSA_Key_to_File("Bob")
    print("%s's private Key: %s" % ("Bob", bob_priKey))
    print("%s's public Key: %s" % ("Bob", bob_pubKey.exportKey('PEM')))


if __name__ == "__main__":
    main()