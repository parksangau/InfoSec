from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512



def gen_RSA_Key(userName):
    privateKey = RSA.generate(2048)
    priKey = privateKey.exportKey('PEM')    # priKey : private key
    print("%s's private key: %s" % (userName, priKey))
    pubKey = privateKey.publickey()
    print("%s's public key: %s" % (userName, pubKey))
    print("%s's public key: %s" % (userName, pubKey.exportKey('PEM')))
    return priKey, pubKey


def rsaEncrypt(message, pubKey):
    rsaCipher = PKCS1_OAEP.new(pubKey)
    encrypted = rsaCipher.encrypt(message)
    return encrypted


def rsaDecrypt(encrypted, priKey):
    privateKey = RSA.importKey(priKey)
    rsa_Decrypt = PKCS1_OAEP.new(privateKey)
    decrypted = rsa_Decrypt.decrypt(encrypted)
    return decrypted


def rsaDigSignGen(message, priKey):
    myhash = SHA512.new(message)
    privateKey = RSA.importKey(priKey)
    signature = PKCS1_v1_5.new(privateKey)
    signMsg = signature.sign(myhash)
    return signMsg


def rsaDigSignVerify(signMsg, message, pubKey):
    myhash = SHA512.new(message)
    signature = PKCS1_v1_5.new(pubKey)
    try:
        signature.verify(myhash, signMsg)
        return True
    except (ValueError, TypeError):
        return False


def main():
    message = b'Information security and Programming, Test Message!!!!'
    print("Message: ", message)


    #Part 1 : public Key Cryptography