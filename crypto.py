from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA


def encryptAES(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    # Encrypt and digest to get the ciphered data and tag
    cipertext, tag = cipher.encrypt_and_digest(message)
    return (cipertext, nonce, tag)

def decryptAES( encryptedMessage, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=encryptedMessage['nonce'])
    plaintext = cipher.decrypt(encryptedMessage['cipertext'])
    try:
        cipher.verify(encryptedMessage['tag'])
        print("DECRYPT WITH AES: Message is authentic")
    except ValueError:
        print("DECRYPT WITH AES: Corrupted message")
    return plaintext


def generateKey():
    key = RSA.generate(2048)
    return key


def exportKey(key,filename):
    f = open(filename, 'wb')
    f.write(key.export_key('PEM'))
    f.close()

def importKey(filename):
    f = open(filename, 'r')
    key = RSA.import_key(f.read())
    f.close()
    return key

def importKey2(message):
    return RSA.importKey(message)

def savePublicKey(key, filename):
    f = open(filename, 'wb')
    f.write(key.publickey().export_key())
    f.close()

def loadPublicKey(filename):
    f = open(filename,'rb')
    key = RSA.import_key(f.read())
    f.close()
    return key

def encryptRSA( message, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def decryptRSA( message, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)


def sign(message, keyFilemane):
    key = RSA.import_key(open(keyFilemane).read())
    h = SHA256.new(message)
    return pkcs1_15.new(key).sign(h)

def verifySignature( message, signature, keyFilename):
        key = loadPublicKey(keyFilename)
        h = SHA256.new(message)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

if __name__ == "__main__":
    serverKey = 'm-key.pem'
    clientKey = 'c-key.pem'
    pgKey = 'pg-key.pem'
    publicKeyServer = 'm-public.pem'
    publicKeyClient = 'c-public.pem'
    publicKeyPG = 'pg-public.pem'

    # generate RSA key for client
    rsaClient = generateKey()
    exportKey(rsaClient, clientKey)
    savePublicKey(rsaClient,publicKeyClient)

    # generate RSA key for merchant
    rsaMerchant = generateKey()
    exportKey(rsaMerchant, serverKey)
    savePublicKey(rsaMerchant,publicKeyServer)
    # generate RSA key for PG
    rsaPG = generateKey()
    exportKey(rsaPG, pgKey)
    savePublicKey(rsaPG,publicKeyPG)