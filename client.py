import socket
import crypto
import pickle
import datetime

rsaKeyFilename = 'c-key.pem'
publicKeyMerchant = 'm-public.pem'
publicKeyPG = 'pg-public.pem'

produse = {
    "produs1": 20,
    "produs2": 130
}

if __name__ == "__main__":
    HOST = 'localhost'
    PORT = 8999
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        produs = 'produs2'

        key = crypto.importKey(rsaKeyFilename)
        pubKM = crypto.loadPublicKey(publicKeyMerchant)
        pubKPG = crypto.loadPublicKey(publicKeyPG)
        AESkey = b'1234567890123456'
        AESkeyPG = b'0123456789123456'

        # setup sub-protocol
        # step 1
        print('Step 1')
        #{PubKC} aes
        #{aes} PubKM
        encryptedMessage = crypto.encryptAES(key.publickey().export_key(), AESkey)
        encryptedKey = crypto.encryptRSA(AESkey, pubKM)
        s.sendall(pickle.dumps({'cipertext': encryptedMessage[0],
                                'nonce': encryptedMessage[1],
                                'tag': encryptedMessage[2],
                                'key': encryptedKey}))

        # step 2
        print('Step 2')
        data = pickle.loads(s.recv(10000))
        data = {'cipertext': data['cipertext'][0], 'nonce': data['cipertext'][1], 'tag': data['cipertext'][2]}

        message = crypto.decryptAES(data, AESkey)
        content = pickle.loads(message)
        SID = content['sid']
        print('Am primit SID = ', SID)
        if crypto.verifySignature(content['sid'], content['signedSid'], publicKeyMerchant):
            print("Valid signature\n")
        else:
            print("Invalid signature")
            s.close()

        # exchange sub-protocol
        # step 3
        print('Step 3')
        #Payment Information
        #PI = (CardInf, Amount, PIN, Sid, NonCPG, M)
        pi = {'cardN': b'4026467078008334',
              'cardExp': datetime.datetime(2020, 9, 10),
              'PIN': b'2334',
              'amount': produse[produs],
              'sid': SID,
              'nc': 1,
              'M': b'merchantName'}

        #Payment Message
        #PM = {PI, DSigC(PI)} PubKPG
        #prevent the merchant from seeing the credit Card info
        pm = {'pi': pickle.dumps(pi),
              'signedPi': crypto.sign(pickle.dumps(pi), rsaKeyFilename)}
        #the message is encrypted using the PubKPG
        encryptedPm = crypto.encryptAES(pickle.dumps(pm), AESkeyPG)
        encryptedPGkey = crypto.encryptRSA(AESkeyPG, pubKPG)

        #relevant order info
        #OI
        poContent = pickle.dumps({
            'orderDesc': produs,
            'sid': SID,
            'amount': produse[produs]
        })
        #semnatura digitala pentru OI
        po = {
            'poContent': poContent,
            'signedPo': crypto.sign(poContent, rsaKeyFilename)
        }

        encryptedMessage = crypto.encryptAES(pickle.dumps({'encryptedPm': encryptedPm,
                                                            'encryptedPGkey': encryptedPGkey,
                                                            'po': po}), AESkey)
        encryptedKey = crypto.encryptRSA(AESkey, pubKM)

        s.sendall(pickle.dumps({'encryptedMessage': encryptedMessage, 'encryptedKey': encryptedKey}))
        print('\n')

        # Step 6
        print('Step 6')
        data = pickle.loads(s.recv(1000))
        AESkey = crypto.decryptRSA(data['encryptedKey'], key)
        pgResponseEncrypted = {
            'cipertext': data['pgResponse'][0],
            'nonce': data['pgResponse'][1],
            'tag': data['pgResponse'][2]
        }
        pgResponse = pickle.loads(crypto.decryptAES(pgResponseEncrypted, AESkey))
        # verify PG signature
        print('Verify PG signature')
        msg = pickle.dumps({
            'resp': pgResponse['resp'],
            'sid': pgResponse['sid'],
            'amount': produse[produs],
            'nc': 1
        })
        crypto.verifySignature(msg, pgResponse['signedMessage'], publicKeyPG)
        print('Am primit raspunsul pentru tranzactie = ', pgResponse['resp'])