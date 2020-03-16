import socketserver
import uuid
import socket
import json
import crypto
import pickle

produse = {
    "produs1": 20,
    "produs2": 130
}

HOST, PORT = "localhost", 8999
rsaKeyFilename = 'm-key.pem'
publicKeyClient = 'c-public.pem'
publicKeyPG = 'pg-public.pem'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        while True:
            # Trimite lista cu produse
            #conn.sendall(pickle.dumps(produse))

            key = crypto.importKey(rsaKeyFilename)

            # setup sub-protocol
            # step 1
            print('Step 1')
            data = pickle.loads(conn.recv(10000))
            #decriptez cheia simetrica AES si PubKC
            AESkey = crypto.decryptRSA(data['key'], key)
            pubKCneimported = crypto.decryptAES(data, AESkey)
            pubKC = crypto.importKey2(pubKCneimported)

            # step 2
            print('Step 2')
            SID = uuid.uuid4().bytes
            #DSigM(Sid)
            signedSID = crypto.sign(SID, rsaKeyFilename)
            #criptez {SID, DSigM(Sid)} cu o cheie simetrica
            encryptedMessage = crypto.encryptAES(pickle.dumps({'sid': SID, 'signedSid': signedSID}), AESkey)
            #cheia simetrica este criptata cu PubKC
            encryptedKey = crypto.encryptRSA(AESkey, pubKC)

            conn.sendall(pickle.dumps({'cipertext': encryptedMessage}))
            print('Am trimis SID = ', SID, '\n')

            # exchange sub-protocol
            # step 3
            print('Step 3')
            data = pickle.loads(conn.recv(20000))
            #cheia AES exte criptata cu PubKM
            AESkey = crypto.decryptRSA(data['encryptedKey'], key)
            #{'encryptedPm': encryptedPm,
            #'encryptedPGkey': encryptedPGkey,
            #'po': po}
            message = {
                'cipertext': data['encryptedMessage'][0],
                'nonce': data['encryptedMessage'][1],
                'tag': data['encryptedMessage'][2]
            }
            #mesajul este criptat cu AES
            message = pickle.loads(crypto.decryptAES(message, AESkey))
            # verify client signature on PO
            print('Verify client signature on PO')
            if crypto.verifySignature(message['po']['poContent'], message['po']['signedPo'], publicKeyClient) == False:
                print("Invalid signature, Closing the connection...")
                conn.close()
            poContent = pickle.loads(message['po']['poContent'])
            # verify SID
            if SID != poContent['sid']:
                print('Invalid SID')
            print('\n')
            print('Step 4')

            # step 4
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spg:
                PGHOST = 'localhost'
                PGPORT = 9009
                spg.connect((PGHOST, PGPORT))
                AESkeyPG = b'0123456789123499'
                pubPG = crypto.loadPublicKey(publicKeyPG)
                #the Pm is forwarded to the PG
                #DSigM(Amount, PubKC, SID)
                merchantMessage = pickle.dumps({
                    'sid': SID,
                    'pubKC': pubKCneimported,
                    'amount': produse[poContent['orderDesc']]
                })
                signedMessage = crypto.sign(merchantMessage, rsaKeyFilename)

                order = pickle.dumps({
                    'pm': message['encryptedPm'],
                    'pubKC': pubKC.export_key(),
                    'encryptedPmKey': message['encryptedPGkey'],
                    'signedMm': signedMessage
                })

                encryptedOrder = crypto.encryptAES(order, AESkeyPG)
                encryptedKey = crypto.encryptRSA(AESkeyPG, pubPG)

                spg.sendall(pickle.dumps({'encryptedOrder': encryptedOrder,
                                          'encryptedKey': encryptedKey}))

                # step 5
                print('Step 5')
                data = pickle.loads(spg.recv(10000))

                AESkeyPG = crypto.decryptRSA(data['encryptedKey'], key)
                encryptedTransactionInfo = {
                    'cipertext': data['encryptedTransactionInfo'][0],
                    'nonce': data['encryptedTransactionInfo'][1],
                    'tag': data['encryptedTransactionInfo'][2]
                }
                pgResponse = pickle.loads(crypto.decryptAES(encryptedTransactionInfo, AESkeyPG))
                print('Am primit raspunsul ', pgResponse['resp'], '\n')

                # step 6
                print('Step 6')
                pgResponseBinary = crypto.encryptAES(pickle.dumps(pgResponse), AESkey)
                encryptedKey = crypto.encryptRSA(AESkey, pubKC)
                conn.sendall(pickle.dumps({'pgResponse': pgResponseBinary,
                                           'encryptedKey': encryptedKey}))
                print('Am criptat si am trimis raspunsul de la PG la Client')
                spg.close()
            conn.close()
            break