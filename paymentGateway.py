import datetime
import uuid
import socket
import crypto
import pickle

HOST, PORT = "localhost", 9009
filenameKey = 'pg-key.pem'
publicKeyMerchant = 'm-public.pem'
publicKeyClient = 'c-public.pem'
cards = [
    {
        'cardN': b'4026467078008334',
        'cardExp': datetime.datetime(2020, 9, 10)
    }
]

cardAmount = {
    cards[0]['cardN']: 400
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        while True:
            # step 4
            data = pickle.loads(conn.recv(10000))

            key = crypto.importKey(filenameKey)
            pubKM = crypto.loadPublicKey(publicKeyMerchant)

            AESkeyM = crypto.decryptRSA(data['encryptedKey'], key)
            encryptedMessage = {
                'cipertext': data['encryptedOrder'][0],
                'nonce': data['encryptedOrder'][1],
                'tag': data['encryptedOrder'][2]
            }
            order = pickle.loads(crypto.decryptAES(encryptedMessage, AESkeyM))
            print('Order: ', order)
            # decrypt client message
            print('Decrypt client message')
            AESkeyC = crypto.decryptRSA(order['encryptedPmKey'], key)
            clientMessage = {
                'cipertext': order['pm'][0],
                'nonce': order['pm'][1],
                'tag': order['pm'][2]
            }
            clientOrder = pickle.loads(crypto.decryptAES(clientMessage, AESkeyC))
            # verify client signature
            print('Verify client signature')
            if crypto.verifySignature(clientOrder['pi'], clientOrder['signedPi'], publicKeyClient) == False:
                print("Invalid signature, Closing the connection...")
                conn.close()
            pi = pickle.loads(clientOrder['pi'])
            # verify merchant signature
            mm = pickle.dumps({
                'sid': pi['sid'],
                'pubKC': order['pubKC'],
                'amount': pi['amount']
            })
            print('Verify merchant signature')
            if crypto.verifySignature(mm, order['signedMm'], publicKeyMerchant) == False:
                print("Invalid signature, Closing the connection...")
                conn.close()

            # step 5
            print('Step 5')
            # verify client CARD
            clientNonce = pi['nc']
            resp = 'OK'
            if {'cardN': pi['cardN'], 'cardExp': pi['cardExp']} not in cards:
                resp = 'Invalid card'
                print(resp)
            else:
                if cardAmount[pi['cardN']] < pi['amount']:
                    resp = 'Insuficient founds'
                    print(resp)
                else:
                    # modify account balance
                    cardAmount[pi['cardN']] -= pi['amount']
                    resp = resp + '\tCard Balance: ' + str(cardAmount[pi['cardN']])
            #the response along with all the other info is DG
            signedMessage = crypto.sign(pickle.dumps(
                {'resp': resp,
                 'sid': pi['sid'],
                 'amount': pi['amount'],
                 'nc': clientNonce}
            ), filenameKey)

            transactionInfo = pickle.dumps({
                'resp': resp,
                'sid': pi['sid'],
                'signedMessage': signedMessage
            })
            encryptedTransactionInfo = crypto.encryptAES(transactionInfo, AESkeyM)
            encryptedKey = crypto.encryptRSA(AESkeyM, pubKM)
            conn.sendall(pickle.dumps({'encryptedTransactionInfo': encryptedTransactionInfo,
                                       'encryptedKey': encryptedKey}))
            print('Am trimis informatiile criptate ale  tranzactiei ')
            conn.close()
            break