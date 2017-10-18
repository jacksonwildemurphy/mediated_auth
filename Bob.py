# Bob is 1 of 3 programs in this mediated key exchange application,
# along with Alice and a Key Distribution Center (KDC).
# This app implements both Needham-Schroeder and extended Needham-Schroeder.

import crypto_lib as Crypto
from socket import *


server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)
msg_from_Alice = 0 # initialize

# Symmetric key used by Bob and KDC
b_kdc_key = b"--BobKDCBobKDC--"
iv = b"00000000"
nonce_secret = "horsesflysnakeadjust"
bob_id = 353535

while 1:
    connection_socket, addr = server_socket.accept()
    msg_from_Alice = connection_socket.recv(1024).decode()
    print("Bob got from Alice:", msg_from_Alice)
    nonce = Crypto.get_nonce(nonce_secret)
    print("Nonce:", nonce)
    # Send encrypted nonce to Alice
    ciphertext = Crypto.des3_encrypt(b_kdc_key, iv, "CBC", nonce)
    print("Encrypted nonce to send to Alice:", ciphertext)
    print("Length of Encrypted nonce to send to Alice:", len(ciphertext))

    connection_socket.send(ciphertext)
    connection_socket.close()
