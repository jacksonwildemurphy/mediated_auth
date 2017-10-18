# Alice is 1 of 3 programs in this mediated key exchange application,
# along with Bob and a Key Distribution Center (KDC).
# This app implements both Needham-Schroeder and extended Needham-Schroeder.

import crypto_lib as Crypto
from socket import *

# Returns a bytes object consisting of 3 concatenated parts:
# N1, Alice wants Bob, Kb{Nb}
def _create_message_to_kdc(nonce_secret, alice_id, bob_id, enc_nonce_from_bob):
    nonce = Crypto.get_nonce(nonce_secret)
    request = alice_id + " wants " + bob_id
    msg = nonce.encode() + request.encode() + enc_nonce_from_bob
    return msg

# Pulls out N1, user id, Bob and Alice's shared key, and the ticket to Bob
# from the KDC's response.
# Raises an exception if N1 does not match what Alice sent, or if
# user id does not match Bob's.
def _parse_kdc_response(response):
    response = Crypto.des3_decrypt(a_key, iv, "CBC", response
    N1 = msg[:8].decode() # the nonce Alice created
    
    request = msg[8:(8 + len(" wants ") + len(alice_id) + len(bob_id))]
    Kb_Nb = msg[-16:] # Bob's nonce encrypted with his key
    Nb = Crypto.des3_decrypt(b_key, iv, "CBC", Kb_Nb).decode()
    return [N1, request, Nb]


# Alice's 3DES key suite with the KDC
# Note: this 16-byte key this turned into 2 64-bit DES keys by 3DES lib fcns
a_kdc_key = b'hidegoesdampbran'
iv = b'00000000' # 8 bytes
nonce_secret = "jumpfrostgrizzlyblack"
alice_id = "171717"
bob_id = "353535"


# Create TCP connection with Bob, requesting his encrypted nonce
server_name = "localhost"
server_port = 12000 # the port Bob is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))
msg = "I want to talk with you.\n"
client_socket.send(msg.encode())
enc_nonce_from_bob = client_socket.recv(1024)
print("Alice got from Bob:", enc_nonce_from_bob)
client_socket.close()

# Create TCP connection with KDC, requesting ticket to Bob
server_name = "localhost"
server_port = 13000 # the port KDC is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))
msg = _create_message_to_kdc(nonce_secret, alice_id, bob_id, enc_nonce_from_bob)
client_socket.send(msg)
kdc_response = client_socket.recv(1024)
[ticket_to_bob, a_b_key] = _parse_kdc_response(kdc_response)









# plaintext = 'I love you.'
# ciphertext = Crypto.des3_encrypt(key, iv, "CBC", plaintext)
# print("ciphertext:", ciphertext)
#
# original = Crypto.des3_decrypt(key, iv, "CBC", ciphertext)
# print(original)
