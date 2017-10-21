# Alice is 1 of 3 programs in this mediated key exchange application,
# along with Bob and a Key Distribution Center (KDC).
# This app implements both Needham-Schroeder and extended Needham-Schroeder.

import base64
import crypto_lib as Crypto
from socket import *
import sys

# If the extended NS protocol is being used, returns a bytes object consisting
# of 3 concatenated parts: N1, Alice wants Bob, Kb{Nb}
# If regular NS protocol is used, Kb{Nb} is not included
def _create_message_to_kdc(nonce_secret, alice_id, bob_id, enc_nonce_from_bob):
    nonce = Crypto.get_nonce(nonce_secret)
    request = alice_id + " wants " + bob_id
    msg = nonce.encode() + request.encode()
    if auth_protocol == "extended-ns":
        msg += enc_nonce_from_bob
    return [msg, nonce]

# Pulls out N1, user id, Bob and Alice's shared key, and the ticket to Bob
# from the KDC's response.
# Prints error and quits if N1 does not match what Alice sent, or if
# user id does not match Bob's.
def _parse_kdc_response(response):
    response = Crypto.des3_decrypt(a_key, iv, encryption_mode, response)
    nonce = response[:8].decode() # the nonce Alice created. nonce is 8 bytes
    if nonce != N1:
        print("Received nonce:", nonce, " from kdc but expected:", N1, "\n")
        sys.exit(0)
    user_id = response[8:14].decode() # user id is 6 bytes
    if user_id != bob_id:
        print("Expected Bob's id from the kdc, but instead got:", user_id, "\n")
        sys.exit(0)
    print("Received Bob's correct userid from KDC:", user_id, "\n")
    a_b_key = response[14:30].decode() # key is 16 bytes
    print("Received key to communicate with Bob:", a_b_key, "\n")
    ticket_to_bob = base64.decodestring(response[30:])
    return [ticket_to_bob, a_b_key]

# Creates a 64-bit nonce (N2 in NS protocol) and encrypts it with
# Alice's and Bob's shared key
def _create_Kab_N2(a_b_key, nonce_secret):
    N2 = Crypto.get_nonce(nonce_secret)
    print("Created nonce N2:", N2, "\n")
    Kab_N2 = Crypto.des3_encrypt(a_b_key, iv, encryption_mode, N2)
    return N2, Kab_N2

# Send msg to Trudy to simulate Trudy's "sniffing" Alice's connection with Bob
def _let_trudy_sniff(msg):
    name = "localhost"
    port = 14000 # the port Trudy is listening on
    client_socket_trudy = socket(AF_INET, SOCK_STREAM)
    client_socket_trudy.connect((name, port))
    client_socket_trudy.send(msg)
    client_socket_trudy.close()

# parse Kab{N2-1,N3}
def _parse_bobs_response(response):
    response = Crypto.des3_decrypt(a_b_key, iv, encryption_mode, response).decode()
    N2_minus_1 = response[:8] # nonce size = 8 bytes
    N3 = response[8:]
    if not Crypto.nonce_difference_is_1(N2_minus_1, N2):
        print("Bob did not send correct N2-1"); sys.exit(0)
    print("Received correct value for N2-1")
    print("Received N3:", N3)
    return N3


def _create_Kab_N3_minus_1(N3, a_b_key):
    N3_minus_1 = Crypto.decrement_hash(N3)
    return Crypto.des3_encrypt(a_b_key, iv, encryption_mode, N3_minus_1)

#### START OF PROGRAM ####

# Alice's 3DES key suite with the KDC
# Note: this 16-byte key this turned into 2 64-bit DES keys by 3DES lib fcns
a_key = b'hidegoesdampbran'
iv = b'00000000' # 8 bytes
nonce_secret = "jumpfrostgrizzlyblack"
# IMPORTANT that user ids are 6 chars long. Otherwise program will break.
alice_id = "171717"
bob_id = "353535"
enc_nonce_from_bob = 0 # initialize (will not be used in regular NS protocol)

# Determine the protocol and encryption mode to use
auth_protocol = Crypto.get_app_mode(sys.argv)
encryption_mode = Crypto.get_encryption_mode(sys.argv)

# For extended NS, establish connection with Bob, requesting his encrypted nonce
if auth_protocol == "extended-ns":
    server_name = "localhost"
    server_port = 12000 # the port Bob is listening on
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((server_name, server_port))
    msg = "I want to talk with you.\n"
    client_socket.send(msg.encode())
    enc_nonce_from_bob = client_socket.recv(1024)
    print("Received encrypted nonce from Bob\n")
    client_socket.close()

# Create TCP connection with KDC, requesting ticket to Bob
server_name = "localhost"
server_port = 13000 # the port KDC is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))
[msg, N1] = _create_message_to_kdc(nonce_secret, alice_id, bob_id, enc_nonce_from_bob)
client_socket.send(msg)
kdc_response = client_socket.recv(1024)
[ticket_to_bob, a_b_key] = _parse_kdc_response(kdc_response)
client_socket.close()

# Send ticket and encrypted nonce to Bob
server_name = "localhost"
server_port = 12000 # the port Bob is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))
[N2, Kab_N2] = _create_Kab_N2(a_b_key, nonce_secret) # nonce 2 encrypted with key AB
msg = ticket_to_bob + Kab_N2 # concatenate bytes
client_socket.send(msg)
print("Sent ticket and encrypted nonce to Bob\n")

# If using regular NS protocol, let Trudy sniff the message just sent to Bob
if auth_protocol == "normal-ns":
    _let_trudy_sniff(msg)

# Receive and parse Bob's response
response = client_socket.recv(1024)
print("Received Kab{N2-1, N3} from Bob\n")
N3 = _parse_bobs_response(response)

# Send Bob final authentication message
Kab_N3_minus_1 = _create_Kab_N3_minus_1(N3, a_b_key)
client_socket.send(Kab_N3_minus_1)
client_socket.close()
print("Sent Bob final authentication message (Kab{N3-1})\n")

if auth_protocol == "extended-ns":
    print("Extended Needham-Schroeder authentication complete\n")
else:
    print("Regular Needham-Schroeder authentication complete\n")
