# This Key Distribution Center mediates the mutual authentication of Bob and Alice.
# The specific protocol and encryption mode used depends on the commandline
# parameters. E.g.
#
#   Kdc.py -v extended-ns
# uses the extended Needham-Schroeder protocol and Cipher Block Chaining
#   Kdc.py -m ecb
# uses the regular Needham-Schroeder protocol and Electronic Code Book encryption
#   Kdc.py -m cbc
# uses the regular Needham-Schroeder protocol and Cipher Block Chaining
#
# Written by Jackson Murphy. Last updated October 22, 2017

import base64
import crypto_lib as Crypto
from socket import *
import sys

# Returns N1, the request, and Nb (if present) rfrom the message from Alice
def _parse_msg(msg, b_key, iv):
    N1 = msg[:8].decode() # the nonce Alice created
    request = msg[8:(8 + len(alice_id) + len(bob_id))]
    if auth_protocol == "extended-ns":
        Kb_Nb = msg[-8:] # Bob's nonce encrypted with his key
        Nb = Crypto.des3_decrypt(b_key, iv, encryption_mode, Kb_Nb).decode()
    else:
        Nb = 0
    return [N1, request, Nb]

# Request should be of the form b"<alice id><bob id>"
def _is_bad_request(request, alice_id, bob_id):
    request_str = request.decode() # convert from bytes to string
    if request_str[:8] != alice_id or request_str[8:] != bob_id: #id's are 8 bytes long
        print("Received invalid request!\n")
        return True
    print("Received valid request\n")
    return False

def _create_ticket(b_key, a_b_key, alice_id, Nb):
    contents = a_b_key.decode() + alice_id
    if auth_protocol == "extended-ns":
        contents += Nb
    ticket = Crypto.des3_encrypt(b_key, iv, encryption_mode, contents)
    return ticket

# Concatenates the input parameters (stringifying the ticket to bob)
# and encrypts the results with Alice's key
def _create_msg(N1, bob_id, a_b_key, ticket_to_bob):
    # ticket_to_bob is just bytes with no discernible encoding (e.g. utf-8).
    # So first convert to base64 byte string and then convert that to a string
    ticket_to_bob = base64.encodestring(ticket_to_bob).decode()
    # add padding string to make ticket a multiple of 8 bytes
    pad_len = 8 - (len(ticket_to_bob) % 8)
    padding = "0" *  pad_len
    ticket_to_bob += padding
    contents = N1 + bob_id + a_b_key.decode() + ticket_to_bob
    msg = Crypto.des3_encrypt(a_key, iv, encryption_mode, contents)
    return msg

#### START OF PROGRAM ####

# 3DES key suites for the 3 communication pairs: Alice <-> KDC, Bob <-> KDC,
# and Alice <-> Bob.
# Note: these 16-byte keys are turned into 2 64-bit DES keys by 3DES lib fcns
a_key = b'hidegoesdampbran'
b_key = b"--BobKDCBobKDC--"
a_b_key = b"realbakejumpblue"
iv = b'00000000' # 8 bytes
# IMPORTANT that user ids are 8 chars long. Otherwise program will break.
alice_id = "17171717"
bob_id = "35353535"

# Determine the protocol and encryption mode to use
auth_protocol = Crypto.get_app_mode(sys.argv)
encryption_mode = Crypto.get_encryption_mode(sys.argv)

# Set up server and listen for connection from Alice
server_port = 13000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)
msg_from_Alice = 0 # initialize


while 1:
    connection_socket, addr = server_socket.accept()
    msg_from_alice = connection_socket.recv(1024)
    print("KDC got msg from Alice\n")
    [N1, request, Nb] = _parse_msg(msg_from_alice, b_key, iv)
    if _is_bad_request(request, alice_id, bob_id):
        connection_socket.send("Badly formed request....".encode())

    ticket_to_bob = _create_ticket(b_key, a_b_key, alice_id, Nb)
    msg_to_alice = _create_msg(N1, bob_id, a_b_key, ticket_to_bob)
    connection_socket.send(msg_to_alice)
    print("KDC sent response to Alice\n")
    connection_socket.close()
