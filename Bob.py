# Bob mutually authenticates with Alice, with the assistance of a
# Key Distribution Center (KDC). The specific protocol and encryption mode
# used depends on the commandline parameters. E.g.
#
#   Bob.py -v extended-ns
# uses the extended Needham-Schroeder protocol and Cipher Block Chaining
#   Bob.py -m ecb
# uses the regular Needham-Schroeder protocol and Electronic Code Book encryption
#   Bob.py -m cbc
# uses the regular Needham-Schroeder protocol and Cipher Block Chaining
#
# In this application, Bob is a concurrent server, and Alice is a client
#
# Written by Jackson Murphy. Last updated October 22, 2017


import crypto_lib as Crypto
from socket import *
import sys
from _thread import *

# Multithreaded, per-client authentication. This function is called for
# each client connection
def _handle_client(connection_socket):
    msg_from_Alice = 0 # initialize
    msg_from_Alice = connection_socket.recv(1024)

    if msg_from_Alice == b"I want to talk with you.\n":
        print("Bob got extended-NS initiation message from Alice")
        nonce = Crypto.get_nonce(nonce_secret)
        # Send encrypted nonce to Alice
        ciphertext = Crypto.des3_encrypt(b_key, iv, encryption_mode, nonce)
        print("Sent encrypted nonce Kb{Nb} to Alice")
        connection_socket.send(ciphertext)

    else:
        [a_b_key, N2] = _parse_ticket_msg(msg_from_Alice)
        print("Got shared key from Alice:", a_b_key.decode())
        print("Got nonce N2 from Alice:", N2)
        [N3, msg] = _create_final_msg(a_b_key, N2) # msg is Kab{N2-1,N3}
        connection_socket.send(msg)
        print("Sent Alice Kab{N2-1,N3} (or {N2-1,N4} or {N4-1,N5} in the case of Trudy)")

        # Parse final message from Alice to verify we received proper N3-1
        final_msg_from_Alice = connection_socket.recv(1024)
        if final_msg_from_Alice == b"":
            connection_socket.close()
            sys.exit(0)

        print("Received final authentication message from Alice")
        _verify_final_msg(final_msg_from_Alice, N3, a_b_key)

        if auth_protocol == "extended-ns":
            print("Extended Needham-Schroeder authentication complete\n")
        else:
            print("Regular Needham-Schroeder authentication complete\n")

    connection_socket.close()



# Pulls out Alice's and Bob's shared key, and Alice's nonce N2.
# msg_from_Alice is in bytes, formatted as <ticket>,<Kab{N2}>
def _parse_ticket_msg(msg_from_Alice):
    # retrieve shared key from ticket. Ticket length depends on protocol used
    ticket_len = 32 if auth_protocol == "extended-ns" else 24 # bytes
    encrypted_ticket = msg_from_Alice[:ticket_len]
    ticket = Crypto.des3_decrypt(b_key, iv, encryption_mode, encrypted_ticket)
    if auth_protocol == "extended-ns": # Check that Nb received is correct
        #verify_ticket(ticket)
        pass
    a_b_key = ticket[:16]
    # decrypt N2
    Kab_N2 = msg_from_Alice[ticket_len:]
    try:
        N2 = Crypto.des3_decrypt(a_b_key, iv, encryption_mode, Kab_N2).decode()
    except UnicodeDecodeError:
        print("ERROR: Decrypting N4 nonce is gibberish. Nice try Trudy!")
        sys.exit(0)
    return [a_b_key, N2]

# Returns N3, and Kab{N2 - 1, N3}
def _create_final_msg(a_b_key, N2):
    N2_minus_1 = Crypto.decrement_hash(N2)
    N3 = Crypto.get_nonce(nonce_secret)
    duo = N2_minus_1 + N3 # concatenate strings
    msg = Crypto.des3_encrypt(a_b_key, iv, encryption_mode, duo)
    return N3, msg

# Parse final message of Kab{N3-1} and verify we received correct N3-1
def _verify_final_msg(final_msg_from_Alice, N3, a_b_key):
    N3_minus_1 = Crypto.des3_decrypt(a_b_key, iv, encryption_mode, final_msg_from_Alice).decode()
    if not Crypto.nonce_difference_is_1(N3_minus_1, N3):
        print("Didn't receive correct value for nonce-1!\n")
    else:
        print("Received correct value for nonce-1")

#### START OF PROGRAM ####

# Symmetric key used by Bob and KDC
b_key = b"--BobKDCBobKDC--"
iv = b"00000000"
nonce_secret = "horsesflysnakeadjust"
# IMPORTANT that user ids are 8 chars long. Otherwise program will break.
bob_id = "35353535"

# Determine the protocol and encryption mode to use
auth_protocol = Crypto.get_app_mode(sys.argv)
encryption_mode = Crypto.get_encryption_mode(sys.argv)

# Set up server
server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)

while 1:
    connection_socket, addr = server_socket.accept()
    # spin up a new thread to concurrently communicate with Alice, Trudy, etc.
    start_new_thread(_handle_client, (connection_socket,)) # ',' bc arg is tuple
