# Bob is 1 of 3 programs in this mediated key exchange application,
# along with Alice and a Key Distribution Center (KDC).
# This app implements both Needham-Schroeder and extended Needham-Schroeder.

import crypto_lib as Crypto
from socket import *

# Pulls out Alice's and Bob's shared key, and Alice's nonce N2.
# msg_from_Alice is in bytes, formatted as <ticket>,<Kab{N2}>
def _parse_ticket_msg(msg_from_Alice):
    # retrieve shared key from ticket
    encrypted_ticket = msg_from_Alice[:32] # the encrypted ticket is 32 bytes
    ticket = Crypto.des3_decrypt(b_key, iv, "CBC", encrypted_ticket)
    #verify_ticket(ticket)
    a_b_key = ticket[:16]
    # decrypt N2
    Kab_N2 = msg_from_Alice[32:]
    N2 = Crypto.des3_decrypt(a_b_key, iv, "CBC", Kab_N2).decode()
    return [a_b_key, N2]

# Returns N3, and Kab{N2 - 1, N3}
def _create_final_msg(a_b_key, N2):
    N2_minus_1 = Crypto.decrement_hash(N2)
    N3 = Crypto.get_nonce(nonce_secret)
    duo = N2_minus_1 + N3 # concatenate strings
    msg = Crypto.des3_encrypt(a_b_key, iv, "CBC", duo)
    return N3, msg

# Parse final message of Kab{N3-1} and verify we received correct N3-1
def _verify_final_msg(final_msg_from_Alice):
    N3_minus_1 = Crypto.des3_decrypt(a_b_key, iv, "CBC", final_msg_from_Alice).decode()
    if not Crypto.nonce_difference_is_1(N3_minus_1, N3):
        print("Alice didn't send correct N3-1\n")
    print("Received correct value for N3-1\n")

#### START OF PROGRAM ####

server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)
msg_from_Alice = 0 # initialize

# Symmetric key used by Bob and KDC
b_key = b"--BobKDCBobKDC--"
iv = b"00000000"
nonce_secret = "horsesflysnakeadjust"
# IMPORTANT that user ids are 6 chars long. Otherwise program will break.
bob_id = "353535"

while 1:
    connection_socket, addr = server_socket.accept()
    msg_from_Alice = connection_socket.recv(1024)

    if msg_from_Alice == b"I want to talk with you.\n":
        print("Bob got from Alice:", msg_from_Alice.decode())
        nonce = Crypto.get_nonce(nonce_secret)
        print("Created nonce Nb:", nonce, "\n")
        # Send encrypted nonce to Alice
        ciphertext = Crypto.des3_encrypt(b_key, iv, "CBC", nonce)
        print("Sent encrypted nonce to send to Alice\n")
        connection_socket.send(ciphertext)

    else:
        [a_b_key, N2] = _parse_ticket_msg(msg_from_Alice)
        print("Got shared key from Alice:", a_b_key.decode(), "\n")
        print("Got nonce N2 from Alice:", N2, "\n")
        [N3, msg] = _create_final_msg(a_b_key, N2) # msg is Kab{N2-1,N3}
        connection_socket.send(msg)
        print("Sent Alice Kab{N2-1,N3}")

        # Parse final message from Alice to verify we received proper N3-1
        final_msg_from_Alice = connection_socket.recv(1024)
        print("Received final authentication message from Alice\n")
        _verify_final_msg(final_msg_from_Alice)
        print("Extended Needham-Schroeder authentication complete\n")

    connection_socket.close()
