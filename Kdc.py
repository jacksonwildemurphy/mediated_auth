# The key distribution center (KDC) is 1 of 3 programs in this
# mediated key exchange application, along with Alice and Bob.
# This application implements both Needham-Schroeder and extended Needham-Schroeder.



import crypto_lib as Crypto
from socket import *

# Returns N1, the request, and Kb_Nb from the message from Alice
def _parse_msg(msg, b_key, iv):
    N1 = msg[:8].decode() # the nonce Alice created
    request = msg[8:(8 + len(" wants ") + len(alice_id) + len(bob_id))]
    Kb_Nb = msg[-16:] # Bob's nonce encrypted with his key
    Nb = Crypto.des3_decrypt(b_key, iv, "CBC", Kb_Nb).decode()
    return [N1, request, Nb]

# Request should be of the form "<alice id> wants <bob id>"
def _is_bad_request(request, alice_id, bob_id):
    if request.split()[0] != alice_id or request.split()[2] != bob_id:
        return False
    return True

def _create_ticket(b_key, a_b_key, alice_id, nonce_from_bob):
    contents = a_b_key + alice_id + nonce_from_bob
    ticket = Crypto.des3_encrypt(b_key, iv, "CBC", contents)
    return ticket

# Concatenates the input parameters (stringifying the ticket to bob)
# and encrypts the results with Alice's key
def _create_msg(N1, bob_id, a_b_key, ticket_to_bob):
    contents = N1 + bob_id + a_b_key + ticket_to_bob.decode()
    msg = Crypto.des3_encrypt(a_key, iv, "CBC", contents)
    return msg

# 3DES key suites for the 3 communication pairs: Alice <-> KDC, Bob <-> KDC,
# and Alice <-> Bob.
# Note: these 16-byte keys are turned into 2 64-bit DES keys by 3DES lib fcns
a_key = b'hidegoesdampbran'
b_key = b"--BobKDCBobKDC--"
a_b_key = b"realbakejumpblue"
iv = b'00000000' # 8 bytes
secret = "ninjadungeonhecticmustard"
alice_id = "171717"
bob_id = "353535"

server_port = 13000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)
msg_from_Alice = 0 # initialize


while 1:
    connection_socket, addr = server_socket.accept()
    msg_from_alice = connection_socket.recv(1024)
    print("KDC got from Alice:", msg_from_alice)
    [N1, request, Kb_Nb] = _parse_msg(msg_from_alice, b_key, iv)
    if _is_bad_request(request, alice_id, bob_id):
        connection_socket.send("Badly formed request".encode())

    ticket_to_bob = _create_ticket(b_key, a_b_key, alice_id, nonce_from_bob)
    msg_to_alice = _create_msg(N1, bob_id, a_b_key, ticket_to_bob)
    connection_socket.send(msg_to_alice)
    connection_socket.close()
