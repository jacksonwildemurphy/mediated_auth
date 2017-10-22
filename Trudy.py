# When the application is run using the normal Needham-Schroeder protocol,
# Trudy "sniffs" Alice's message to Bob containing the ticket.
# Trudy then attempts a replay attack to impersonate Alice.
# This attack is successful when the encryption mode used is ECB,
# but is unsuccessful when the encryption mode is CBC.
#
# Written by Jackson Murphy. Last updated October 21, 2017


from socket import *
import sys
import time

# Set up server
server_port = 14000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)
sniffed_msg = 0 # initialize

# "Sniff" msg 3 from Alice
connection_socket, addr = server_socket.accept()
sniffed_msg = connection_socket.recv(1024)
connection_socket.close()

# Wait until Alice finishes with Bob before commencing attack
time.sleep(3)

# Replay sniffed msg to Bob
server_name = "localhost"
server_port = 12000 # the port Bob is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))
client_socket.send(sniffed_msg)
print("Replayed sniffed message to Bob\n")

# Receive Bob's response Kab{N2-1,N4}
response1 = client_socket.recv(1024)
print("Received Kab{N2-1,N4} from Bob\n")

# Form ticket,Kab{N4}
ticket_len = 24 # 24 bytes
ticket = sniffed_msg[:ticket_len]
Kab_N4 = response1[int(len(response1)/2):] # second half of response1
msg = ticket + Kab_N4

# Open a second connection with Bob
client_socket2 = socket(AF_INET, SOCK_STREAM)
client_socket2.connect((server_name, server_port))
client_socket2.send(msg)
print("Sent Bob via a second connection: <ticket,Kab{N4}>\n")

# Receive Bob's response Kab{N4-1,N5}
response2 = client_socket2.recv(1024)
if response2 == b"":
    print("Trudy unable to impersonate Alice.\n")
    client_socket.close(); server_socket.close(); sys.exit(0)

    # Pull out Kab{N4-1} and send it back to Bob via the first connection
print("Received Kab{N4-1,N5} from Bob\n")
Kab_N4_minus_1 = response2[:int(len(response2)/2)]
client_socket.send(Kab_N4_minus_1)
print("Sent Bob Kab{N4-1} via the first connection\n")
print("Successfully impersonated Alice!\n")

# Clean up connections
client_socket.close()
#client_socket2.close() # keep this connection open to make printing more clear
server_socket.close()
