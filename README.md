# Mediated Authentication
A command-line application demonstrating secure mediated authentication between Alice, Bob, and a Key Distribution Center (KDC). The protocol and type of 3DES-ciphertext concatenation used depend on the command-line arguments.

The 2 protocol options are: Extended Needham-Schroeder and normal Needham-Schroeder. 
When normal Needham-Schroeder is used, specify between using cipher block chaining (cbc) or electronic code book (ecb)

Bonus: When the regular Needham-Schroeder protocol is used, a fourth entity, Trudy, attempts a replay attack to impersonate Alice. This succeeds when the encryption type is ecb

Note: This application uses python 3. To get the following examples to work, you may need to replace `python` with `python3`

# Examples 
### Extended Needham-Schroeder protocol 
Note: Using extended NS protocol uses Cipher Block Chaining by default

1) In one terminal window, start up Bob
  `python Bob.py -v extended-ns`
 
 2) In a second terminal window, start up the KDC
  `python Kdc.py -v extended-ns`
 
 3) In a third terminal window, start up Alice
  `python Alice.py -v extended-ns`

### Normal Needham-Schroeder protocol using ECB

1) In one terminal window, start up Bob
  `python Bob.py -m ecb`
 
 2) In a second terminal window, start up the KDC
  `python Kdc.py -m ecb`
 
 3) In a third terminal window, start up Trudy 
  `python Trudy.py`
 
 4) In a fourth terminal window, start up Alice
  `python Alice.py -m ecb`

### Normal Needham-Schroeder protocol using CBC
(Same as for ECB, just replace `-m ecb` with `-m cbc`




