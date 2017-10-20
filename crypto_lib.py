from Crypto.Cipher import DES3
import hashlib
import time


# Converts a string into the proper DES3 library mode variable
def _get_des3_mode(mode_str):
    if mode_str == "CBC":
        return DES3.MODE_CBC
    elif mode_str == "ECB":
        return DES3.MODE_ECB
    else:
        raise Exception("DES mode should be either 'CBC' or 'ECB'")

# returns a des3 cipher that can be used to encrypt and decrypt messages
def _create_des3_cipher(key, iv, mode):
    cipher = DES3.new(key, mode, iv)
    return cipher


def des3_encrypt(key, iv, mode, msg):
    mode = _get_des3_mode(mode)
    cipher = _create_des3_cipher(key, iv, mode)
    padding_len = 8 - len(msg) % 8
    padding = chr(padding_len) * padding_len # a la PKCS5
    msg += padding
    return cipher.encrypt(msg)


def des3_decrypt(key, iv, mode, msg):
    mode = _get_des3_mode(mode)
    cipher = _create_des3_cipher(key, iv, mode)
    result = cipher.decrypt(msg)
    pad_len = (result[-1])
    result = result[:-pad_len]
    return result

# Returns a nonce created using a secret and the length of time elapsed since
# the current process began (in millionths of seconds)
def get_nonce(secret):
    proc_time = str(time.process_time())
    duo = secret + proc_time
    nonce = hashlib.sha256(duo.encode()).hexdigest()
    nonce = nonce[:8] # only use the first 64 bits as per assignment instructions
    return nonce

# Given a hash digest in string format, returns that hash minus one, in string format
def decrement_hash(hash):
    first_chars = hash[:len(hash)-1]
    last_char = hash[-1]
    if last_char == "a":
        return first_chars + "z"
    if last_char == "1":
        return first_chars + "9"
    return first_chars + chr(ord(last_char) - 1)

# Returns True if the nonce received (N_r) is 1 less than the original nonce
# Expects both nonces to be in string format
def nonce_difference_is_1(N_r, N_o):
    if decrement_hash(N_o) == N_r:
        return True
    else:
        return False
