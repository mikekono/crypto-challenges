import base64
import binascii
import math
from Crypto.Cipher import AES
import Crypto.Util.Counter
import random
import string
import time
import struct

import sha1
execfile("set3.py")	



# prob 25
#######################
def edit_aes_ctr(ciphertext, key, offset, newtext, nonce=0):
	text = decrypt_ctr(key, ciphertext, nonce) # I really should decrypt only the block here
	
	text = text[:offset] + newtext + text[offset + len(newtext):]
	return encrypt_ctr(key, text, nonce)

def break_editable_ctr(text, key, ciphertext):
	ctr_keys = edit_aes_ctr(ciphertext, key, 0, "\x00" * len(ciphertext))
	print xor_strings(ctr_keys, ciphertext)
	

# prob 26
######################
key_p26 = init_rand_key()
def setup_p26(text, key):
	s = "comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon"
	s = pkcs7_padding(s, 16)
	return encrypt_ctr(key, s)
	
# ctr bitflipping
def prob26():
	usertext = (chr(0) * 16) # setting this to all zeroes means ciphertext is also encrypted counter
	
	ciphertext = setup_p26(usertext, key_p26)
	junk1 = ciphertext[32:48] # input we desire to transform to admin=true
	desired_string = ";admin=true;;;;;"
	transformed_string = ""
	for i in range(0, len(desired_string)):
		transformed_string += chr(ord(junk1[i]) ^ ord(desired_string[i]))
	new_ciphertext = ciphertext[0:32] + transformed_string + ciphertext[48::]
	return decrypt_ctr(key_p16, new_ciphertext)

# prob 27 - recover key from cbc with iv=key
######################
key_p27 = init_rand_key()
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

# encrypt using the key as an iv
def setup_p27(key):
	s = "comment1=cooking%20MCs;userdata=0123456789abcdef"
	return encrypt_cbc(key, s, iv=key)
	
# decrypt and return the text if the result doesn't seem to be ascii
def decrypt_cbc_detect_ascii(key, ciphertext):
	text = decrypt_cbc(key_p16, ciphertext, iv=key)
	# return 0 or 1 is easier than raising an exception; kinf of hacky
	if not is_ascii(text):
		return (0, text)
	else:
		return (1, "")

	
def prob27():
	zeroes = (chr(0) * 16) # need to set the middle block to 0's

	ciphertext = setup_p27(key_p27) # encrypt under our key & iv
	
	# iv is xored with block 1; to recover iv, xor the result of (iv ^ block1) with block1
	new_ciphertext = ciphertext[:16] + zeroes + ciphertext[:16]
	
	(no_error, text) = decrypt_cbc_detect_ascii(key_p27, new_ciphertext)
	if (no_error != 1):
		found_key = xor_strings(text[:16], text[32:])
		if (key_p27 == found_key):
			return "Correctly got key of: " + found_key
	return False


# prob 28 - Implement a SHA-1 keyed MAC
#############################################
# check to see if sha-1 matches our mac
def sha1_auth(mac, text):
        return (sha1.sha1(text) == mac)

def sha1_secret_prefix(key, message):
        return sha1.sha1(key + message)

# test that the function is tamper-proof
def prob28():
        message1 = "Hello1"
        message2 = "Hello2"
        prefix = "pre"

        sha1_1 = sha1_secret_prefix(prefix, message1)
        sha1_2 = sha1_secret_prefix(prefix, message2)
        if (sha1_1 == sha1_2):
                return False

        if not (sha1_auth(sha1_1, "pra" + message1)):
                return True
        return False

# prob 29 - Break a SHA-1 keyed MAC using length extension
###########################################################
# modifide sha1 code
def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
def sha1_with_regs(message, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        message: The input message string to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    
    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
    
        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    
def gen_sha1_padding(message):
    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # start with the bit '1' as the padding
    padding = b'\x80'
    
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    padding += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    padding += struct.pack(b'>Q', original_bit_len)
    return padding
  
def prob29():
     key = "YELLOW SUBMARINE"
     message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
     appending = ';admin=true'

     # go through different key lengths
     for i in range(0, 64):
             message_padding = gen_sha1_padding(('a' * i) + message) # generate padding with the proposed key length
             sha1_hash = sha1.sha1(key + message) # do a normal sha1 

             # get the state from our sha1 results
             a  = int(sha1_hash[0:8], 16)
             b  = int(sha1_hash[8:16], 16)
             c  = int(sha1_hash[16:24], 16)
             d  = int(sha1_hash[24:32], 16)
             e  = int(sha1_hash[32:40], 16)    

             # generate new padding or when we append to the message
             new_pad = gen_sha1_padding(('a' * i) + message + message_padding + appending)
             # do sha1 with our previous state
             modified = sha1_with_regs(appending + new_pad, a, b, c, d, e)
             actual_sha1 = sha1.sha1(key + message + message_padding + appending)
             # compare our real sha1 result with what we proposed
             if (actual_sha1 == modified):
                     return True
     return False
