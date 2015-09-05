import base64
import binascii
import math
from Crypto.Cipher import AES
import Crypto.Util.Counter
import random
import string
import time

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
	
