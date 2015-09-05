import base64
import binascii
import math
from Crypto.Cipher import AES
import Crypto.Util.Counter

execfile("set1.py") # originally all functions were in one file. This stops me from having to make changes to the code.

#### SET 2 ####
###############
def pkcs7_padding(s, block_size):
    offset = block_size - (len(s) % block_size)
    return s + (chr(offset) * offset)

def xor_strings(x, y):
    result = ""
    for i in range(0, len(x)):
        result += chr(ord(x[i]) ^ ord(y[i]))
    return result
	
	
def encrypt_cbc(key, text, iv="\x00" * 16):
	split_text = [text[i:i+16] for i in range(0, len(text), 16)] # split the text into 16 byte sequences for cbc
	# need to pad last block if not the block size for xor
	if (len(split_text[-1]) % 16 != 0):
		split_text[-1] = pkcs7_padding(split_text[-1], 16)
		print split_text[-1]
	else:
		split_text.append(chr(16) * 16)
	split_text[0] = encrypt_ebc(key, xor_strings(split_text[0], iv))
	for i in range(1, len(split_text)):
		split_text[i] = encrypt_ebc(key, xor_strings(split_text[i], split_text[i-1]))
	return "".join(split_text)

def decrypt_cbc(key, ciphertext, iv="\x00" * 16):
	split_text = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)] # split the text into 16 byte sequences for cbc
	# decrypt the first block and apply the xor to ciphertext and initial value
	text = [ decrypt_ebc(key, split_text[0]) ]
	text[0] = xor_strings(text[0], iv)
	# now, decrypt the rest, xoring the previous ciphertext with the current
	for i in range(1, len(split_text)):
		text.append(decrypt_ebc(key, split_text[i]))
		text[i] = xor_strings(text[i], split_text[i-1])
	return "".join(text)
	
def prob10():
	text = open_base64("10.txt")
	return decrypt_cbc("YELLOW SUBMARINE", text)
	
# problem 11 - ebc/cbc detection
######################################
def encryption_oracle(text):
	key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16)) #generate random key
	# append text, pad to 16 bytes
	text = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(5, 10))) + text # prepend randomly
	text = text + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(5, 10))) # append randomly
	text = pkcs7_padding(text, 16)
	
	# chose ebc/cbc and encrypt
	ciphertext = ''
	cipher_mode = random.randint(0, 1)
	if (cipher_mode == 1):
		# cbc
		ciphertext = encrypt_cbc(key, text)
	else:
		# ebc
		ciphertext = encrypt_ebc(key, text)
	return (ciphertext, cipher_mode, key)

def detect_ebc_or_cbc(ciphertext):
	split_text = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)] # split the text into 16 byte sequences
	d = dict()
	for i in range(0, len(split_text)):
		if split_text[i] in d:
			d[split_text[i]] += 1
		else:
			d[split_text[i]] = 1
			
	dup_count = 0
	for keys in d:
		if d[keys] > 1:
			dup_count+=1
	return dup_count
	
# Input specifically chosen to exploit cbc characteristics
def prob11():
	infile = open("11.txt")
	text = infile.read()
	infile.close()
	
	for i in range(0, 10000):
		(ciphertext, cipher_mode, key) = encryption_oracle(text)
		if (detect_ebc_or_cbc(ciphertext) <= 30):
			if (1 != cipher_mode):
				return("Failed to correctly detect mode", i, detect_ebc_or_cbc(ciphertext), cipher_mode)
		else:
			if (0 != cipher_mode):
				return("Failed to correctly detect mode", i, detect_ebc_or_cbc(ciphertext), cipher_mode)
	return ("Success")
        
# problem 12 - breaking ebc
######################################
def init_rand_key():
	return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
	
	
def find_block_size(key):
	random_key = init_rand_key()
	for i in range(1, 65):
		char_string = 'A' * i * 3
		ciphertext = encrypt_ebc(random_key, char_string)
		if ((ciphertext[0:i] == ciphertext[i:i*2]) and (ciphertext[i*2:i*3] == ciphertext[i:i*2])):
			return i
		
	
def break_ebc(text):

	key = init_rand_key()
	block_size = find_block_size(key)
	
	found_bytes = ""
	block_dict = dict()
	
	# iterate through every block
	for block in range(0, len(text) / block_size + 1):
		# iterate through each byte in our block
		for byte in range(0, block_size):
			a_string = 'A' * (15 - (byte % 16)) # serves as an offset to isolate out byte
			block_dict = dict() # make a dict for each possible block
			
			first_15_bytes = found_bytes[-15:] # get the last 15 bytes we found so that we can isolate a new byte
			if (len(first_15_bytes) < 15): # first 15 bytes of entire stream are set to 'A'
				first_15_bytes = a_string + first_15_bytes
			#iterate all 255 byte possibilities
			for i in range(0, 256):
				encrypted_block = encrypt_ebc(key, first_15_bytes + chr(i))
				block_dict[encrypted_block] = first_15_bytes + chr(i)
			encrypted_text = encrypt_ebc(key, a_string + text)
			encrypted_block = encrypted_text[block * 16: (block * 16) + 16]
			# with the encrypted block, compare to our dict of all possibilities and add the char to the found string
			found_bytes += block_dict[encrypted_block][15]

	return found_bytes
	
def prob12():
	text = open_base64('12.txt')
	result = break_ebc(text)
	return result
	
#prob 13
###########################
def parse_kv(text):
	k_eq_v = text.split('&')
	kv_obj = dict()
	for item in k_eq_v:
		(x, y) = (item.split('='))
		kv_obj[x] = y
	return kv_obj
	
def profile_for(email):
	if '=' in email or '&' in email:
		return "Error"
	return "email=" + email + "&uid=10&role=user"

def prob13():
	# isolate admin so that we can append to the end
	admin_discovery = '0000000000admin' + ("\x00" * 11)
	email = "test@mail.com"
	
	prof1 = profile_for(admin_discovery)
	prof2 = profile_for(email)
	
	key = init_rand_key()
	admin_encrypted = encrypt_ebc(key, prof1)[16:32] # take only admin part
	encrypted_profile = encrypt_ebc(key, prof2)[0:32] + admin_encrypted # replace user with admin
	
	return decrypt_ebc(key, encrypted_profile) #return our decrypted result to verify correctness
	
# prob14
######################################
prefix_p14 = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(0, 64)))
key_p14 = init_rand_key()
def ebc_with_rand_prefix(key, text):
	return encrypt_ebc(key, prefix_p14 + text)
	
def find_prefix(random_key, block_size):
	base_string = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(0, 64))
	# iterate through several potential block sizes of our prefix
	for blocks in range(0, 8):
		for i in range(0, 16):
			char_string = 'A' * (block_size - i) # try to isolate prefix from start of our text
			char_string += base_string * block_size
			ciphertext = ebc_with_rand_prefix(random_key, char_string)
			base = (blocks+1)*block_size
			if ((ciphertext[base:base+block_size] == ciphertext[64+base:64+base+block_size])):
				return i + (blocks*block_size)
	
def break_ebc_harder(text):
	key = key_p14
	block_size = find_block_size(key)
	
	found_bytes = ""
	block_dict = dict()
	prefix_size = find_prefix(key, block_size)
	
	# iterate through every block
	for block in range(0, len(text) / block_size + 1):
		# iterate through each byte in our block
		for byte in range(0, block_size):
			a_string = 'A' * (15 - (byte % 16)) # serves as an offset to isolate out byte
			block_dict = dict() # make a dict for each possible block
			
			first_15_bytes = found_bytes[-15:] # get the last 15 bytes we found so that we can isolate a new byte
			if (len(first_15_bytes) < 15): # first 15 bytes of entire stream are set to 'A'
				first_15_bytes = a_string + first_15_bytes
			#iterate all 255 byte possibilities
			extra_pad = 'A' * (64 - prefix_size) # just a hack for our arbitrary max length
			for i in range(0, 256):
				encrypted_block = ebc_with_rand_prefix(key, extra_pad + first_15_bytes + chr(i))[64:]
				block_dict[encrypted_block] = first_15_bytes + chr(i)
			encrypted_text = ebc_with_rand_prefix(key, extra_pad + a_string + text)[64:]
			encrypted_block = encrypted_text[block * 16: (block * 16) + 16]
			# with the encrypted block, compare to our dict of all possibilities and add the char to the found string
			found_bytes += block_dict[encrypted_block][15]

	return found_bytes
	
	
def prob14():
	text = open_base64('12.txt')
	result = break_ebc_harder(text)
	return result

# prob15
#####################
class PadError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)


def is_pkcs7_valid(text):
	pad_length = ord(text[-1])
	for i in range(1, pad_length + 1):
		if ord(text[0 - i]) != pad_length:
			try:
				raise PadError(0-i)
			except PadError as e:
				#print "Padding error occurred at location: ", e.value
				return False
	if pad_length == 0:
			try:
				raise PadError(0)
			except PadError as e:
				#print "Padding error occurred at location: ", e.value
				return False
	return True
		
# prob 16
######################
key_p16 = init_rand_key()
def setup_p16(text, key):
	s = "comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon"
	s = pkcs7_padding(s, 16)
	return encrypt_cbc(key, s)
	
def break_cbc():
	usertext = (chr(0) * 32) # set up one block we can change to garbage, one to admin
	
	ciphertext = setup_p16(usertext, key_p16)
	junk1 = ciphertext[32:48] # this is what we can modify to make the admin=true string appear
	desired_string = ";admin=true;;;;;"
	transformed_string = ""
	junk2 = ciphertext[64:80] # this allows the rest of the data to decrypt normally
	return_string = ""
	
	for i in range(0, len(junk1)):
		transformed_string += chr(ord(junk1[i]) ^ ord(desired_string[i]))
		return_string += chr(ord(junk2[i]) ^ ord(desired_string[i]))	
	new_ciphertext = ciphertext[0:32] + transformed_string + ciphertext[48::]
	return decrypt_cbc(key_p16, new_ciphertext)
