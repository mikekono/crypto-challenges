import base64
import binascii
import math
from Crypto.Cipher import AES
import Crypto.Util.Counter
import random
import string
import time

execfile("set2.py")

# prob 17
#################################
key_p17 = init_rand_key()
def select_and_encrypt():
	# open input file and choose a string at random to encrypt
	infile = open("17.txt")
	input_list = infile.readlines()
	infile.close()
	selected_string = binascii.unhexlify(b64_to_hex(input_list[random.randint(0, 9)]))
	iv="\x00" * 16
	return (selected_string, encrypt_cbc(key_p17, selected_string, iv), iv)

def decrypt_and_check_pad(ciphertext, iv="\x00" * 16):
	text = decrypt_cbc(key_p17, ciphertext, iv)
	return is_pkcs7_valid(text)
	
	
def blk_padding_attack(block1, block2, block_size, byte_start=0):
	found_text = ""
	for i in range(0, 16):
		pkcs7_offset = i + 1
		new_block1 = block1[0:16-pkcs7_offset]
		padding = ""
		for j in range(0, i):
			padding = chr(ord(found_text[j]) ^ ord(block1[15-j]) ^ pkcs7_offset) + padding
				
		for j in range(0, 256):
			new_block1 = block1[0:16-pkcs7_offset] + chr(j ^ ord(block1[15-i]) ^ pkcs7_offset) + padding
			is_valid = decrypt_and_check_pad(new_block1 + block2)
			if is_valid:
				found_text += chr(j)
				break;
			
			
	return found_text[::-1]
	
	
def padding_oracle_attack(ciphertext, iv="\x00" * 16):
	block_size = 16
	block1 = ciphertext[0:16]
	block2 = ciphertext[16:32]
	
	block1 = iv
	block2 = ciphertext[0:16]
	text = blk_padding_attack(block1, block2, block_size)
	
	for i in range(block_size, len(ciphertext) - block_size, block_size):
		block1 = ciphertext[i-block_size:i]
		block2 = ciphertext[i:i + block_size]
		text += blk_padding_attack(block1, block2, block_size)
	
	block2 = ciphertext[len(ciphertext) - block_size:]
	block1 = ciphertext[len(ciphertext) - (2 * block_size):len(ciphertext) - block_size]
	offset_begin = 0
	for i in range(0, 16):
		# try to discover where padding begins so our test doesn't mess up
		new_beginning = chr(ord(block1[i]) ^ 0xff) * i
		is_valid = decrypt_and_check_pad(new_beginning + block1[i:] + block2)
		if is_valid == False:
			offset_begin = i
			break;	
	# Hacky way to prevent the real offset from interfering with the oracle
	# - changing the real pkcs7 offset sections to 0xff produces junk data
	# - TODO: investigate a better way to do this
	text_with_junk = blk_padding_attack(block1[:offset_begin] + (chr(0xFF) * (block_size - offset_begin)), block2, block_size)
	text += text_with_junk[:offset_begin-1]
	return text
	
def prob17():
	# loop through 20 times, checking if we decrypted correctly
	for i in range(0, 20):
		(text, ciphertext, iv) = select_and_encrypt()
		result = padding_oracle_attack(ciphertext, iv)
		if (result not in text):
			print "Error for: " + text
			return False
		print "Successfully decrypted " + result
	return True
	
# prob 18
############################
def encrypt_ctr(key, text, nonce=0, suf=("\x00"*7)):
    ctr = Crypto.Util.Counter.new(8 * 9, initial_value=nonce, suffix=suf)
    crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    if ((len(text) % 16) != 0):
        text = pkcs7_padding(text, 16)
    ciphertext = crypto.encrypt(text)
    return ciphertext
	
def decrypt_ctr(key, ciphertext, nonce=0):
    ctr = Crypto.Util.Counter.new(8 * 9, initial_value=nonce, suffix=("\x00"*7))
    crypto = AES.new(key, AES.MODE_CTR, counter=ctr)
    text = crypto.decrypt(ciphertext)
    return text
	
# prob 19
############################
def open_lines(fpath):
	# open input file and choose a string at random to encrypt
	infile = open(fpath)
	input_list = infile.readlines()
	infile.close()
	for i in range(0, len(input_list)):
		input_list[i] = binascii.unhexlify(b64_to_hex(input_list[i]))
	return input_list
	
def prob19():
	key = init_rand_key()
	
	# encrypt each entry separately
	text_list = open_lines('19.txt')
	print text_list
	encrypted_list = []
	for i in range(0, len(text_list)):
		encrypted_list.append(encrypt_ctr(key, text_list[i]))
	
	letters = [""] * 20
	for i in range(0, 20):
		for line in range(0, len(encrypted_list)):
			letters[i] += encrypted_list[line][i]
	
	# With first letters isolated, do frequency analysis
	converted_letters = []
	for line in letters:
		converted_letters.append(find_xor_cipher(binascii.hexlify(line))[1])
	
	# now reconstruct the block
	result = [""] * len(encrypted_list)
	for i in range(0, len(encrypted_list)):
		for j in range(0, len(converted_letters)):
			result[i] += converted_letters[j][i]
	
	return result
	
# problem 19 solution was actually usable for 20 as well
def prob20():
	return prob19()
	
# prob 21
###############################
def get_int32(x):
	return int(0xFFFFFFFF & x)

class MT19937:
	n = 624 # degree of recurrence
	f = 1812433253 # ??? hard-coded on wikipedia page
	w = 32 # word size
	def __init__(self, seed):
		self.index = self.n
		self.mt = [0] * self.n
		self.mt[0] = seed # set initial state to seed
		for i in range(1, self.n):
			self.mt[i] = get_int32(self.f * (self.mt[i - 1] ^ self.mt[i - 1] >> (self.w - 2)) + i)

	def extract_num(self):
		if self.index >= self.n:
			self.twist()
		y = self.mt[self.index]
		
		# right shift 11
		y = y ^ (y >> 11)
		# left shift 7 and and with 2636928640
		y = y ^ ((y << 7) & 2636928640)
		# shift y left by 15, then and with 4022730752
		y = y ^ ((y << 15) & 4022730752)
		# right shift by 18y = y ^ y >> 18
		y = y ^ (y >> 18)
	
		self.index += 1
		
		return get_int32(y)
	
	def twist(self):
		for i in range(0, self.n):
			# add most sig bit to less sig of next number
			y = get_int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % self.n] & 0x7fffffff))
			self.mt[i] = self.mt[(i + 397) % self.n] ^ y >> 1
			
			if y % 2 != 0:
				self.mt[i] = self.mt[i] ^ 0x9908b0df
			self.index = 0
	
	
# prob 22
##############################
def time_rand_wait():
	time.sleep(random.randint(20, 100))
	init_time = int(time.time())
	rand_gen = MT19937(init_time)
	rand_num = rand_gen.extract_num()
	
	time.sleep(random.randint(20, 400))
	return (rand_num, init_time)
	
def find_time_seed(rand_num):
	cur_time = int(time.time())
	for i in range (1, 10000):
		rand_gen = MT19937(cur_time - i)
		num = rand_gen.extract_num()
		if (num == rand_num):
			return (cur_time - i)

def prob22():
	(rand_num, init_time) = time_rand_wait()
	found_seed = find_time_seed(rand_num)
	if (found_seed == init_time):
		return "Found seed at time: " + str(found_seed)
	else:
		return False
		
# prob 23
###############################
def untemper(y):
	y = y ^ (y >> 18)
	# shift y left by 15, then and with 4022730752
	y = y ^ ((y << 15) & 4022730752)
	
	# left shift 7 and and with 2636928640
	# restore 7 bits each
	x = y ^ ((y << 7) & 2636928640)
	x = y ^ ((x << 7) & 2636928640)
	x = y ^ ((x << 7) & 2636928640)
	y = y ^ ((x << 7) & 2636928640)
	
	# shift right 11
	x = y ^ (y >> 11)
	return y ^ (x >> 11)
	
def get_624_rand_outputs(rand_gen):
	out = []
	for i in range(0, 624):
		out.append(rand_gen.extract_num())
	return out
	
def clone_mt(rand_gen):
	out_batch = get_624_rand_outputs(rand_gen)
	cloned_mt = []
	for item in out_batch:
		cloned_mt.append(untemper(item))
	# reconstruct identical rng without knowing the seed
	cloned_rng = MT19937(0)
	# create a new rng with a different seed; overwrite internal state with found untempered values
	for i in range(0, 624):
		cloned_rng.extract_num() # increments index by 1; don't care about actual value
		cloned_rng.mt[i] = cloned_mt[i]
	return cloned_rng
	
def predict_next(cloned_mt):
	return cloned_mt.extract_num()

def prob23():
	time_seed = int(time.time())
	base_rand = MT19937(time_seed)
	cloned_rand = clone_mt(base_rand)
	
	# loop through 1000 values to test if they match
	for i in range(0, 1000):
		if base_rand.extract_num() != cloned_rand.extract_num():
			return "Error: incorrect prediction"
	return "Successfully predicted 1000 rng values"
	
# prob 24
##############################
def encrypt_mt(seed, text):
	rng = MT19937(seed)
	ciphertext = ""
	for c in text:
		xor_int = rng.extract_num() % 256
		ciphertext += chr(ord(c) ^ xor_int)
	return ciphertext
	
def decrypt_mt(seed, ciphertext):
	rng = MT19937(seed)
	text = ""
	for c in ciphertext:
		xor_int = rng.extract_num() % 256
		text += chr(ord(c) ^ xor_int)
	return text
	
def encrypt_mt_with_rand_prefix(seed, text):
	prefix = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(0, 32)))
	return encrypt_mt(seed, prefix + text)
	
# brute force the key as it's only 16 bit
def break_16_bit_mt(text, ciphertext):
	cipher_len = len(ciphertext)
	pad_len = len(ciphertext) - len(text)
	for i in range(0, 0xFFFF + 1):
		decrypted = decrypt_mt(i, ciphertext)
		if (text == decrypted[pad_len:]):
			return i
	return -1

def prob24():
	seed = int(time.time()) % 0x10000
	text = 'a' * 14
	ciphertext = encrypt_mt_with_rand_prefix(seed, text)
	found_seed = break_16_bit_mt(text, ciphertext)
	if (found_seed == seed):
		return "Found correct seed of: " + str(found_seed)
	else:
		return "!!!ERROR!!!: Found correct seed of: " + str(found_seed)
	
