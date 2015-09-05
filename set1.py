import base64
import binascii
import math
from Crypto.Cipher import AES
import Crypto.Util.Counter

##### SET 1  - http://cryptopals.com/sets/1/ ####
#################################################

# the frequency that letters occur naturally in the english language
english_freq = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}
# just a list of letters in the alphabet
letters = "abcdefghijklmnopqrstuvwxyz".upper()

# problem 1 - convert hex to base64
def hex_to_b64(s):
    return base64.b64encode(binascii.unhexlify(s))

def b64_to_hex(s):
    return binascii.hexlify(base64.b64decode(s))

# problem 2 - fixed xor
def apply_xor(s, c):
    byte_stream = bytearray(binascii.unhexlify(s))
    for i in range(0, len(byte_stream)):
        byte_stream[i] = byte_stream[i] ^ c
    return binascii.hexlify(str(byte_stream))

# problem 3 - cracking a single byte xor cipher
def get_freq(s):
    letter_count = {}
    letter_freq = {}
    for c in letters:
        letter_count[c] = 0
    for c in s:
        if c in letters:
            letter_count[c] += 1
    for c in letters:
        letter_freq[c] = (letter_count[c] / float(len(s))) * 100
    return letter_freq

def score_freq(f, s):
    score = 0.0
    for c in letters:
        score += math.sqrt(((english_freq[c] - f[c]) / english_freq[c]) ** 2)
    for c in s:
        if (c not in letters) and (c not in " .?!-'"):
            score += 10
    return score

def get_freq_and_score(s):
    f = get_freq(s.upper())
    return score_freq(f, s.upper())

def find_xor_cipher(s):
    best_score = 9999999
    best_string = ''
    best_xor = 0
    for i in range(0, 256):
        result = binascii.unhexlify(apply_xor(s, i))
        score = get_freq_and_score(result)
        if score < best_score:
            best_score = score
            best_string = result
            best_xor = i
    return (best_score, best_string)

# problem 4 - detect single character xor
def prob4():
    lines = [line.rstrip('\n') for line in open('4.txt')]
    best_score = 99999999
    best_line = 0
    for line in lines:
        best = find_xor_cipher(line)
        if (best_score > best[0]):
            best_score = best[0]
            best_line = best[1]
    return (best_score, best_line)

# problem 5 - apply repeating key xor
def repeating_xor(s, key):
    byte_stream = bytearray(s)
    for i in range(0, len(byte_stream)):
        j = (i % len(key))
        byte_stream[i] = byte_stream[i] ^ ord(key[j])
    return binascii.hexlify(str(byte_stream))

# problem 6 - break repeating key xor

# xor each byte and count number of 1s
def find_edit_dist(x, y):
    dist = 0
    for i in range(0, len(x)):
        xor_xy = ord(x[i]) ^ ord(y[i])
        dist += bin(xor_xy).count("1")
    return dist

def find_best_keysize(s):
    dist = [9999, 9999] #inser high values for 0, 1 to discard them
    for i in range(2, 40):
        temp = 0
        temp += find_edit_dist(s[0:i], s[i:(i*2)])
        temp += find_edit_dist(s[0:i], s[(i*2):(i*3)])
        temp += find_edit_dist(s[0:i], s[(i*3):(i*4)])
        temp += find_edit_dist(s[i:(i*2)], s[(i*2):(i*3)])
        temp += find_edit_dist(s[i:(i*2)], s[(i*3):(i*4)])
        temp += find_edit_dist(s[(i*2):(i*3)], s[(i*3):(i*4)])        
        temp = temp / float(i)
        dist.append(temp)
    return sorted(range(len(dist)),key=lambda x:dist[x]) # return sorted list of indicies

def prob6():
    infile = open("6.txt")
    base64_in = infile.read().replace("\n", "")
    infile.close()

    in_buf = binascii.unhexlify(b64_to_hex(base64_in))
    best_keysize_list = find_best_keysize(in_buf)
    #print best_keysize_list
    s = []
    chosen_keysize = best_keysize_list[0]
    for i in range(0, chosen_keysize):
        s.append('')
        for j in range(i, len(in_buf), chosen_keysize):
            s[i] = s[i] + in_buf[j]
        s[i] = find_xor_cipher(binascii.hexlify(s[i]))[1]
        #print s[i]
    out = ''
    for i in range(0, len(s[len(s)-1])):
        for j in range(0, len(s)):
            out = out + s[j][i]
    return out

# problem 7 - encrypt / decrypt AES
def open_base64(fname):
    infile = open(fname)
    base64_in = infile.read().replace("\n", "")
    infile.close()
    return binascii.unhexlify(b64_to_hex(base64_in))
	
def decrypt_ebc(key, ciphertext):
    crypto = AES.new(key, AES.MODE_ECB)
    text = crypto.decrypt(ciphertext)
    return text
	
def encrypt_ebc(key, text):
    crypto = AES.new(key, AES.MODE_ECB)
    if ((len(text) % 16) != 0):
        text = pkcs7_padding(text, 16)
    ciphertext = crypto.encrypt(text)
    return ciphertext

def prob7():
    ciphertext = open_base64("7.txt")
    text = decrypt_ebc("YELLOW SUBMARINE", ciphertext)
    return text
	
# problem 8 - detect if encryption in ebc mode
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

# demo for all problem sets
def set1_demo():
    print("Breaking single-byte xor cipher by doing frequency scoring...")
    ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print("ciphertext: " + ciphertext)
    print("decoded text: " + find_xor_cipher(ciphertext)[1])
    print("")

    print("Breaking repeating key xor...")
    print("Ciphertext found in 6.txt")
    print("First few lines of decrypted output: \n" + prob6()[:113])

    
