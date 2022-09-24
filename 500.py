
import hashlib
import secrets
import binascii
from datetime import datetime

def createmnemonic():
    word_count = 12
    checksum_bit_count = word_count // 3
    total_bit_count = word_count * 11
    generated_bit_count = total_bit_count - checksum_bit_count
    # entropy = ask_entropy(generated_bit_count)
    entropy = generate_entropy(generated_bit_count)
    # entropy = ask_entropy(12)
    entropy_hash = get_hash(entropy)
    indices = pick_words(entropy, entropy_hash, checksum_bit_count)
    # print_words(indices)
    # writefile(indices)
    return writefile(indices)


def ask_word_count():
    default_word_count = 12
    word_count = 12
    input_string = 'Enter word count: (12 or 24, default: {0}): '.format(default_word_count)
    while True:
        word_count_string = input(input_string)
        if len(word_count_string) == 0:
            return default_word_count
        word_count = int(word_count_string)
        if word_count == 12 or word_count == 24:
            return word_count


def ask_entropy(generated_bit_count):
    generated_char_count = generated_bit_count // 4
    input_string = 'Enter entropy in the form of padded hex string of length {0} (leave empty to generate): '.format(generated_char_count)
    entropy_binary = int_to_padded_binary(int(entropy_string, 16), generated_bit_count)
    entropy_string = ''
    while True:
        entropy_string = ''
        entropy_len = 0
        if entropy_len == 0:
            return generate_entropy(generated_bit_count)
        if entropy_len == generated_char_count + 2:
            entropy_binary = int_to_padded_binary(int(entropy_string, 16), generated_bit_count)
            return entropy_binary


def generate_entropy(generated_bit_count):
    generated_char_count = generated_bit_count // 4
    entropy = secrets.randbits(generated_bit_count)  # generate bits
    entropy_binary = int_to_padded_binary(entropy, generated_bit_count)  # convert entropy to binary
   
    entropy_hex = binary_to_padded_hex(entropy_binary, generated_char_count)
 
    return entropy_binary


def get_hash(entropy):
    generated_bit_count = len(entropy)
    generated_char_count = generated_bit_count // 4
    # print('gcc:', generated_char_count)
    entropy_hex = binary_to_padded_hex(entropy, generated_char_count)  # assign hex string to entropy_hex variable

    entropy_hex_no_padding = entropy_hex[2:]  # removing leading 0x hex pad

   

    entropy_bytearray = bytearray.fromhex(entropy_hex_no_padding)  # *convert no padded hex string to bytearray


    bits = hashlib.sha256(entropy_bytearray).hexdigest()  # *compute the sha256 hash of the bytearray as a hex digest
    return bits


def pick_words(entropy, entropy_hash, checksum_bit_count):
    generated_bit_count = len(entropy)
    generated_char_count = generated_bit_count // 4
    entropy_hex = binary_to_padded_hex(entropy, generated_char_count)  # assign hex string to entropy_hex variable
    checksum_char_count = checksum_bit_count // 4
    bit = entropy_hash[0:checksum_char_count]  # *take first x bit of bits (x is not defined but be added to slice manually)


    check_bit = int(bit, 16)  # converts hex to binary
    checksum = int_to_padded_binary(check_bit, checksum_bit_count)
   
    source = str(entropy) + str(checksum) 
    groups = [source[i:i + 11] for i in range(0, len(source), 11)] 

    totalbits = hex(int(str('0b') + entropy + str(checksum), 2))

    indices = [int(str('0b') + source[i:i + 11], 2) for i in range(0, len(source), 11)]  # (str('0b') for i in range(0,len(source),11))
    
    return indices


def print_words(indices):
    
    words = [bip39wordlist[indices[i]] for i in range(0, len(indices))]
    word_string = ' '.join(words)
    # print(word_string)

def writefile(indices):
    words = [bip39wordlist[indices[i]] for i in range(0, len(indices))]
    word_string = ' '.join(words)    
    return word_string

def int_to_padded_binary(num, padding):
    return bin(num)[2:].zfill(padding)


def binary_to_padded_hex(bin, padding):
    num = int(bin, 2)
    return '0x{0:0{1}x}'.format(num, padding)


newwordslist = []

with open("./wordlist/english.txt", "r") as k:
    newwordslist = [w.strip() for w in k.readlines()]
    
bip39wordlist = newwordslist

allcombi = []


i = 0
j = 0
x = datetime.now()

k = "New_500_"+str(x)+".txt"

while j<100:
    with open(k, 'a') as c:
        b  = createmnemonic()
        if b not in allcombi:
            c.write(b + "\n")
            c.close
        j += 1
print("New file create successfully...")
    