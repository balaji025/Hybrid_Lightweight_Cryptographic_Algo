import time
import random
import math

debug = False
debugpermutation = False
enq = {}  # Dictionary to store encoding mappings
deq = {}  # Dictionary to store decoding mappings


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def primefiller():
    s = [True] * 250
    s[0] = False
    s[1] = False
    for i in range(2, int(math.sqrt(250)) + 1):
        if s[i]:
            for j in range(i * i, 250, i):
                s[j] = False
    prime = set()
    for i in range(len(s)):
        if s[i]:
            prime.add(i)
    return prime

prime = primefiller()

def pickrandomprime():
    p = random.randint(0, len(prime) - 1)
    i = iter(prime)
    for _ in range(p):
        next(i)
    ret = next(i)
    prime.remove(ret)
    return ret

def setkeys():
    prime1 = pickrandomprime()
    prime2 = pickrandomprime()
    n = prime1 * prime2
    fi = (prime1 - 1) * (prime2 - 1)
    e = 2
    while (gcd(e, fi) != 1):
        e += 1
    public_key = e
    d = 2
    while ((d * e) % fi != 1):
        d += 1
    private_key = d
    return public_key, private_key, n

public_key, private_key, n = setkeys()

def encrypt(message):
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text

def encoder(message):
    encoded = []
    for letter in message:
        if letter in enq.keys():
            encoded.append(enq[letter])
        else:
            eq = encrypt(ord(letter))
            encoded.append(eq)
            enq[letter] = eq
    return encoded

def decrypt(encrypted_text):
    d = private_key
    decrypted = 1
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= n
        d -= 1
    return decrypted

def decoder(encoded):
    s = ' '
    for num in encoded:
        if num in deq.keys():
            s += deq[num]
        else:
            q = chr(decrypt(num))
            s += q
            deq[num] = q
    return s

def rsa(message):
    # Encoding
    encoded_message = encoder(message)

    # Decoding
    decoded_message = decoder(encoded_message)

    return encoded_message, decoded_message

def results_rsa(m,m1,m2):
    print("RSA Input: ",m)
    print("RSA Encoded: ",m1)
    print("RSA Decoded: ",m2)

def get_random_bytes(num):
    import os
    return to_bytes(os.urandom(num))

def zero_bytes(n):
    return n * b"\x00"

def to_bytes(l): # where l is a list or bytearray or bytes
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << ((len(bytes) - 1 - i)*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> ((nbytes - 1 - i) * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return (val >> r) | ((val & (1<<r)-1) << (64-r))

def bytes_to_hex(b):
    return b.hex()
    #return "".join(x.encode('hex') for x in b)

def printstate(S, description=""):
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S, description=""):
    print(" " + description)
    print("\n".join(["  x{i}={s:016x}".format(**locals()) for i, s in enumerate(S)]))

def bytes_to_string(byte_data):
    try:
        # Decode bytes to string using UTF-8 encoding
        decoded_string = byte_data.decode("utf-8")
        return decoded_string
    except UnicodeDecodeError as e:
        print("Error decoding byte data:", e)
        return None


def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128"): 
    """
    Ascon encryption.
    key: a bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    plaintext: a bytes object of arbitrary length
    variant: "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of rounds)
    returns a bytes object of length len(plaintext)+16 containing the ciphertext and tag
    """
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    if variant in ["Ascon-128", "Ascon-128a"]: assert(len(key) == 16 and len(nonce) == 16)
    if variant == "Ascon-80pq": assert(len(key) == 20 and len(nonce) == 16)
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8   # bits
    a = 12   # rounds
    b = 8 if variant == "Ascon-128a" else 6   # rounds
    rate = 16 if variant == "Ascon-128a" else 8   # bytes

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ciphertext + tag

def ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-128"):
    """
    Ascon decryption.
    key: a bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    ciphertext: a bytes object of arbitrary length (also contains tag)
    variant: "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of rounds)
    returns a bytes object containing the plaintext or None if verification fails
    """
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    if variant in ["Ascon-128", "Ascon-128a"]: assert(len(key) == 16 and len(nonce) == 16 and len(ciphertext) >= 16)
    if variant == "Ascon-80pq": assert(len(key) == 20 and len(nonce) == 16 and len(ciphertext) >= 16)
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8 # bits
    a = 12 # rounds
    b = 8 if variant == "Ascon-128a" else 6   # rounds
    rate = 16 if variant == "Ascon-128a" else 8   # bytes

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])
    tag = ascon_finalize(S, rate, a, key)
    if tag == ciphertext[-16:]:
        return plaintext
    else:
        return None

def ascon_initialize(S, k, rate, a, b, key, nonce):
    """
    Ascon initialization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    k: key size in bits
    rate: block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
    a: number of initialization/finalization rounds for permutation
    b: number of intermediate rounds for permutation
    key: a bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
    nonce: a bytes object of size 16
    returns nothing, updates S
    """
    iv_zero_key_nonce = to_bytes([k, rate * 8, a, b]) + zero_bytes(20-len(key)) + key + nonce
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv_zero_key_nonce)
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, a)

    zero_key = bytes_to_state(zero_bytes(40-len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]
    if debug: printstate(S, "initialization:")

def ascon_process_associated_data(S, b, rate, associateddata):
    """
    Ascon associated data processing phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for Ascon-128, 16 for Ascon-128a)
    associateddata: a bytes object of arbitrary length
    returns nothing, updates S
    """
    if len(associateddata) > 0:
        a_padding = to_bytes([0x80]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block+8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block+8:block+16])

            ascon_permutation(S, b)

    S[4] ^= 1
    if debug: printstate(S, "process associated data:")

def ascon_process_plaintext(S, b, rate, plaintext):
    """
    Ascon plaintext processing phase (during encryption) - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
    plaintext: a bytes object of arbitrary length
    returns the ciphertext (without tag), updates S
    """
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x80]) + zero_bytes(rate-p_lastlen-1)
    p_padded = plaintext + p_padding

    # first t-1 blocks
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        if rate == 8:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            ciphertext += int_to_bytes(S[0], 8)
        elif rate == 16:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            S[1] ^= bytes_to_int(p_padded[block+8:block+16])
            ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))

        ascon_permutation(S, b)

    # last block t
    block = len(p_padded) - rate
    if rate == 8:
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        ciphertext += int_to_bytes(S[0], 8)[:p_lastlen]
    elif rate == 16:
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        S[1] ^= bytes_to_int(p_padded[block+8:block+16])
        ciphertext += (int_to_bytes(S[0], 8)[:min(8,p_lastlen)] + int_to_bytes(S[1], 8)[:max(0,p_lastlen-8)])
    if debug: printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    """
    Ascon ciphertext processing phase (during decryption) - internal helper function. 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
    ciphertext: a bytes object of arbitrary length
    returns the plaintext, updates S
    """
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    # first t-1 blocks
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        if rate == 8:
            Ci = bytes_to_int(c_padded[block:block+8])
            plaintext += int_to_bytes(S[0] ^ Ci, 8)
            S[0] = Ci
        elif rate == 16:
            Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
            plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
            S[0] = Ci[0]
            S[1] = Ci[1]

        ascon_permutation(S, b)

    # last block t
    block = len(c_padded) - rate
    if rate == 8:
        c_padding1 = (0x80 << (rate-c_lastlen-1)*8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen*8))
        Ci = bytes_to_int(c_padded[block:block+8])
        plaintext += int_to_bytes(Ci ^ S[0], 8)[:c_lastlen]
        S[0] = Ci ^ (S[0] & c_mask) ^ c_padding1
    elif rate == 16:
        c_lastlen_word = c_lastlen % 8
        c_padding1 = (0x80 << (8-c_lastlen_word-1)*8)
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen_word*8))
        Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
        if c_lastlen < 8:
            S[0] = Ci[0] ^ (S[0] & c_mask) ^ c_padding1
        else:
            S[0] = Ci[0]
            S[1] = Ci[1] ^ (S[1] & c_mask) ^ c_padding1
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S, rate, a, key):
    """
    Ascon finalization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rate: block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
    a: number of initialization/finalization rounds for permutation
    key: a bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq; 128-bit security)
    returns the tag, updates S
    """
    assert(len(key) in [16,20])
    S[rate//8+0] ^= bytes_to_int(key[0:8])
    S[rate//8+1] ^= bytes_to_int(key[8:16])
    S[rate//8+2] ^= bytes_to_int(key[16:] + zero_bytes(24-len(key)))

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag

def ascon_permutation(S, rounds=1):
    """
    Ascon core permutation for the sponge construction - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rounds: number of rounds to perform
    returns nothing, updates S
    """
    assert(rounds <= 12)
    if debugpermutation: printwords(S, "permutation input:")
    for r in range(12-rounds, 12):
        # --- add round constants ---
        S[2] ^= (0xf0 - r*0x10 + r*0x1)
        if debugpermutation: printwords(S, "round constant addition:")
        # --- substitution layer ---
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF
        if debugpermutation: printwords(S, "substitution layer:")
        # --- linear diffusion layer ---
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        if debugpermutation: printwords(S, "linear diffusion layer:")

def demo_print(data):
    maxlen = max([len(text) for (text, val) in data])
    for text, val in data:
        print("{text}:{align} 0x{val} ({length} bytes)".format(text=text, align=((maxlen - len(text)) * " "), val=bytes_to_hex(val), length=len(val)))

def demo_hybrid(plaintext,message):
    variant ="Ascon-128"
    keysize = 16
    print("")
    print("=== demo encryption and decryption using {variant} and RSA ===".format(variant=variant))
    print("")
    #print("Message: ",message)
    
    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(keysize) # zero_bytes(keysize)
    nonce = get_random_bytes(16)      # zero_bytes(16)
    associateddata = b"ASCON"
    #print("Ascon Input: ",plaintext)
    
    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    #print("Ascon Encoded: ",ciphertext.hex())
    
    rsa_input = ciphertext.hex()
    enc_rsa, dec_rsa = rsa(rsa_input)
    
    dec_rsa_byte = bytearray.fromhex(dec_rsa)
    
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, dec_rsa_byte, variant)


    receivedmessage = receivedplaintext.decode("utf-8")

    if receivedplaintext == None: print("verification failed!")

def demo_hybrid_print(plaintext,message):
    variant ="Ascon-128"
    keysize = 16
    print("")
    print("=== demo encryption and decryption using {variant} and RSA ===".format(variant=variant))
    print("")
    print("Message: ",message)
    
    # choose a cryptographically strong random key and a nonce that never repeats for the same key:
    key   = get_random_bytes(keysize) # zero_bytes(keysize)
    nonce = get_random_bytes(16)      # zero_bytes(16)
    associateddata = b"ASCON"
    print("Ascon Input: ",plaintext)
    
    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext,  variant)
    print("Ascon Encoded(bytes): ",ciphertext)
    print("Accon Encoded:",ciphertext.hex())

    rsa_input = ciphertext.hex()
    enc_rsa, dec_rsa = rsa(rsa_input)
    results_rsa(rsa_input, enc_rsa, dec_rsa)
    
    dec_rsa_byte = bytearray.fromhex(dec_rsa)
    print("RSA Decoded(bytes): ", dec_rsa_byte)

    receivedplaintext = ascon_decrypt(key, nonce, associateddata, dec_rsa_byte, variant)
    print("Ascon Decoded: ",receivedplaintext)

    receivedmessage = receivedplaintext.decode("utf-8")
    print("Message: ",receivedmessage)
    if receivedplaintext == None: print("verification failed!")


'''
if __name__ == "__main__":
    public_key, private_key, n = setkeys()
    # file = open("75000.txt","r")
    # message = file.readline()
    message = input()
    start = time.time()
    bytes_message = message.encode("utf-8")
    demo_hybrid_print(bytes_message,message)
    end = time.time()
    
    print("The time of execution of above program is :",(end-start), "s")
'''

def demo_hybrid_encrypt(message):
    
    plaintext=message.encode("utf-8")
    variant = "Ascon-128"
    keysize = 16
    
    # Choose a cryptographically strong random key and a nonce that never repeats for the same key
    key = get_random_bytes(keysize)
    nonce = get_random_bytes(16)
    associateddata = b"ASCON"
    
    # Encrypt the plaintext using Ascon
    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext, variant)
    
    # Convert the ciphertext to hex format (for RSA input)
    rsa_input = ciphertext.hex()
    
    # RSA encryption
    enc_rsa, _ = rsa(rsa_input)
    
    s=''
    for i in enc_rsa:
        s+=str(i)
    # Return the RSA-encrypted data
    return s


#encrypted_message = demo_hybrid_encrypt(bytes_message, message)
#print("Encrypted Message:", encrypted_message)





