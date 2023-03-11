import struct

def sha256(data):
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
   
    # Pre-processing
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8
   
    # append the bit '1' to the message
    data += b'\x80'
   
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    data += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
   
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    data += struct.pack(b'>Q', original_bit_len)
   
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(data), 64):
        w = [0] * 64
       
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', data[i + j*4:i + j*4 + 4])[0]
       
        # Extend the sixteen 32-bit words into sixty-four 32-bit words:
        for j in range(16, 64):
            s0 = (w[j-15] >> 7 | w[j-15] << 25) ^ (w[j-15] >> 18 | w[j-15] << 14) ^ (w[j-15] >> 3)
            s1 = (w[j-2] >> 17 | w[j-2] << 15) ^ (w[j-2] >> 19 | w[j-2] << 13) ^ (w[j-2] >> 10)
            w[j] = w[j-16] + s0 + w[j-7] + s1
           
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
       
        # Main loop:
        for i in range(64):
            S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)
            ch = (e & f) ^ (~e & g)
            temp1 = h + S1 + ch + k[i] + w[i]
            S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)
