import struct

# Constants used in the SHA-256 algorithm
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Helper functions
def right_rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xffffffff

def sha256_transform(state, block):
    w = [0] * 64
    w[0:16] = struct.unpack('!16L', block)

    for i in range(16, 64):
        s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = h + s1 + ch + K[i] + w[i]
        s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    state[0] = (state[0] + a) & 0xffffffff
    state[1] = (state[1] + b) & 0xffffffff
    state[2] = (state[2] + c) & 0xffffffff
    state[3] = (state[3] + d) & 0xffffffff
    state[4] = (state[4] + e) & 0xffffffff
    state[5] = (state[5] + f) & 0xffffffff
    state[6] = (state[6] + g) & 0xffffffff
    state[7] = (state[7] + h) & 0xffffffff

def sha256(data):
    # Initial hash values
    state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Pre-processing: Padding the data
    data = bytearray(data)
    orig_len_in_bits = (8 * len(data)) & 0xffffffffffffffff
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += orig_len_in_bits.to_bytes(8, 'big')

    # Process the message in successive 512-bit chunks
    for i in range(0, len(data), 64):
        sha256_transform(state, data[i:i + 64])

    # Produce the final hash value (big-endian) as a 256 bit number
    return b''.join(struct.pack('!I', i) for i in state)

# Test the SHA-256 implementation
def sha256_test():
    test_data = b"hello, world"
    hash_value = sha256(test_data)
    print(hash_value.hex())

sha256_test()
