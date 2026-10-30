
# Simplified Data Encryption Standard (SDES)

# Permutation tables
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# S-Boxes
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


# Apply permutation
def permute(bits, table):
    return [bits[i - 1] for i in table]


# Circular left shift
def left_shift(bits, count):
    return bits[count:] + bits[:count]


# XOR operation
def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


# Generate two subkeys
def generate_keys(key):
    key = [int(bit) for bit in format(key, '010b')]

    p10 = permute(key, P10)

    left = p10[:5]
    right = p10[5:]

    # First left shift
    left = left_shift(left, 1)
    right = left_shift(right, 1)

    k1 = permute(left + right, P8)

    # Second left shift
    left = left_shift(left, 2)
    right = left_shift(right, 2)

    k2 = permute(left + right, P8)

    return k1, k2


# S-Box substitution
def sbox(bits, box):
    row = bits[0] * 2 + bits[3]
    col = bits[1] * 2 + bits[2]

    value = box[row][col]

    return [int(bit) for bit in format(value, '02b')]


# Feistel function
def fk(bits, key):
    left = bits[:4]
    right = bits[4:]

    expanded = permute(right, EP)

    result = xor(expanded, key)

    left_result = sbox(result[:4], S0)
    right_result = sbox(result[4:], S1)

    combined = permute(left_result + right_result, P4)

    return xor(left, combined) + right


# Swap left and right halves
def switch(bits):
    return bits[4:] + bits[:4]


# Encrypt one byte using generated keys
def encrypt_byte_with_keys(value, k1, k2):
    bits = [int(bit) for bit in format(value, '08b')]

    bits = permute(bits, IP)
    bits = fk(bits, k1)
    bits = switch(bits)
    bits = fk(bits, k2)
    bits = permute(bits, IP_INV)

    return int(''.join(map(str, bits)), 2)


# Decrypt one byte using generated keys
def decrypt_byte_with_keys(value, k1, k2):
    bits = [int(bit) for bit in format(value, '08b')]

    bits = permute(bits, IP)
    bits = fk(bits, k2)
    bits = switch(bits)
    bits = fk(bits, k1)
    bits = permute(bits, IP_INV)

    return int(''.join(map(str, bits)), 2)


# Encrypt a single byte
def encrypt_byte(value, key):
    k1, k2 = generate_keys(key)
    return encrypt_byte_with_keys(value, k1, k2)


# Decrypt a single byte
def decrypt_byte(value, key):
    k1, k2 = generate_keys(key)
    return decrypt_byte_with_keys(value, k1, k2)


# Encrypt complete data
def encrypt_data(data, key):
    k1, k2 = generate_keys(key)

    return bytes(
        encrypt_byte_with_keys(byte, k1, k2)
        for byte in data
    )


# Decrypt complete data
def decrypt_data(data, key):
    k1, k2 = generate_keys(key)

    return bytes(
        decrypt_byte_with_keys(byte, k1, k2)
        for byte in data
    )
