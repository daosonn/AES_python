import numpy as np
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16

INV_S_BOX = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0x7B, 0xF2, 0xC3, 0x9F, 0x81, 0xF3, 0xD7,
    0xFB, 0x7C, 0x7B, 0xF2, 0xC3, 0x9F, 0x81, 0xF3,
    0xD7, 0xFB, 0x7C, 0x7B, 0xF2, 0xC3, 0x9F, 0x81,
    0xF3, 0xD7, 0xFB, 0x7C, 0x7B, 0xF2, 0xC3, 0x9F,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0x7B, 0xF2, 0xC3,
    0x9F, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0x7B, 0xF2,
    0xC3, 0x9F, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0x7B,
    0xF2, 0xC3, 0x9F, 0x81, 0xF3, 0xD7, 0xFB, 0x7C,
    0x7B, 0xF2, 0xC3, 0x9F, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0x7B, 0xF2, 0xC3, 0x9F, 0x81, 0xF3, 0xD7,
])

# AES 
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i, j] = INV_S_BOX[state[i, j]]
    return state

def shift_rows(state):
    state[1] = np.roll(state[1], 3)  
    state[2] = np.roll(state[2], 2) 
    state[3] = np.roll(state[3], 1)  
    return state

def mix_columns(state):
    for i in range(4):
        col = state[:, i]
        state[:, i] = [
            (14 * col[0]) ^ (11 * col[1]) ^ (13 * col[2]) ^ (9 * col[3]),
            (9 * col[0]) ^ (14 * col[1]) ^ (11 * col[2]) ^ (13 * col[3]),
            (13 * col[0]) ^ (9 * col[1]) ^ (14 * col[2]) ^ (11 * col[3]),
            (11 * col[0]) ^ (13 * col[1]) ^ (9 * col[2]) ^ (14 * col[3]),
        ]
    return state

def add_round_key(state, key):
    return np.bitwise_xor(state, key)

def key_expansion(key):
    return [key] 

def decrypt(ciphertext, key):
    state = np.array(ciphertext).reshape(4, 4)  
    state = add_round_key(state, key)  
    state = shift_rows(state) 
    state = sub_bytes(state)  
    state = mix_columns(state)  
    state = add_round_key(state, key)  
    return unpad(state.flatten(), BLOCK_SIZE)  

def decrypt_file(input_file, output_file, key_file):
    with open(key_file, 'rb') as keyfile:
        key = keyfile.read()

    with open(input_file, 'rb') as infile:
        encrypted_data = infile.read()

    decrypted_data = decrypt(encrypted_data, key)

    with open(output_file, 'wb') as outfile:
        outfile.write(decrypted_data)

    print(f"decrypted and saved to {output_file}")

decrypt_file(r"C:\Users\Admin\OneDrive - Hanoi University of Science and Technology\Tailieutruong_20242\ATTT\AES\encrypted.txt", r"C:\Users\Admin\OneDrive - Hanoi University of Science and Technology\Tailieutruong_20242\ATTT\AES\decrypted.txt", r"C:\Users\Admin\OneDrive - Hanoi University of Science and Technology\Tailieutruong_20242\ATTT\AES\key.txt")
