def simple_transposition_encrypt(plaintext, key):
    plaintext = ' '.join(plaintext.split()).upper()
    padded_length = len(plaintext) + (key - len(plaintext) % key) % key
    plaintext += ' ' * (padded_length - len(plaintext))
    ciphertext = ''
    for i in range(key):
        ciphertext += ''.join(plaintext[j] for j in range(i, len(plaintext), key))
    return ciphertext

def simple_transposition_decrypt(ciphertext, key):
    rows = len(ciphertext) // key
    extra_chars = len(ciphertext) % key
    
    full_columns = extra_chars
    short_columns = key - extra_chars
    plaintext = [''] * (rows + 1)

    cur_row = 0
    cur_col = 0
    for char in ciphertext:
        plaintext[cur_row] += char
        cur_row += 1
        if (cur_col < full_columns and cur_row == rows + 1) or (cur_col >= full_columns and cur_row == rows):
            cur_row = 0
            cur_col += 1
    
    return ''.join(plaintext).rstrip()

def get_numerical_key(prompt="Enter the numerical key: "):
    try:
        key = int(input(prompt))
        return key
    except ValueError:
        print("Invalid key. Please enter a positive integer.")
        return get_numerical_key(prompt)
