from Transposition_ciphers.Simple_Transposition_Cipher import simple_transposition_decrypt, simple_transposition_encrypt

# In double_transposition.py
def double_transposition_encrypt(plaintext, key1, key2):
    first_transposition = simple_transposition_encrypt(plaintext, key1)
    second_transposition = simple_transposition_encrypt(first_transposition, key2)
    return second_transposition

def double_transposition_decrypt(ciphertext, key1, key2):
    first_reversal = simple_transposition_decrypt(ciphertext, key2)
    second_reversal = simple_transposition_decrypt(first_reversal, key1)
    return second_reversal
