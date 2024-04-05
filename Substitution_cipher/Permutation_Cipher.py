def permute_encrypt(text, key):
    permuted_text = ''
    for char in text:
        if char.isalpha():
            index = ord(char.lower()) - ord('a')
            permuted_char = key[index]
            permuted_text += permuted_char.upper() if char.isupper() else permuted_char
        else:
            permuted_text += char
    return permuted_text

def permute_decrypt(text, key):
    reverse_key = {v: k for k, v in enumerate(key)}
    permuted_text = ''
    for char in text:
        if char.isalpha():
            index = reverse_key[char.lower()]
            permuted_char = chr(index + ord('a'))
            permuted_text += permuted_char.upper() if char.isupper() else permuted_char
        else:
            permuted_text += char
    return permuted_text

def get_permutation_key():
    while True:
        key = input("Enter the permutation key as a sequence of 26 unique characters: ")
        if len(key) != 26 or not all(char.isalpha() for char in key) or len(set(key.lower())) != 26:
            print("Permutation key must contain 26 unique alphabetic characters.")
        else:
            return key.lower()