# vigenere_cipher.py
class VigenereCipher:
    def __init__(self, keyword):
        self.keyword = keyword

    def __create_key(self, text):
        key = self.keyword
        while len(key) < len(text):
            key += self.keyword
        return key[:len(text)]

    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        key = self.__create_key(plaintext)
        ciphertext = ""

        for p, k in zip(plaintext, key):
            if p.isalpha():
                shifted = ord(p) + (ord(k) - ord('A'))
                if shifted > ord('Z'):
                    shifted -= 26
                ciphertext += chr(shifted)
            else:
                ciphertext += p

        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        key = self.__create_key(ciphertext)
        plaintext = ""

        for c, k in zip(ciphertext, key):
            if c.isalpha():
                shifted = ord(c) - (ord(k) - ord('A'))
                if shifted < ord('A'):
                    shifted += 26
                plaintext += chr(shifted)
            else:
                plaintext += c

        return plaintext
