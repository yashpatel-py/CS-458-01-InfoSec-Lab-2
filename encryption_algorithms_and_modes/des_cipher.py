from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class DESCipher:
    def __init__(self, key):
        if len(key) != DES.key_size:
            raise ValueError("Key must be exactly 8 bytes long.")
        self.key = key

    def encrypt(self, plaintext, mode):
        cipher_mode = self._get_mode(mode)
        if cipher_mode == DES.MODE_CBC:
            iv = get_random_bytes(DES.block_size)
            cipher = DES.new(self.key, cipher_mode, iv)
            ciphertext = iv + cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
        else:
            cipher = DES.new(self.key, cipher_mode)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
        return ciphertext

    def decrypt(self, ciphertext, mode):
        cipher_mode = self._get_mode(mode)
        if cipher_mode == DES.MODE_CBC:
            iv = ciphertext[:DES.block_size]
            cipher = DES.new(self.key, cipher_mode, iv)
            plaintext = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)
        else:
            cipher = DES.new(self.key, cipher_mode)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return plaintext.decode('utf-8')

    def _get_mode(self, mode):
        if mode == 'CBC':
            return DES.MODE_CBC
        elif mode == 'ECB':
            return DES.MODE_ECB
        else:
            raise ValueError("Invalid mode provided. Use 'ECB' or 'CBC'.")

    @staticmethod
    def generate_key():
        return get_random_bytes(DES.key_size)
