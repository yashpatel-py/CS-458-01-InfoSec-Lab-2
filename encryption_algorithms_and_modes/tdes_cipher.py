from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class TDESCipher:
    def __init__(self, key):
        # 3DES key must be either 16 or 24 bytes long. We'll enforce 24 bytes.
        if len(key) not in [16, 24]:
            raise ValueError("Key must be either 16 or 24 bytes long.")
        self.key = DES3.adjust_key_parity(key)

    def encrypt(self, plaintext, mode='CBC'):
        cipher = DES3.new(self.key, DES3.MODE_CBC if mode == 'CBC' else DES3.MODE_ECB)
        iv = cipher.iv if mode == 'CBC' else None
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
        return (iv + ciphertext) if mode == 'CBC' else ciphertext

    def decrypt(self, ciphertext, mode='CBC'):
        if mode == 'CBC':
            # For CBC mode, the first 8 bytes are the IV
            iv = ciphertext[:DES3.block_size]
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext[DES3.block_size:]), DES3.block_size)
        elif mode == 'ECB':
            # For ECB mode, no IV is needed
            cipher = DES3.new(self.key, DES3.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        else:
            raise ValueError("Invalid mode provided. Use 'ECB' or 'CBC'.")

        return plaintext.decode('utf-8')
    @staticmethod
    def generate_key():
        # Generate a random 24-byte key.
        return get_random_bytes(24)
