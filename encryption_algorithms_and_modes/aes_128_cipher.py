from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AES128Cipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        if len(key) != AES.block_size:
            raise ValueError(f"Key must be {AES.block_size} bytes long.")
        self.key = key  # The key must already be the correct size
        
    def encrypt(self, plaintext, mode):
        plaintext = pad(plaintext.encode(), AES.block_size)
        if mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
        elif mode == 'CBC':
            self.iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        else:
            raise ValueError("Unsupported mode provided")
        
        ciphertext = cipher.encrypt(plaintext)
        return (self.iv + ciphertext) if mode == 'CBC' else ciphertext

    def decrypt(self, ciphertext, mode):
        if mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        elif mode == 'CBC':
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        else:
            raise ValueError("Unsupported mode provided")
        
        return plaintext.decode('utf-8')
