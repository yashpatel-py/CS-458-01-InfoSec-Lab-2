from Substitution_cipher.shift_cipher import shift_encrypt, shift_decrypt, get_numerical_key
from Substitution_cipher.Permutation_Cipher import permute_decrypt, permute_encrypt, get_permutation_key
from Transposition_ciphers.Simple_Transposition_Cipher import simple_transposition_encrypt, simple_transposition_decrypt, get_numerical_key
from Transposition_ciphers.double_transposition import double_transposition_encrypt, double_transposition_decrypt
from Vigenere_Cipher.vigenere_cipher import VigenereCipher
from encryption_algorithms_and_modes.aes_128_cipher import AES128Cipher
from encryption_algorithms_and_modes.des_cipher import DESCipher
from encryption_algorithms_and_modes.tdes_cipher import TDESCipher
from Crypto.Random import get_random_bytes
from random import randint
import random

def main():
    print("Select the encryption method:")
    print("1: Shift Cipher")
    print("2: Permutation Cipher")
    print("3: Simple Transposition Cipher")
    print("4: Double Transposition Cipher")
    print("5: Vigenère Cipher")
    print("6: AES-128 Cipher")
    print("7: DES Cipher")
    print("8: 3DES Cipher")

    cipher_choice = input("Enter the cipher choice: ")

    if cipher_choice == "1":
        plaintext = input("Enter the text to encrypt: ")
        use_default_key = input("Do you want to use the default key? (yes/no/random): ").lower()
        shift = 3 

        if use_default_key == "yes":
            print(f"Using the default shift key: {shift}")
        elif use_default_key == "random":
            shift = randint(1, 25)
            print(f"Randomly generated shift key: {shift}")
        else:
            shift = get_numerical_key()

        encrypted_text = shift_encrypt(plaintext, shift)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            encrypted_text_for_decryption = input("Enter the encrypted text for decryption: ")
            if use_default_key == "random":
                decryption_shift = int(input("Enter the randomly generated key: "))
            elif use_default_key == "no":
                decryption_shift = get_numerical_key()
            else:
                decryption_shift = shift

            decrypted_text = shift_decrypt(encrypted_text_for_decryption, decryption_shift)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")

    if cipher_choice == "2":
        def get_random_permutation_key():
            alphabet = list("abcdefghijklmnopqrstuvwxyz")
            random.shuffle(alphabet)
            return ''.join(alphabet)
        plaintext = input("Enter the text to encrypt: ")
        use_default_key = input("Do you want to use the default key? (yes/no/random): ").lower()

        if use_default_key == "yes":
            key = "bcdefghijklmnopqrstuvwxyza"
        elif use_default_key == "random":
            key = get_random_permutation_key()
            print(f"Randomly generated key: {key}")
        else:
            key = get_permutation_key()

        encrypted_text = permute_encrypt(plaintext, key)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            if use_default_key == "random":
                print("Enter the randomly generated key you saved:")
                decryption_key = input("Key: ")
            elif use_default_key == "no":
                decryption_key = get_permutation_key()
            else:
                decryption_key = key

            encrypted_text_for_decryption = input("Enter the encrypted text: ")
            decrypted_text = permute_decrypt(encrypted_text_for_decryption, decryption_key)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")

    elif cipher_choice == "3":
        plaintext = input("Enter the text to encrypt: ")

        use_default_key = input("Do you want to use the default key? (yes/no): ").lower()
        key = 4

        if use_default_key == "no":
            key = get_numerical_key("Enter the numerical key: ")

        encrypted_text = simple_transposition_encrypt(plaintext, key)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            encrypted_text_for_decryption = input("Enter the encrypted text: ")
            use_default_key_during_decryption = input("Do you want to use the default key during decryption? (yes/no): ").lower()

            if use_default_key_during_decryption == "no":
                decryption_key = get_numerical_key("Enter the decryption key: ")
            else:
                decryption_key = key

            decrypted_text = simple_transposition_decrypt(encrypted_text_for_decryption, decryption_key)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
        return
    
    elif cipher_choice == "4":
        plaintext = input("Enter the text to encrypt: ")

        use_default_keys = input("Do you want to use the default keys? (yes/no): ").lower()
        
        if use_default_keys == "no":
            key1 = get_numerical_key("Enter the first numerical key: ")
            key2 = get_numerical_key("Enter the second numerical key: ")
        else:
            key1, key2 = 4, 5

        encrypted_text = double_transposition_encrypt(plaintext, key1, key2)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            encrypted_text_for_decryption = input("Enter the encrypted text: ")

            if use_default_keys == "no":
                key1 = get_numerical_key("Enter the first numerical key for decryption: ")
                key2 = get_numerical_key("Enter the second numerical key for decryption: ")
            else:
                pass

            decrypted_text = double_transposition_decrypt(encrypted_text_for_decryption, key1, key2)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
        return
    
    elif cipher_choice == "5":
        plaintext = input("Enter the text to encrypt: ")
        
        use_default_key = input("Do you want to use the default key? (yes/no): ").lower()
        if use_default_key == "yes":
            keyword = "INFOSEC"
        else:
            keyword = input("Enter the keyword: ")

        cipher = VigenereCipher(keyword)
        encrypted_text = cipher.encrypt(plaintext)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            ciphertext = input("Enter the text to decrypt: ")
            decrypted_text = cipher.decrypt(ciphertext)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
        return

    elif cipher_choice == "6":
        plaintext = input("Enter the text to encrypt: ")
        use_default_key = input("Do you want to use the default key? (yes/no/random): ").lower()
        
        if use_default_key == "yes":
            key = b'ThisIsADefaultKe'
            print(f"Using the default key: {key.hex()}")
        elif use_default_key == "random":
            key = get_random_bytes(16)
            print(f"Randomly generated key (hex): {key.hex()}")
        else:
            key_input = input("Enter a 16-byte key: ")
            key = key_input.encode('utf-8').ljust(16, b'\0')

        mode = input("Enter the mode of operation for encryption (ECB/CBC): ").upper()
        aes_cipher = AES128Cipher(key)
        encrypted_text = aes_cipher.encrypt(plaintext, mode)
        print("Encrypted text:", encrypted_text.hex())
        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            if use_default_key == "no":
                key_input = input("Enter the 16-byte key used for encryption: ")
                key = key_input.encode('utf-8').ljust(16, b'\0')
            
            decryption_mode = input("Enter the mode of operation for decryption (ECB/CBC): ").upper()
            ciphertext_hex = input("Enter the encrypted text (in hex): ")
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted_text = aes_cipher.decrypt(ciphertext, decryption_mode)
            print("Decrypted text:", decrypted_text)
        
            return

        print("Decryption not performed.")
        return


    elif cipher_choice == "7":
        plaintext = input("Enter the text to encrypt: ")
        use_default_key = input("Do you want to use the default key? (yes/no): ").lower()
        
        if use_default_key == "yes":
            key = b'DfltKey!'
            print(f"Using the default key: {key.hex()}")
        else:
            while True:
                key_input = input("Enter an 8-character key: ")
                if len(key_input) == 8:
                    key = key_input.encode('utf-8')
                    break
                print("Key must be exactly 8 characters long.")
        
        mode = input("Enter the mode of operation for encryption (ECB/CBC): ").upper()
        des_cipher = DESCipher(key)
        encrypted_text = des_cipher.encrypt(plaintext, mode)
        print("Encrypted text:", encrypted_text.hex())

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            if use_default_key != "yes":
                key = input("Enter the 8-character key used for encryption: ").encode('utf-8')
            decryption_mode = input("Enter the mode of operation for decryption (ECB/CBC): ").upper()
            ciphertext_hex = input("Enter the encrypted text (in hex): ")
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted_text = des_cipher.decrypt(ciphertext, decryption_mode)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
        return
    
    elif cipher_choice == "8":
        plaintext = input("Enter the text to encrypt: ")
        use_default_key = input("Do you want to use the default key? (yes/no/random): ").lower()

        if use_default_key == "yes":
            key = b'DefaultKeyMustBe24Bytes!'
            print(f"Using the default key: {key.hex()}")
        elif use_default_key == "random":
            key = TDESCipher.generate_key()
            print(f"Randomly generated key (hex): {key.hex()}")
        else:
            while True:
                key_input = input("Enter a 16 or 24-byte key: ")
                key = key_input.encode('utf-8')
                if len(key) in (16, 24):
                    break
                print("Key must be either 16 or 24 bytes long.")
        mode = input("Enter the mode of operation for encryption (ECB/CBC): ").upper()
        tdes_cipher = TDESCipher(key)
        encrypted_text = tdes_cipher.encrypt(plaintext, mode)
        print("Encrypted text:", encrypted_text.hex())

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            if use_default_key == "no":
                while True:
                    decryption_key_input = input("Enter the 16 or 24-byte key used for encryption: ")
                    decryption_key = decryption_key_input.encode('utf-8')
                    if len(decryption_key) in (16, 24):
                        break
                    print("Key must be either 16 or 24 bytes long.")
            else:
                decryption_key = key

            decryption_mode = input("Enter the mode of operation for decryption (ECB/CBC): ").upper()
            ciphertext_hex = input("Enter the encrypted text (in hex): ")
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted_text = tdes_cipher.decrypt(ciphertext, decryption_mode)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
        return

if __name__ == "__main__":
    main()