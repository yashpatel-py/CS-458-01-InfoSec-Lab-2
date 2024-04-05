def shift_encrypt(plaintext, shift):
    encrypted_text = ''
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_text += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                encrypted_text += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            encrypted_text += char
    return encrypted_text

def shift_decrypt(ciphertext, shift):
    decrypted_text = ''
    for char in ciphertext:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                decrypted_text += chr((ord(char) - ord('a') - shift_amount) % 26 + ord('a'))
            else:
                decrypted_text += chr((ord(char) - ord('A') - shift_amount) % 26 + ord('A'))
        else:
            decrypted_text += char
    return decrypted_text

def get_numerical_key(prompt):
    while True:
        try:
            key = int(input(prompt))
            if key <= 0:
                print("Key must be a positive integer.")
            else:
                return key
        except ValueError:
            print("Invalid key. Please enter a positive integer.")

def main():
    print("Select the encryption method:")
    print("1: Shift Cipher")

    cipher_choice = input("Enter the cipher choice (1): ")

    if cipher_choice == "1":
        plaintext = input("Enter the text to encrypt: ")

        use_default_key = input("Do you want to use the default key? (yes/no): ").lower()
        shift = 3  # Default shift value for Shift Cipher

        if use_default_key == "no":
            shift = get_numerical_key("Enter the shift key: ")

        encrypted_text = shift_encrypt(plaintext, shift)
        print("Encrypted text:", encrypted_text)

        perform_decryption = input("Do you want to perform decryption? (yes/no): ").lower()
        if perform_decryption == "yes":
            encrypted_text_for_decryption = input("Enter the encrypted text: ")
            use_default_key_during_decryption = input("Do you want to use the default key during decryption? (yes/no): ").lower()

            if use_default_key_during_decryption == "no":
                decryption_shift = get_numerical_key("Enter the decryption shift key: ")
            else:
                decryption_shift = shift

            decrypted_text = shift_decrypt(encrypted_text_for_decryption, decryption_shift)
            print("Decrypted text:", decrypted_text)
        else:
            print("Decryption not performed.")
    else:
        print("Invalid cipher choice.")

if __name__ == "__main__":
    main()