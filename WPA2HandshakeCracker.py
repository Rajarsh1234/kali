import os
import hashlib
from Crypto.Cipher import AES

def main():
    handshake_file_path = input("Enter the path to the handshake file: ")
    wordlist_file_path = input("Enter the path to the wordlist file: ")

    try:
        if not os.path.exists(handshake_file_path) or not os.path.exists(wordlist_file_path):
            print("The specified files do not exist.")
            return

        with open(handshake_file_path, 'rb') as handshake_file:
            handshake_bytes = handshake_file.read()

        with open(wordlist_file_path, 'r') as wordlist_file:
            for line in wordlist_file:
                password = line.strip()
                pmk = generate_pmk(password)

                try:
                    decrypted_bytes = decrypt_handshake(handshake_bytes, pmk)

                    # Check if the decryption is successful
                    if is_valid_decryption(decrypted_bytes):
                        print("Password found:", password)
                        return
                except ValueError:
                    # Incorrect password, continue with the next one
                    pass

        print("Password not found in the wordlist.")
    except Exception as e:
        # Handle or print the exception as needed
        print("An error occurred:", str(e))

def generate_pmk(password):
    ssid = "Purabi"  # Replace with the actual SSID
    salt = ssid.encode('utf-8')
    password = password.encode('utf-8')
    pmk = hashlib.pbkdf2_hmac('sha1', password, salt, 4096, 32)
    return pmk

def decrypt_handshake(handshake_bytes, pmk):
    try:
        key_spec = AES.new(pmk, AES.MODE_ECB)
        decrypted_bytes = key_spec.decrypt(handshake_bytes)
        return decrypted_bytes
    except Exception as e:
        # Handle decryption errors, e.g., incorrect PMK
        raise ValueError("Decryption failed: " + str(e))

def is_valid_decryption(decrypted_bytes):
    # You need to implement a function to check if the decrypted data is valid
    # This depends on the structure of the handshake file and how you can determine validity
    # For WPA2 handshakes, it typically involves checking for specific patterns or fields
    # Return True if it's a valid decryption, otherwise False
    # For now, just return True to test decryption
    return True

if __name__ == "__main__":
    main()
