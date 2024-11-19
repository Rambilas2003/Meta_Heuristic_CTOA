from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# Function to generate a key using a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES key size (256 bits)
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

# Function to encrypt a message
def encrypt(plaintext: str, key: bytes) -> dict:
    # Generate a random nonce
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of block size
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }

# Function to decrypt a message
def decrypt(encrypted_data: dict, key: bytes) -> str:
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the plaintext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# Interactive Usage
if __name__ == "__main__":
    # Step 1: Input password and optional salt
    password = input("Enter a password for encryption: ").strip()
    
    # Optionally input a salt, or generate one if none is provided
    use_existing_salt = input("Do you have a salt to reuse? (yes/no): ").strip().lower()
    if use_existing_salt == "yes":
        salt = base64.b64decode(input("Enter the base64-encoded salt: ").strip())
    else:
        salt = os.urandom(16)
        print(f"Generated Salt (base64): {base64.b64encode(salt).decode()}")

    # Generate the encryption key
    key = generate_key(password, salt)

    # Step 2: Input a message to encrypt
    message = input("Enter the message to encrypt: ").strip()

    # Encrypt the message
    encrypted_data = encrypt(message, key)

    # Step 3: Decrypt the message
    decrypt_choice = input("Do you want to decrypt the message? (yes/no): ").strip().lower()
    if decrypt_choice == "yes":
        decrypted_message = decrypt(encrypted_data, key)
        print(f"Decrypted Message: {decrypted_message}")
