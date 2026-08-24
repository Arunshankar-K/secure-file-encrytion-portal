import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key():
    """Generate a secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(input_file, output_file, key):
    """Encrypt a file using AES-256-GCM."""

    # Generate a unique 96-bit nonce
    nonce = os.urandom(12)

    # Read the original file
    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Encrypt and authenticate the data
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Store nonce + ciphertext
    with open(output_file, "wb") as file:
        file.write(nonce + ciphertext)


def decrypt_file(input_file, output_file, key):
    """Decrypt and authenticate an AES-256-GCM encrypted file."""

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    # Extract the 12-byte nonce
    nonce = encrypted_data[:12]

    # Extract ciphertext + authentication tag
    ciphertext = encrypted_data[12:]

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Decrypt and verify integrity
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Write the decrypted file
    with open(output_file, "wb") as file:
        file.write(plaintext)
