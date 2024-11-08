import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def derive_key_from_password(password: bytes, salt: bytes, length: int = 32) -> bytes:
    """Derive an AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password)


def generate_aes_key(password: bytes, filename: str):
    """Generate and save an AES key, password-protected."""
    aes_key = os.urandom(32)  # AES key generation
    salt = os.urandom(16)
    derived_key = derive_key_from_password(password, salt)

    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_key = padder.update(aes_key) + padder.finalize()
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()

    with open(f"{filename}.key", "wb") as key_file:
        key_file.write(salt + iv + encrypted_key)
    print(f"AES key saved as '{filename}.key'.")


def main():
    {}


if __name__ == "__main__":
    main()
