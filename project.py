import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa


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


def generate_rsa_key(password: bytes, filename: str):
    """Generate and save an RSA key pair, password-protected."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    with open(f"{filename}_rsa_private.pem", "wb") as private_file:
        private_file.write(pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(f"{filename}_rsa_public.pem", "wb") as public_file:
        public_file.write(public_pem)

    print(
        f"RSA private key saved as '{filename}_rsa_private.pem' and public key as '{filename}_rsa_public.pem'."
    )


def load_key(filename: str, password: bytes = None):
    """Load and decrypt an AES or RSA key from a file."""
    with open(filename, "rb") as key_file:
        key_data = key_file.read()

    # AES key load
    if filename.endswith(".key"):
        salt, iv, encrypted_key = key_data[:16], key_data[16:32], key_data[32:]
        derived_key = derive_key_from_password(password, salt)

        cipher = Cipher(
            algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_key = decryptor.update(encrypted_key) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        aes_key = unpadder.update(padded_key) + unpadder.finalize()
        return aes_key

    # RSA private key load
    elif filename.endswith("_rsa_private.pem"):
        private_key = serialization.load_pem_private_key(
            key_data, password=password, backend=default_backend()
        )
        return private_key

    # RSA public key load
    elif filename.endswith("_rsa_public.pem"):
        public_key = serialization.load_pem_public_key(
            key_data, backend=default_backend()
        )
        return public_key

    else:
        raise ValueError("Unsupported key file format")


def aes_encrypt_file(aes_key, input_file, output_file):
    """Encrypt a file using AES."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(iv + ciphertext)
    print(f"File encrypted and saved to {output_file}.")


def main():
    {}


if __name__ == "__main__":
    main()
