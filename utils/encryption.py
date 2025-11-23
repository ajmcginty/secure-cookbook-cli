import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def encrypt_password(password):
    """
    Takes in an entered password and returns the associated salt and key
    """
    salt = os.urandom(16)
    salt2 = os.urandom(16)
    password_bytes = password.encode("utf-8")
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(password_bytes)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    key_b64 = base64.b64encode(key).decode("utf-8")
    salt2_b64 = base64.b64encode(salt2).decode("utf-8")
    return salt_b64, key_b64, salt2_b64


def verify_password(entered_password, salt_b64, key_b64):
    """
    Returns True if password is correct, False otherwise.
    """
    salt = base64.b64decode(salt_b64)
    stored_key = base64.b64decode(key_b64)
    password_bytes = entered_password.encode("utf-8")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    try:
        kdf.verify(password_bytes, stored_key)
        return True
    except Exception:
        return False
    
def generate_user_key(password, salt_2_b64):
    salt_2 = base64.b64decode(salt_2_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 256-bit key
        salt=salt_2,
        iterations=600_000  # strong iteration count
    )
    k_user = kdf.derive(password.encode())
    return k_user


def encrypt_recipe(recipe, user_key):
    #TODO
    data = b"a secret message"
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(user_key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, aad)
