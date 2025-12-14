import os
import base64
import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID


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
    """
    Encrypts a recipe dictionary using ChaCha20Poly1305.
    Returns nonce and ciphertext as base64 strings.
    """
    import json
    
    # Serialize recipe to JSON bytes
    data = json.dumps(recipe).encode('utf-8')
    
    # Generate random nonce
    nonce = os.urandom(12)
    
    # Encrypt with ChaCha20Poly1305
    chacha = ChaCha20Poly1305(user_key)
    ciphertext = chacha.encrypt(nonce, data, None)
    
    # Return base64 encoded values
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    
    return nonce_b64, ciphertext_b64


def decrypt_recipe(nonce_b64, ciphertext_b64, user_key):
    """
    Decrypts a recipe using ChaCha20Poly1305.
    Returns the original recipe dictionary.
    """
    import json
    
    # Decode from base64
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Decrypt with ChaCha20Poly1305
    chacha = ChaCha20Poly1305(user_key)
    plaintext = chacha.decrypt(nonce, ciphertext, None)
    
    # Deserialize JSON
    recipe = json.loads(plaintext.decode('utf-8'))
    
    return recipe


# ========== RSA KEY GENERATION AND MANAGEMENT ==========

def generate_rsa_keys(username, password):
    """
    Generate RSA key pair for a user.
    Save private key (encrypted with password) and public key to files.
    """
    # Create keys directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)
    
    # Generate 2048-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize private key (encrypted with password)
    password_bytes = password.encode('utf-8')
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    with open(f"keys/{username}_private.pem", "wb") as f:
        f.write(private_pem)
    
    with open(f"keys/{username}_public.pem", "wb") as f:
        f.write(public_pem)
    
    return private_key, public_key


def load_private_key(username, password):
    """
    Load and decrypt user's private key from file.
    """
    with open(f"keys/{username}_private.pem", "rb") as f:
        private_pem = f.read()
    
    password_bytes = password.encode('utf-8')
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=password_bytes
    )
    
    return private_key


def load_public_key(username):
    """
    Load user's public key from file.
    """
    with open(f"keys/{username}_public.pem", "rb") as f:
        public_pem = f.read()
    
    public_key = serialization.load_pem_public_key(public_pem)
    
    return public_key


# ========== SELF-SIGNED CERTIFICATE CREATION ==========

def create_self_signed_certificate(username, private_key, public_key):
    """
    Create a self-signed X.509 certificate for the user.
    """
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    # Certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    # Save certificate to file
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(f"certs/{username}_cert.pem", "wb") as f:
        f.write(cert_pem)
    
    return cert


def load_certificate(username):
    """
    Load user's certificate from file.
    """
    with open(f"certs/{username}_cert.pem", "rb") as f:
        cert_pem = f.read()
    
    cert = x509.load_pem_x509_certificate(cert_pem)
    
    return cert


# ========== DIGITAL SIGNATURES ==========

def sign_data(data, private_key):
    """
    Sign data using RSA-PSS with SHA256.
    Returns signature as base64 string.
    """
    import json
    
    # Convert data to bytes
    if isinstance(data, dict):
        data_bytes = json.dumps(data).encode('utf-8')
    else:
        data_bytes = data.encode('utf-8')
    
    # Sign with RSA-PSS
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Return as base64
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(data, signature_b64, public_key):
    """
    Verify a signature using RSA-PSS with SHA256.
    Returns True if valid, False otherwise.
    """
    import json
    
    # Convert data to bytes
    if isinstance(data, dict):
        data_bytes = json.dumps(data).encode('utf-8')
    else:
        data_bytes = data.encode('utf-8')
    
    # Decode signature
    signature = base64.b64decode(signature_b64)
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ========== CERTIFICATE VERIFICATION ==========

def verify_certificate(cert):
    """
    Verify a self-signed certificate by checking its signature.
    Returns True if valid, False otherwise.
    """
    # Extract certificate information
    signature = cert.signature
    tbs_certificate_bytes = cert.tbs_certificate_bytes
    signature_hash_algorithm = cert.signature_hash_algorithm
    
    # Get public key from certificate
    public_key = cert.public_key()
    
    # Verify certificate signature
    try:
        public_key.verify(
            signature,
            tbs_certificate_bytes,
            padding.PKCS1v15(),
            signature_hash_algorithm
        )
        return True
    except Exception:
        return False
