import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import time
import jwt

_cached_private_key = None
_cached_public_key = None

def generate_rsa_keys(key_size=4096):
    """Generate RSA private and public keys"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(private_key, public_key, private_key_path="rsa_private_key.pem", public_key_path="rsa_public_key.pem"):
    """Save RSA keys to PEM files"""
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Generated RSA keys:")
    print(f"  - {private_key_path}")
    print(f"  - {public_key_path}")

def load_rsa_private_key(key_path="api/keys/rsa_private_key.pem"):
    """Load RSA private key from PEM file"""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_rsa_public_key(key_path="api/keys/rsa_public_key.pem"):
    """Load RSA public key from PEM file"""
    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def ensure_rsa_keys_exist():
    """Ensure RSA keys exist, generate if they don't"""
    keys_dir = "api/keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"Created keys directory: {keys_dir}")
    
    private_key_path = os.path.join(keys_dir, "rsa_private_key.pem")
    public_key_path = os.path.join(keys_dir, "rsa_public_key.pem")
    
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key, private_key_path, public_key_path)
        return private_key, public_key
    else:
        private_key = load_rsa_private_key(private_key_path)
        public_key = load_rsa_public_key(public_key_path)
        return private_key, public_key

def get_private_key():
    global _cached_private_key
    if _cached_private_key is None:
        private_key, _ = ensure_rsa_keys_exist()
        _cached_private_key = private_key
    return _cached_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_public_key():
    global _cached_public_key
    if _cached_public_key is None:
        _, public_key = ensure_rsa_keys_exist()
        _cached_public_key = public_key
    return _cached_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def generate_access_token(profile, client_token):
    """
    Generate a new JWT access token for the given profile and client token.
    Returns the encoded token string.
    """
    current_time = int(time.time())
    token_expiry = current_time + 86400  # 24 hours
    
    jwt_payload = {
        "iss": "yggdrapy",
        "sub": str(profile.user_UUID),
        "exp": token_expiry,
        "iat": current_time,
        "nbf": current_time,
        "version": 0, 
        "clientToken": client_token
    }
    
    private_key = get_private_key()
    access_token = jwt.encode(jwt_payload, private_key, algorithm='RS512')
    return access_token

if __name__ == "__main__":
    private_key, public_key = ensure_rsa_keys_exist()
    print("RSA keys ready!") 