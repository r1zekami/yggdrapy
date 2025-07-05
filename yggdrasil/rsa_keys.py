import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys(key_size=2048):
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
    
    print(f"RSA keys saved:")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key: {public_key_path}")

def load_rsa_private_key(key_path="yggdrasil/keys/rsa_private_key.pem"):
    """Load RSA private key from PEM file"""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_rsa_public_key(key_path="yggdrasil/keys/rsa_public_key.pem"):
    """Load RSA public key from PEM file"""
    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def ensure_rsa_keys_exist():
    """Ensure RSA keys exist, generate if they don't"""
    keys_dir = "yggdrasil/keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"Created keys directory: {keys_dir}")
    
    private_key_path = os.path.join(keys_dir, "rsa_private_key.pem")
    public_key_path = os.path.join(keys_dir, "rsa_public_key.pem")
    
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("RSA keys not found. Generating new keys...")
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key, private_key_path, public_key_path)
        return private_key, public_key
    else:
        print("RSA keys found. Loading existing keys...")
        private_key = load_rsa_private_key(private_key_path)
        public_key = load_rsa_public_key(public_key_path)
        return private_key, public_key

def get_private_key():
    """Get private key for JWT signing"""
    private_key, _ = ensure_rsa_keys_exist()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_public_key():
    """Get public key for JWT verification"""
    _, public_key = ensure_rsa_keys_exist()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

if __name__ == "__main__":
    private_key, public_key = ensure_rsa_keys_exist()
    print("RSA keys ready!") 