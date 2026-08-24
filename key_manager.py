import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

MASTER_KEY = os.getenv("MASTER_KEY")

if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY is not configured in .env")

fernet = Fernet(MASTER_KEY.encode())


def protect_key(aes_key):
    """Encrypt an AES file key using the master key."""
    return fernet.encrypt(aes_key)


def unprotect_key(protected_key):
    """Recover the original AES file key."""
    return fernet.decrypt(protected_key)
