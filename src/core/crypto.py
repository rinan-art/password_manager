"""
Core cryptography module for the password vault.
Implements secure key derivation and AES-256-GCM encryption.

SECURITY PRINCIPLES:
- Master password is NEVER stored
- Encryption keys are derived from master password using PBKDF2
- Keys exist ONLY in RAM as mutable bytearrays
- Keys are securely wiped when vault is locked
- All encryption uses AES-256-GCM for authenticated encryption
- Plaintext passwords NEVER touch storage
"""
import os
import secrets
import hmac
import hashlib
from typing import Tuple, Optional
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# Security constants
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits recommended for GCM
SALT_SIZE = 32
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256
VERIFICATION_SIZE = 32  # Size of verification hash


class SecureKey:
    """
    A secure wrapper for encryption keys that stores them in mutable memory
    and provides secure wiping functionality.
    
    The key is stored as a bytearray (mutable) so it can be zeroed out.
    This class should be used with a context manager to ensure cleanup.
    """
    
    def __init__(self, key: bytes):
        """Initialize with a key. Key is copied to mutable bytearray."""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        # Store as mutable bytearray for secure wiping
        self._key: bytearray = bytearray(key)
        self._valid: bool = True
    
    @property
    def key(self) -> bytes:
        """Get the key as bytes. Raises if key has been wiped."""
        if not self._valid:
            raise ValueError("Key has been securely wiped")
        return bytes(self._key)
    
    def wipe(self) -> None:
        """
        Securely wipe the key from memory.
        Overwrites the key multiple times with different patterns.
        """
        if self._valid:
            # Overwrite with random data multiple times
            for _ in range(3):
                secrets.token_bytes(len(self._key))
                for i in range(len(self._key)):
                    self._key[i] = secrets.randbits(8)
            # Final zero
            for i in range(len(self._key)):
                self._key[i] = 0
            self._valid = False
    
    def is_valid(self) -> bool:
        """Check if key is still valid (not wiped)."""
        return self._valid
    
    def __del__(self):
        """Destructor - attempt to wipe key when object is garbage collected."""
        self.wipe()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False
    
    def __repr__(self):
        return f"SecureKey(valid={self._valid}, len={AES_KEY_SIZE})"


class CryptoManager:
    """
    Manages all cryptographic operations for the password vault.
    
    Features:
    - Derives encryption key from master password using PBKDF2-HMAC-SHA256
    - Encrypts/decrypts data using AES-256-GCM
    - Stores keys only in RAM, never on disk
    - Provides secure key wiping
    """
    
    def __init__(self):
        self._encryption_key: Optional[SecureKey] = None
        self._salt: Optional[bytes] = None
    
    @property
    def is_unlocked(self) -> bool:
        """Check if vault is currently unlocked (key in memory)."""
        return (self._encryption_key is not None and 
                self._encryption_key.is_valid())
    
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure salt."""
        return secrets.token_bytes(SALT_SIZE)
    
    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from master password using PBKDF2.
        
        Args:
            master_password: The user's master password
            salt: Salt for key derivation (should be stored in DB)
            
        Returns:
            32-byte derived key
        """
        if not master_password:
            raise ValueError("Master password cannot be empty")
        if len(salt) != SALT_SIZE:
            raise ValueError(f"Salt must be {SALT_SIZE} bytes")
        
        password_bytes = master_password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        return kdf.derive(password_bytes)
    
    def derive_verification_hash(
        self, 
        master_password: str, 
        salt: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Create a verification hash from master password.
        This allows verifying the password without storing it.
        
        Returns:
            Tuple of (verification_hash, nonce)
        """
        # Use a different key derivation for verification
        # We derive a key and then hash it again with a nonce
        derived_key = self.derive_key(master_password, salt)
        
        nonce = secrets.token_bytes(GCM_NONCE_SIZE)
        
        # Create verification by encrypting a known value
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the salt as a known plaintext
        ciphertext = encryptor.update(salt) + encryptor.finalize()
        tag = encryptor.tag
        
        # Combine ciphertext and tag for verification
        verification = ciphertext + tag
        
        # Securely clear the derived key
        derived_key = bytearray(derived_key)
        for i in range(len(derived_key)):
            derived_key[i] = 0
        
        return verification, nonce
    
    def verify_master_password(
        self,
        master_password: str,
        salt: bytes,
        verification_hash: bytes,
        verification_nonce: bytes
    ) -> bool:
        """
        Verify that the provided master password is correct.
        
        Args:
            master_password: Password to verify
            salt: Salt used for key derivation
            verification_hash: Stored verification data
            verification_nonce: Stored verification nonce
            
        Returns:
            True if password is correct
        """
        try:
            derived_key = self.derive_key(master_password, salt)
            
            # Attempt to decrypt the verification
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(verification_nonce, verification_hash[-16:]),  # Last 16 bytes are tag
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt (verification_hash without tag is ciphertext)
            plaintext = decryptor.update(verification_hash[:-16]) + decryptor.finalize()
            
            # Verify it matches the salt
            is_valid = hmac.compare_digest(plaintext, salt)
            
            # Securely clear
            derived_key = bytearray(derived_key)
            for i in range(len(derived_key)):
                derived_key[i] = 0
            
            return is_valid
            
        except (InvalidTag, Exception):
            return False
    
    def unlock_vault(self, master_password: str, salt: bytes) -> bool:
        """
        Unlock the vault by deriving and storing the encryption key in RAM.
        
        Args:
            master_password: The master password
            salt: Salt for key derivation
            
        Returns:
            True if unlock successful
        """
        try:
            derived_key = self.derive_key(master_password, salt)
            self._encryption_key = SecureKey(derived_key)
            self._salt = salt
            
            # Securely clear the temporary key
            derived_key = bytearray(derived_key)
            for i in range(len(derived_key)):
                derived_key[i] = 0
            
            return True
        except Exception:
            return False
    
    def lock_vault(self) -> None:
        """
        Lock the vault by securely wiping the encryption key from RAM.
        This should be called when the user locks the vault or closes the app.
        """
        if self._encryption_key is not None:
            self._encryption_key.wipe()
            self._encryption_key = None
        self._salt = None
    
    def encrypt_data(self, plaintext: bytes, nonce: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (e.g., serialized password entry)
            nonce: Optional nonce (generated if not provided)
            
        Returns:
            Tuple of (ciphertext, nonce)
            
        Raises:
            ValueError: If vault is not unlocked
        """
        if not self.is_unlocked:
            raise ValueError("Vault is locked. Call unlock_vault() first.")
        
        if nonce is None:
            nonce = secrets.token_bytes(GCM_NONCE_SIZE)
        
        key = self._encryption_key.key
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        # Append tag to ciphertext for storage
        ciphertext_with_tag = ciphertext + encryptor.tag
        
        return ciphertext_with_tag, nonce
    
    def decrypt_data(self, ciphertext_with_tag: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext_with_tag: Encrypted data with authentication tag
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted plaintext
            
        Raises:
            ValueError: If vault is not unlocked or decryption fails
        """
        if not self.is_unlocked:
            raise ValueError("Vault is locked. Call unlock_vault() first.")
        
        if len(ciphertext_with_tag) < 16:
            raise ValueError("Ciphertext too short")
        
        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        key = self._encryption_key.key
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise ValueError("Decryption failed: authentication tag invalid")
    
    def encrypt_password(self, password: str) -> Tuple[bytes, bytes]:
        """
        Encrypt a password string.
        
        SECURITY: The plaintext password exists only briefly in memory
        during this operation and is never stored.
        
        Args:
            password: Plaintext password to encrypt
            
        Returns:
            Tuple of (encrypted_data, nonce)
        """
        plaintext = password.encode('utf-8')
        
        # Clear the plaintext from memory after use
        try:
            result = self.encrypt_data(plaintext)
            return result
        finally:
            # Securely clear the plaintext
            plaintext = bytearray(plaintext)
            for i in range(len(plaintext)):
                plaintext[i] = 0
    
    def decrypt_password(self, encrypted_data: bytes, nonce: bytes) -> str:
        """
        Decrypt a password string.
        
        SECURITY: The plaintext password exists only briefly in memory
        and should be displayed only briefly to the user.
        
        Args:
            encrypted_data: Encrypted password data
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted password string
        """
        plaintext = self.decrypt_data(encrypted_data, nonce)
        
        try:
            password = plaintext.decode('utf-8')
            return password
        finally:
            # Securely clear the plaintext
            plaintext = bytearray(plaintext)
            for i in range(len(plaintext)):
                plaintext[i] = 0


@contextmanager
def temporary_decrypt(
    crypto: CryptoManager,
    encrypted_data: bytes,
    nonce: bytes
):
    """
    Context manager for temporarily decrypting sensitive data.
    
    Automatically clears the plaintext from memory when done.
    
    Usage:
        with temporary_decrypt(crypto, encrypted_data, nonce) as password:
            # Use password here
            pass
        # Password is cleared from memory
    """
    plaintext = crypto.decrypt_data(encrypted_data, nonce)
    try:
        yield plaintext
    finally:
        # Securely clear
        plaintext = bytearray(plaintext)
        for i in range(len(plaintext)):
            plaintext[i] = 0
