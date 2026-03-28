"""
Domain entities for the password vault.
These are pure data structures with no business logic.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class VaultEntry:
    """
    Represents a stored password entry in the vault.
    Note: The actual password is never stored in this entity - 
    only the encrypted blob is persisted.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    username: str = ""
    url: str = ""
    notes: str = ""
    category: str = "General"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    # This holds the encrypted data, never plaintext password
    encrypted_data: bytes = b""
    # IV/Nonce for the encryption
    encryption_nonce: bytes = b""
    
    def to_dict(self) -> dict:
        """Convert to dictionary (for UI display, excluding encrypted data)."""
        return {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'url': self.url,
            'notes': self.notes,
            'category': self.category,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }

    def to_encrypted_dict(self) -> dict:
        """
        Convert sensitive fields to dictionary for encryption.
        This excludes ID and timestamps which may remain in plaintext
        for database operations.
        """
        return {
            'title': self.title,
            'username': self.username,
            'url': self.url,
            'notes': self.notes,
            'category': self.category,
            'password': '',  # Will be filled by service before encryption
        }

    @classmethod
    def from_encrypted_dict(cls, data: dict, entry_id: str = None) -> 'VaultEntry':
        """
        Create VaultEntry from decrypted dictionary data.
        """
        if entry_id is None:
            entry_id = data.get('id', str(uuid.uuid4()))

        return cls(
            id=entry_id,
            title=data.get('title', ''),
            username=data.get('username', ''),
            url=data.get('url', ''),
            notes=data.get('notes', ''),
            category=data.get('category', 'General'),
            encrypted_data=data.get('encrypted_data', b''),
            encryption_nonce=data.get('encryption_nonce', b'')
        )


@dataclass
class VaultMetadata:
    """
    Metadata about the vault database.
    Contains information needed to verify and decrypt the vault.
    """
    id: int = 1
    # Salt for key derivation (stored in DB, not secret)
    key_derivation_salt: bytes = b""
    # Verification hash to validate master password without storing it
    verification_hash: bytes = b""
    # Verification nonce
    verification_nonce: bytes = b""
    # Version for future migrations
    schema_version: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    # Whether vault is currently unlocked
    is_unlocked: bool = False
