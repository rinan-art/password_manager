"""
Database layer for the password vault.
Manages SQLite database with secure storage of encrypted data.

SECURITY PRINCIPLES:
- Only encrypted data and metadata are stored
- Encryption keys NEVER touch storage
- Plaintext passwords NEVER touch storage
- Salt and verification hash stored for password verification only
"""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from src.core.entities import VaultEntry, VaultMetadata


class DatabaseError(Exception):
    """Base exception for database errors."""
    pass


class DatabaseNotInitializedError(DatabaseError):
    """Raised when database is not initialized."""
    pass


class DatabaseLockedError(DatabaseError):
    """Raised when database is locked."""
    pass


class DatabaseManager:
    """
    Manages the SQLite database for the password vault.
    
    The database stores:
    - Vault metadata (salt, verification hash, schema version)
    - Encrypted entries (encrypted data + nonce)
    
    SECURITY:
    - Encryption keys are NOT stored (derived from master password in RAM)
    - Plaintext passwords are NEVER stored
    - Only encrypted blobs are persisted
    """
    
    # Current schema version
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file. 
                     If None, uses default location.
        """
        if db_path is None:
            # Default to user's home directory
            home = Path.home()
            db_dir = home / '.secure_vault'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'vault.db')
        
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None
        self._is_initialized = False
    
    @property
    def is_initialized(self) -> bool:
        """Check if database is initialized."""
        return self._is_initialized and self._connection is not None
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize_database(self) -> None:
        """
        Initialize the database with required tables.
        This should be called once when setting up a new vault.
        
        Creates:
        - vault_metadata table: stores salt, verification hash
        - entries table: stores encrypted password entries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create vault_metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vault_metadata (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    key_derivation_salt BLOB NOT NULL,
                    verification_hash BLOB NOT NULL,
                    verification_nonce BLOB NOT NULL,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT NOT NULL
                )
            ''')
            
            # Create entries table - MINIMAL schema for security
            # Only ID, encrypted blob, and timestamps are stored in plaintext
            # All sensitive data (title, username, password, etc.) is encrypted
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS entries (
                    id TEXT PRIMARY KEY,
                    encrypted_data BLOB NOT NULL,
                    encryption_nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')

            # Only index on ID for performance - no searchable plaintext fields
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_entries_id
                ON entries(id)
            ''')
            
            conn.commit()
        
        self._is_initialized = True
    
    def is_vault_initialized(self) -> bool:
        """
        Check if the vault has been initialized with a master password.

        Returns:
            True if vault metadata exists
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Check if vault_metadata table exists and has data
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_metadata'")
                if not cursor.fetchone():
                    return False

                cursor.execute('SELECT COUNT(*) FROM vault_metadata WHERE id = 1')
                count = cursor.fetchone()[0]
                return count > 0
        except sqlite3.Error:
            return False
    
    def save_vault_metadata(
        self,
        salt: bytes,
        verification_hash: bytes,
        verification_nonce: bytes
    ) -> None:
        """
        Save vault metadata during initial setup.
        
        SECURITY: Only stores salt and verification data, NOT the key.
        
        Args:
            salt: Key derivation salt
            verification_hash: Password verification data
            verification_nonce: Nonce for verification encryption
        """
        if not self._is_initialized:
            raise DatabaseNotInitializedError("Database not initialized")
        
        now = datetime.now().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO vault_metadata 
                (id, key_derivation_salt, verification_hash, verification_nonce,
                 schema_version, created_at, last_accessed)
                VALUES (1, ?, ?, ?, ?, ?, ?)
            ''', (salt, verification_hash, verification_nonce, 
                  self.SCHEMA_VERSION, now, now))
            conn.commit()
    
    def get_vault_metadata(self) -> Optional[VaultMetadata]:
        """
        Retrieve vault metadata.
        
        Returns:
            VaultMetadata if exists, None otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM vault_metadata WHERE id = 1')
                row = cursor.fetchone()
                
                if row is None:
                    return None
                
                return VaultMetadata(
                    id=row['id'],
                    key_derivation_salt=row['key_derivation_salt'],
                    verification_hash=row['verification_hash'],
                    verification_nonce=row['verification_nonce'],
                    schema_version=row['schema_version'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    last_accessed=datetime.fromisoformat(row['last_accessed']),
                    is_unlocked=False
                )
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get vault metadata: {e}")
    
    def update_last_accessed(self) -> None:
        """Update the last_accessed timestamp."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE vault_metadata SET last_accessed = ? WHERE id = 1
            ''', (datetime.now().isoformat(),))
            conn.commit()
    
    def save_entry(self, entry: VaultEntry, encrypted_blob: bytes = None) -> None:
        """
        Save an encrypted entry to the database.

        SECURITY: ALL sensitive data (title, username, password, URL, notes, category)
        is encrypted together in a single blob. Only ID and timestamps are stored
        in plaintext for database operations.

        Args:
            entry: VaultEntry (used for ID and timestamps)
            encrypted_blob: The fully encrypted entry data (JSON serialized + encrypted)
                           If None, uses entry.encrypted_data
        """
        if not self._is_initialized:
            raise DatabaseNotInitializedError("Database not initialized")

        now = datetime.now().isoformat()
        blob_to_store = encrypted_blob or entry.encrypted_data

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if entry exists
            cursor.execute('SELECT id FROM entries WHERE id = ?', (entry.id,))
            exists = cursor.fetchone() is not None

            if exists:
                # Update existing entry
                cursor.execute('''
                    UPDATE entries SET
                        encrypted_data = ?,
                        encryption_nonce = ?,
                        updated_at = ?
                    WHERE id = ?
                ''', (
                    blob_to_store,
                    entry.encryption_nonce,
                    now,
                    entry.id
                ))
            else:
                # Insert new entry
                cursor.execute('''
                    INSERT INTO entries
                    (id, encrypted_data, encryption_nonce, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    entry.id,
                    blob_to_store,
                    entry.encryption_nonce,
                    now,
                    now
                ))

            conn.commit()
    
    def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
        """
        Retrieve an entry by ID.

        Returns:
            VaultEntry with encrypted_data (the FULL entry is encrypted in this blob)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM entries WHERE id = ?', (entry_id,))
                row = cursor.fetchone()

                if row is None:
                    return None

                # Return minimal entry - sensitive data is in encrypted_data
                return VaultEntry(
                    id=row['id'],
                    title="",  # Will be populated after decryption
                    username="",
                    url="",
                    notes="",
                    category="General",
                    created_at=datetime.fromisoformat(row['created_at']),
                    updated_at=datetime.fromisoformat(row['updated_at']),
                    encrypted_data=row['encrypted_data'],
                    encryption_nonce=row['encryption_nonce']
                )
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get entry: {e}")
    
    def get_all_entries(self) -> List[VaultEntry]:
        """
        Retrieve all entries (encrypted data only, not decrypted).

        Returns:
            List of VaultEntry objects with encrypted_data containing
            the full encrypted entry (title, username, password, etc.)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM entries
                    ORDER BY created_at DESC
                ''')
                rows = cursor.fetchall()

                entries = []
                for row in rows:
                    entries.append(VaultEntry(
                        id=row['id'],
                        title="",  # Will be populated after decryption
                        username="",
                        url="",
                        notes="",
                        category="General",
                        created_at=datetime.fromisoformat(row['created_at']),
                        updated_at=datetime.fromisoformat(row['updated_at']),
                        encrypted_data=row['encrypted_data'],
                        encryption_nonce=row['encryption_nonce']
                    ))

                return entries
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get entries: {e}")
    
    def get_entries_by_category(self, category: str) -> List[VaultEntry]:
        """
        This method is deprecated for security.
        Since all data is encrypted, category filtering must happen
        at the application layer AFTER decryption.
        """
        # Return all entries - filtering will be done by VaultService after decryption
        return self.get_all_entries()

    def get_categories(self) -> List[str]:
        """
        This method is deprecated for security.
        Since all data is encrypted, categories must be extracted
        at the application layer AFTER decryption.
        """
        # Return empty - categories will be determined by VaultService after decryption
        return []
    
    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete an entry by ID.
        
        Args:
            entry_id: ID of entry to delete
            
        Returns:
            True if entry was deleted
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM entries WHERE id = ?', (entry_id,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to delete entry: {e}")
    
    def search_entries(self, query: str) -> List[VaultEntry]:
        """
        Search is now handled at the application layer.
        Since all data is encrypted in a single blob, we return all entries
        and let VaultService filter them after decryption.

        Args:
            query: Search query string (not used at DB level)

        Returns:
            List of all VaultEntry objects (filtering done in service layer)
        """
        # Return all entries - filtering will be done by VaultService after decryption
        return self.get_all_entries()
    
    def clear_all_entries(self) -> None:
        """Clear all entries from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM entries')
            conn.commit()
    
    def delete_database(self) -> None:
        """
        Permanently delete the database file.
        Use with caution - this cannot be undone.
        """
        if self._connection:
            self._connection.close()
            self._connection = None
        
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        
        self._is_initialized = False
    
    def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
        self._is_initialized = False
