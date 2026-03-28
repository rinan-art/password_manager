"""
Vault service - Core application logic for the password vault.
This is the main service that coordinates crypto and database operations.

SECURITY PRINCIPLES:
- Encryption keys stored only in RAM
- Keys wiped on lock
- Plaintext passwords never stored
"""
from typing import Optional, List
import json
from datetime import datetime

from src.core.crypto import CryptoManager
from src.core.entities import VaultEntry, VaultMetadata
from src.infrastructure.database import DatabaseManager, DatabaseError


class VaultError(Exception):
    """Base exception for vault operations."""
    pass


class VaultLockedError(VaultError):
    """Raised when vault is locked but operation requires unlock."""
    pass


class VaultService:
    """
    Main service for vault operations.
    
    Coordinates between:
    - CryptoManager: encryption/decryption, key management
    - DatabaseManager: persistent storage
    
    SECURITY:
    - Manages vault unlock/lock lifecycle
    - Ensures keys are wiped when vault is locked
    - Ensures plaintext passwords never reach storage
    """
    
    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        crypto_manager: Optional[CryptoManager] = None
    ):
        """
        Initialize the vault service.
        
        Args:
            db_manager: Database manager instance (created if None)
            crypto_manager: Crypto manager instance (created if None)
        """
        self.db = db_manager or DatabaseManager()
        self.crypto = crypto_manager or CryptoManager()
        self._is_initialized = False
    
    @property
    def is_unlocked(self) -> bool:
        """Check if vault is currently unlocked."""
        return self.crypto.is_unlocked
    
    @property
    def is_initialized(self) -> bool:
        """Check if vault has been initialized with a master password."""
        if not self._is_initialized:
            self._is_initialized = self.db.is_vault_initialized()
        return self._is_initialized
    
    def initialize_new_vault(self, master_password: str) -> None:
        """
        Initialize a new vault with a master password.
        
        This:
        1. Generates a salt
        2. Creates verification hash
        3. Initializes database
        4. Saves metadata
        5. Unlocks vault
        
        SECURITY: Master password is used only for key derivation,
        never stored.
        
        Args:
            master_password: The master password for the vault
            
        Raises:
            VaultError: If vault already exists or initialization fails
        """
        if self.is_initialized:
            raise VaultError("Vault already initialized")
        
        if not master_password:
            raise VaultError("Master password cannot be empty")
        
        if len(master_password) < 8:
            raise VaultError("Master password must be at least 8 characters")
        
        try:
            # Generate salt for key derivation
            salt = self.crypto.generate_salt()
            
            # Create verification hash
            verification_hash, verification_nonce = \
                self.crypto.derive_verification_hash(master_password, salt)
            
            # Initialize database
            self.db.initialize_database()
            
            # Save metadata (salt + verification, NOT the key)
            self.db.save_vault_metadata(
                salt=salt,
                verification_hash=verification_hash,
                verification_nonce=verification_nonce
            )
            
            # Unlock vault
            self.crypto.unlock_vault(master_password, salt)
            
            self._is_initialized = True
            
        except Exception as e:
            # Cleanup on failure
            self.crypto.lock_vault()
            raise VaultError(f"Failed to initialize vault: {e}")
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock the vault with master password.

        Args:
            master_password: The master password

        Returns:
            True if unlock successful (or already unlocked)

        Raises:
            VaultError: If vault not initialized
        """
        if not self.is_initialized:
            raise VaultError("Vault not initialized. Call initialize_new_vault first.")

        # Ensure database is initialized
        if not self.db.is_initialized:
            self.db.initialize_database()

        # If already unlocked, just return success
        # This handles the case after initial setup
        if self.is_unlocked:
            return True

        # Get stored metadata
        metadata = self.db.get_vault_metadata()
        if metadata is None:
            raise VaultError("Vault metadata not found")

        # Verify password first
        is_valid = self.crypto.verify_master_password(
            master_password=master_password,
            salt=metadata.key_derivation_salt,
            verification_hash=metadata.verification_hash,
            verification_nonce=metadata.verification_nonce
        )

        if not is_valid:
            return False

        # Unlock vault
        success = self.crypto.unlock_vault(
            master_password=master_password,
            salt=metadata.key_derivation_salt
        )

        if success:
            self.db.update_last_accessed()
            self._is_initialized = True

        return success
    
    def lock(self) -> None:
        """
        Lock the vault.
        
        SECURITY: This securely wipes the encryption key from RAM.
        The key is overwritten multiple times before being freed.
        """
        self.crypto.lock_vault()
    
    def create_entry(
        self,
        title: str,
        password: str,
        username: str = "",
        url: str = "",
        notes: str = "",
        category: str = "General"
    ) -> VaultEntry:
        """
        Create a new password entry.

        SECURITY: The ENTIRE entry (title, username, password, URL, notes, category)
        is serialized to JSON and encrypted together as a single blob.
        Only the ID and timestamps are stored in plaintext.

        Args:
            title: Entry title (required)
            password: The password to store (will be encrypted)
            username: Username (optional)
            url: URL (optional)
            notes: Notes (optional)
            category: Category (default: General)

        Returns:
            Created VaultEntry

        Raises:
            VaultLockedError: If vault is locked
            VaultError: If entry creation fails
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")

        if not title:
            raise VaultError("Title is required")

        try:
            # Create entry entity
            entry = VaultEntry(
                title=title,
                username=username,
                url=url,
                notes=notes,
                category=category
            )

            # Prepare full entry data for encryption
            entry_data = entry.to_encrypted_dict()
            entry_data['password'] = password  # Add the actual password

            # Serialize to JSON and encrypt the entire entry
            # SECURITY: All sensitive data is encrypted together
            json_data = json.dumps(entry_data).encode('utf-8')

            # Encrypt the full JSON
            encrypted_data, nonce = self.crypto.encrypt_data(json_data)

            entry.encrypted_data = encrypted_data
            entry.encryption_nonce = nonce

            # Save to database (only encrypted blob + ID + timestamps)
            self.db.save_entry(entry, encrypted_blob=encrypted_data)

            return entry

        except Exception as e:
            raise VaultError(f"Failed to create entry: {e}")
    
    def update_entry(
        self,
        entry_id: str,
        title: Optional[str] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        category: Optional[str] = None
    ) -> VaultEntry:
        """
        Update an existing entry.
        
        SECURITY: If password is updated, it's encrypted immediately.
        
        Args:
            entry_id: ID of entry to update
            title: New title (optional)
            password: New password (optional, will be encrypted)
            username: New username (optional)
            url: New URL (optional)
            notes: New notes (optional)
            category: New category (optional)
            
        Returns:
            Updated VaultEntry
            
        Raises:
            VaultLockedError: If vault is locked
            VaultError: If entry not found or update fails
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        # Get existing entry
        entry = self.db.get_entry(entry_id)
        if entry is None:
            raise VaultError(f"Entry not found: {entry_id}")
        
        try:
            # Get the full decrypted entry first
            decrypted_entry = self.get_decrypted_entry(entry_id)

            # Update fields on the decrypted entry
            if title is not None:
                decrypted_entry.title = title
            if username is not None:
                decrypted_entry.username = username
            if url is not None:
                decrypted_entry.url = url
            if notes is not None:
                decrypted_entry.notes = notes
            if category is not None:
                decrypted_entry.category = category

            # Prepare full entry data for re-encryption
            entry_data = decrypted_entry.to_encrypted_dict()
            if password is not None and password != "••••••••":
                entry_data['password'] = password
            else:
                # Get existing password if not updating it
                existing_password = self.get_decrypted_password(entry_id)
                entry_data['password'] = existing_password

            # Serialize to JSON and encrypt the entire entry
            json_data = json.dumps(entry_data).encode('utf-8')
            encrypted_data, nonce = self.crypto.encrypt_data(json_data)

            decrypted_entry.encrypted_data = encrypted_data
            decrypted_entry.encryption_nonce = nonce
            decrypted_entry.updated_at = datetime.now()

            # Save to database (only encrypted blob + ID + timestamps)
            self.db.save_entry(decrypted_entry, encrypted_blob=encrypted_data)

            return decrypted_entry
            
        except Exception as e:
            raise VaultError(f"Failed to update entry: {e}")
    
    def get_entry(self, entry_id: str) -> VaultEntry:
        """
        Get an entry by ID.
        
        Note: Returns encrypted entry. Use get_decrypted_password()
        to get the password.
        
        Args:
            entry_id: Entry ID
            
        Returns:
            VaultEntry
            
        Raises:
            VaultLockedError: If vault is locked
            VaultError: If entry not found
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        entry = self.db.get_entry(entry_id)
        if entry is None:
            raise VaultError(f"Entry not found: {entry_id}")
        
        return entry
    
    def get_decrypted_entry(self, entry_id: str) -> VaultEntry:
        """
        Get a fully decrypted entry.

        SECURITY: The entire entry is decrypted from the encrypted blob.
        Plaintext data exists only briefly in memory.

        Args:
            entry_id: Entry ID

        Returns:
            Fully populated VaultEntry with decrypted data

        Raises:
            VaultLockedError: If vault is locked
            VaultError: If entry not found or decryption fails
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")

        entry = self.db.get_entry(entry_id)
        if entry is None:
            raise VaultError(f"Entry not found: {entry_id}")

        try:
            # Decrypt the full entry blob
            decrypted_json = self.crypto.decrypt_data(
                entry.encrypted_data,
                entry.encryption_nonce
            )

            # Parse the JSON
            entry_data = json.loads(decrypted_json.decode('utf-8'))

            # Create fully populated entry
            decrypted_entry = VaultEntry(
                id=entry.id,
                title=entry_data.get('title', ''),
                username=entry_data.get('username', ''),
                url=entry_data.get('url', ''),
                notes=entry_data.get('notes', ''),
                category=entry_data.get('category', 'General'),
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                encrypted_data=entry.encrypted_data,
                encryption_nonce=entry.encryption_nonce
            )

            return decrypted_entry

        except Exception as e:
            raise VaultError(f"Failed to decrypt entry: {e}")

    def get_decrypted_password(self, entry_id: str) -> str:
        """
        Get the decrypted password for an entry.

        SECURITY: Plaintext password exists only briefly in memory.
        Caller should clear it as soon as possible.

        Args:
            entry_id: Entry ID

        Returns:
            Decrypted password string

        Raises:
            VaultLockedError: If vault is locked
            VaultError: If entry not found or decryption fails
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")

        try:
            # Get the full decrypted entry
            decrypted_entry = self.get_decrypted_entry(entry_id)

            # For now, we need to decrypt again to get the password
            # since get_decrypted_entry doesn't return the password field
            entry = self.db.get_entry(entry_id)
            decrypted_json = self.crypto.decrypt_data(
                entry.encrypted_data,
                entry.encryption_nonce
            )
            entry_data = json.loads(decrypted_json.decode('utf-8'))
            return entry_data.get('password', '')

        except Exception as e:
            raise VaultError(f"Failed to decrypt password: {e}")
    
    def get_all_entries(self) -> List[VaultEntry]:
        """
        Get all entries with decrypted data.

        SECURITY: Each entry is decrypted from its encrypted blob.
        This allows the UI to show proper titles and metadata.

        Returns:
            List of fully decrypted VaultEntry objects

        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")

        # Get encrypted entries from database
        encrypted_entries = self.db.get_all_entries()
        decrypted_entries = []

        for encrypted_entry in encrypted_entries:
            try:
                # Decrypt each entry to get the full data
                decrypted_entry = self.get_decrypted_entry(encrypted_entry.id)
                decrypted_entries.append(decrypted_entry)
            except Exception:
                # If decryption fails for one entry, still include the basic entry
                decrypted_entries.append(encrypted_entry)

        return decrypted_entries
    
    def get_categories(self) -> List[str]:
        """
        Get all categories.
        
        Returns:
            List of category names
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        return self.db.get_categories()
    
    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete an entry.
        
        Args:
            entry_id: Entry ID
            
        Returns:
            True if deleted
            
        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        return self.db.delete_entry(entry_id)
    
    def search_entries(self, query: str) -> List[VaultEntry]:
        """
        Search entries by title, username, URL, or category.
        
        Args:
            query: Search query
            
        Returns:
            List of matching VaultEntry objects
            
        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        return self.db.search_entries(query)
    
    def change_master_password(
        self,
        old_password: str,
        new_password: str
    ) -> None:
        """
        Change the master password.
        
        This re-encrypts all entries with the new key.
        
        SECURITY: All entries are re-encrypted with new key.
        Old key is wiped.
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Raises:
            VaultLockedError: If vault is locked
            VaultError: If password change fails
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        if len(new_password) < 8:
            raise VaultError("New password must be at least 8 characters")
        
        try:
            # Get all entries
            entries = self.db.get_all_entries()
            
            # Decrypt all passwords with old key
            decrypted_data = []
            for entry in entries:
                password = self.crypto.decrypt_password(
                    entry.encrypted_data,
                    entry.encryption_nonce
                )
                decrypted_data.append((entry, password))
            
            # Lock with old key (wipes old key)
            self.crypto.lock_vault()
            
            # Generate new salt
            new_salt = self.crypto.generate_salt()
            
            # Create new verification hash
            verification_hash, verification_nonce = \
                self.crypto.derive_verification_hash(new_password, new_salt)
            
            # Save new metadata
            self.db.save_vault_metadata(
                salt=new_salt,
                verification_hash=verification_hash,
                verification_nonce=verification_nonce
            )
            
            # Unlock with new key
            self.crypto.unlock_vault(new_password, new_salt)
            
            # Re-encrypt all entries with new key
            for entry, password in decrypted_data:
                encrypted_data, nonce = self.crypto.encrypt_password(password)
                entry.encrypted_data = encrypted_data
                entry.encryption_nonce = nonce
                entry.updated_at = datetime.now()
                self.db.save_entry(entry)
                
                # Clear password from memory
                password = bytearray(password.encode('utf-8'))
                for i in range(len(password)):
                    password[i] = 0
            
        except Exception as e:
            # Try to re-lock on failure
            self.crypto.lock_vault()
            raise VaultError(f"Failed to change master password: {e}")
    
    def export_entries_decrypted(self) -> List[dict]:
        """
        Export all entries with decrypted passwords.
        
        SECURITY: Use only for explicit user export.
        Plaintext passwords exist in memory during export.
        
        Returns:
            List of entry dictionaries with decrypted passwords
            
        Raises:
            VaultLockedError: If vault is locked
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked")
        
        entries = self.db.get_all_entries()
        result = []
        
        for entry in entries:
            password = self.crypto.decrypt_password(
                entry.encrypted_data,
                entry.encryption_nonce
            )
            result.append({
                'id': entry.id,
                'title': entry.title,
                'username': entry.username,
                'password': password,
                'url': entry.url,
                'notes': entry.notes,
                'category': entry.category,
                'created_at': entry.created_at.isoformat(),
                'updated_at': entry.updated_at.isoformat(),
            })
        
        return result
    
    def close(self) -> None:
        """
        Close the vault service.
        
        SECURITY: Locks vault (wipes keys) and closes database.
        """
        self.crypto.lock_vault()
        self.db.close()
