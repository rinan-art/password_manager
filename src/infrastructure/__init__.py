"""
Infrastructure layer for the password vault.
Contains database, storage, and external service implementations.
"""
from src.infrastructure.database import DatabaseManager, DatabaseError

__all__ = ['DatabaseManager', 'DatabaseError']
