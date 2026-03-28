#!/usr/bin/env python3
"""
Secure Vault - A local-first password manager.

Entry point for the application.

SECURITY FEATURES:
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
- Keys stored in RAM only, wiped on lock
- Plaintext passwords never touch storage
- Secure memory management
"""
import sys
import os

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.presentation.main_window import run_app


if __name__ == "__main__":
    run_app()
