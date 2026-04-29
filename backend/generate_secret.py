#!/usr/bin/env python3
"""
Generate a secure SECRET_KEY for IRVES production deployment.
Usage: python generate_secret.py
"""

import secrets
import sys

if __name__ == "__main__":
    # Generate 64-byte hex string (128 characters) - very secure
    secret_key = secrets.token_hex(32)
    print(secret_key)
