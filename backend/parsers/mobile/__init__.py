"""
IRVES — Mobile Platform Parsers
Parsers for mobile security tools (Android & iOS).
"""

# These imports trigger parser registration via @register_parser decorator
try:
    from parsers.mobile.frida import FridaParser
except ImportError as e:
    import logging
    logging.getLogger(__name__).debug(f"[Mobile Parsers] Some parsers not loaded: {e}")

__all__ = ["FridaParser"]
