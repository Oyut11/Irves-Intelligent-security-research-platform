"""
IRVES — Repository Analysis Parsers
Parsers for source code security tools (SAST, secrets scanning).
"""

# These imports trigger parser registration via @register_parser decorator
try:
    from parsers.repository.semgrep import SemgrepParser
    from parsers.repository.gitleaks import GitLeaksParser
except ImportError as e:
    import logging
    logging.getLogger(__name__).debug(f"[Repository Parsers] Some parsers not loaded: {e}")

__all__ = ["SemgrepParser", "GitLeaksParser"]
